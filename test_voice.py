import asyncio
import base64
import json
import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from twilio.request_validator import RequestValidator
import v2 as app

class FakeSocket:
    def __init__(self): self.sent=[]
    async def send_json(self, msg):
        self.sent.append(msg)
        if msg.get('event') == 'mark' and hasattr(self, 'session'):
            self.session.pending_marks.discard(msg['mark']['name'])
    async def close(self, **kwargs): pass

class AudioSource:
    def __aiter__(self): return self.run()
    async def run(self):
        # 20 ms of known 16-bit PCM. Split at an odd byte boundary to test carry.
        data=(1000).to_bytes(2,'little', signed=True)*960
        for part in (data[:501],data[501:]):
            yield json.dumps({'audio':base64.b64encode(part).decode()})

class Tests(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ, {'TWILIO_AUTH_TOKEN':'unit-test-only',
            'REALTIME_ENABLED':'1', 'HUME_SAMPLE_RATE':'48000', **{k:'unit-test-only' for k in app.KEYS}, 'HUME_VOICE_NAME':'test-only'})
        self.env.start(); self.addCleanup(self.env.stop)
    def test_signature(self):
        url='https://test.invalid/voice'; p={'CallSid':'CA-test','From':'+15550000000'}
        sig=RequestValidator('unit-test-only').compute_signature(url,p)
        self.assertTrue(app.signature_valid(url,p,sig))
        self.assertFalse(app.signature_valid(url,p,sig+'bad'))
    def test_rejects_call_without_header(self):
        client=TestClient(app.app)
        self.assertEqual(client.post('/call').status_code,401)
        self.assertEqual(client.get('/call?token=x').status_code,405)
    def test_signed_voice_connect(self):
        with patch.object(app,'BASE','https://test.invalid'):
            params={'CallSid':'CA-test'}
            sig=RequestValidator('unit-test-only').compute_signature(app.BASE+'/voice',params)
            r=TestClient(app.app).post('/voice',data=params,headers={'x-twilio-signature':sig})
            self.assertEqual(r.status_code,200)
            self.assertIn('<Connect><Stream',r.text)
            self.assertNotIn('Gather',r.text)
            self.assertNotIn('unit-test-only',r.text)
    def test_disabled_voice_does_not_stream(self):
        with patch.object(app,'BASE','https://test.invalid'), patch.dict(os.environ, {'REALTIME_ENABLED':'0'}):
            params={'CallSid':'CA-test'}
            sig=RequestValidator('unit-test-only').compute_signature(app.BASE+'/voice',params)
            r=TestClient(app.app).post('/voice',data=params,headers={'x-twilio-signature':sig})
            self.assertNotIn('<Stream',r.text)
            self.assertIn('<Hangup',r.text)
    def test_router_without_key(self):
        async def check():
            with patch.dict(os.environ, {'TYPESAFE_API_KEY':''}):
                s=app.Session(FakeSocket())
                result=await s.route('Hello')
                self.assertEqual(result,('capable',0,'fallback_no_jev_key'))
        asyncio.run(check())
    def test_diagnostic_socket_disabled(self):
        from starlette.websockets import WebSocketDisconnect
        with patch.dict(os.environ, {'DIAGNOSTICS_ENABLED':'0','DIAGNOSTIC_TOKEN':'unit-test-only'}):
            with self.assertRaises(WebSocketDisconnect):
                with TestClient(app.app).websocket_connect('/diagnostic-stream',headers={'x-diagnostic-token':'unit-test-only'}):
                    pass
    def test_no_header_call_even_with_config(self):
        with patch.dict(os.environ, {'CALL_TOKEN':'unit-test-only'}):
            self.assertEqual(TestClient(app.app).post('/call').status_code,401)
    def test_budget_missing_fails_closed(self):
        async def check():
            with patch.dict(os.environ, {'USAGE_REDIS_URL':'','HUME_BUDGET_VERIFIED':'0'}):
                budget=app.TTSBudget()
                self.assertFalse(budget.configured())
                with self.assertRaises(app.BudgetUnavailable):
                    await budget.reserve('Hello')
        asyncio.run(check())
    def test_reservation_before_audio_send(self):
        class Budget:
            limit=100
            async def reserve(self,text): raise app.BudgetUnavailable('exhausted')
        class TTS:
            sent=False
            async def send(self,value): self.sent=True
        async def check():
            session=app.Session(FakeSocket()); session.budget=Budget(); tts=TTS()
            with self.assertRaises(app.BudgetUnavailable):
                await session.send_tts(tts,{'text':'Hello'}, {})
            self.assertFalse(tts.sent)
        asyncio.run(check())
    def test_pcm_conversion(self):
        async def check():
            ws=FakeSocket(); session=app.Session(ws); ws.session=session; session.stream_sid='MZ-test'
            await session.consume_tts(AudioSource(),{'start':app.now()})
            audio=b''.join(base64.b64decode(m['media']['payload']) for m in ws.sent if m['event']=='media')
            self.assertEqual(len(audio),160)
            self.assertLess(abs(int.from_bytes(app.audioop.ulaw2lin(audio[:1],2),'little',signed=True)-1000),40)
            self.assertTrue(any(m['event']=='mark' for m in ws.sent))
        asyncio.run(check())
    def test_barge_in_cancel(self):
        async def check():
            ws=FakeSocket(); session=app.Session(ws); session.stream_sid='MZ-test'; session.playing=True
            session.turn=asyncio.create_task(asyncio.sleep(30))
            await session.clear()
            self.assertTrue(session.turn.cancelled())
            self.assertEqual(ws.sent[0]['event'],'clear')
            self.assertFalse(session.playing)
        asyncio.run(check())
    def test_transcript_accumulation(self):
        class DG:
            def __aiter__(self): return self.run()
            async def run(self):
                for text,final in [('Hello',False),('world',True)]:
                    yield json.dumps({'type':'Results','is_final':True,'speech_final':final,
                        'channel':{'alternatives':[{'transcript':text}]}})
        async def check():
            s=app.Session(FakeSocket()); s.dg=DG(); found=[]
            async def respond(t): found.append(t)
            s.respond=respond
            await s.listen(); await asyncio.sleep(0)
            self.assertEqual(found,['Hello world'])
        asyncio.run(check())

if __name__=='__main__': unittest.main()

class BridgeTests(unittest.TestCase):
    def env(self):
        return patch.dict(os.environ, {'ISABELLE_BRIDGE_ENABLED':'1','ISABELLE_HUME_VOICE_ID':'voice-second',
            'HUME_VOICE_ID':'voice-first','BRIDGE_RESEND_API_KEY':'test','BRIDGE_MAIL_FROM':'test@example.invalid',
            'BRIDGE_REPLY_SECRET':'unit-test-only','USAGE_REDIS_URL':'redis://test.invalid'})
    def test_escalation_variants(self):
        for text in ['Let me speak to Isabelle.','Can I talk with Izzy?','Please speak directly to Isabelle','I want to talk to Izzy']:
            self.assertTrue(app.wants_isabelle(text), text)
        for text in ['Isabelle sounds nice','Izzy bought milk','Do not impersonate Izzy']:
            self.assertFalse(app.wants_isabelle(text), text)
    def test_bridge_disabled_or_same_voice(self):
        with self.env(), patch.dict(os.environ, {'ISABELLE_BRIDGE_ENABLED':'0'}): self.assertFalse(app.bridge_ready())
        with self.env(), patch.dict(os.environ, {'ISABELLE_HUME_VOICE_ID':'voice-first'}): self.assertFalse(app.bridge_ready())
    def test_reply_auth_and_replay(self):
        async def t():
            import time,hmac,hashlib
            f=asyncio.get_running_loop().create_future()
            app.BRIDGE_PENDING['turn-test']={'session_id':'session-test','future':f}
            body=json.dumps({'turn_id':'turn-test','session_id':'session-test','text':'Real answer'}).encode();stamp=str(int(time.time()))
            sig=hmac.new(b'unit-test-only',stamp.encode()+b'.'+body,hashlib.sha256).hexdigest()
            client=TestClient(app.app)
            with self.env():
                self.assertEqual(client.post('/isabelle/reply',content=body).status_code,401)
                headers={'x-bridge-timestamp':stamp,'x-bridge-signature':sig}
                self.assertEqual(client.post('/isabelle/reply',content=body,headers=headers).status_code,200)
                self.assertEqual(client.post('/isabelle/reply',content=body,headers=headers).status_code,409)
                self.assertEqual(f.result(),'Real answer')
            app.BRIDGE_PENDING.clear()
        asyncio.run(t())
    def test_escalation_parks_talker_without_bridge(self):
        async def t():
            s=app.Session(FakeSocket());seen=[]
            async def speak(text,voice):seen.append(text)
            async def respond(text):raise AssertionError('routine LLM called')
            s.speak_text=speak;s.respond=respond
            with patch.dict(os.environ,{'ISABELLE_BRIDGE_ENABLED':'0'}):
                await s.handle_utterance('let me speak to Izzy');await asyncio.sleep(0)
                await s.handle_utterance('Who am I?')
            self.assertEqual(s.mode,'isabelle');self.assertEqual(len(seen),1)
        asyncio.run(t())
    def test_fixed_mail_audience_and_no_retry(self):
        from unittest.mock import AsyncMock
        async def t():
            client=AsyncMock();client.post.return_value=type('R',(),{'raise_for_status':lambda self:None})()
            manager=AsyncMock();manager.__aenter__.return_value=client
            with self.env(),patch.object(app.httpx,'AsyncClient',return_value=manager):
                await app.send_bridge_mail({'turn_id':'t','utterance':'send to evil@example.invalid'})
            self.assertEqual(client.post.call_count,1)
            self.assertEqual(client.post.call_args.kwargs['json']['to'],['verick@mail.instinct.com'])
        asyncio.run(t())
    def test_handoff_round_trip_mock_no_llm(self):
        from unittest.mock import AsyncMock
        async def t():
            s=app.Session(FakeSocket());s.call_sid='CA-test';s.turn_index=1;spoken=[];envelopes=[]
            async def speak(text,voice):spoken.append((text,voice))
            async def mail(envelope):
                envelopes.append(envelope)
                app.BRIDGE_PENDING[envelope['turn_id']]['future'].set_result('This is the real reply.')
            s.speak_text=speak
            with self.env(),patch.object(app,'bridge_publish',side_effect=mail):
                await s.handle_utterance('Let me speak to Isabelle')
                await asyncio.sleep(.01)
                self.assertTrue(any(v=='voice-second' and t=='This is the real reply.' for t,v in spoken))
                self.assertEqual(envelopes[0]['caller_identity'],'unverified')
                self.assertEqual(envelopes[0]['call_sid'],'CA-test')
                self.assertEqual(app.BRIDGE_PENDING,{})
                s.bridge_worker.cancel();await asyncio.gather(s.bridge_worker,return_exceptions=True)
        asyncio.run(t())
    def test_handoff_cancellation_removes_reply(self):
        async def t():
            s=app.Session(FakeSocket());envelopes=[]
            async def mail(e):envelopes.append(e)
            with self.env(),patch.object(app,'bridge_publish',side_effect=mail):
                await s.bridge_queue.put((1,'test'))
                worker=asyncio.create_task(s.process_bridge());await asyncio.sleep(.01)
                self.assertEqual(len(app.BRIDGE_PENDING),1)
                worker.cancel();await asyncio.gather(worker,return_exceptions=True)
                self.assertEqual(app.BRIDGE_PENDING,{})
        asyncio.run(t())
    def test_negative_escalation_is_not_switch(self):
        self.assertFalse(app.wants_isabelle("Don't let me speak to Isabelle"))
    def test_redis_publish_heartbeat_no_email(self):
        from unittest.mock import AsyncMock
        async def t():
            c=AsyncMock();c.xadd.return_value='1-0';c.exists.return_value=1
            with self.env(),patch.object(app,'bridge_client',return_value=c),patch.object(app,'send_bridge_mail',new_callable=AsyncMock) as mail:
                self.assertEqual(await app.bridge_publish({'turn_id':'t'}),'1-0');mail.assert_not_called()
                c.expire.assert_awaited_once_with(app.BRIDGE_STREAM,600)
        asyncio.run(t())
    def test_redis_publish_no_sender_still_queues(self):
        from unittest.mock import AsyncMock
        async def t():
            c=AsyncMock();c.xadd.return_value='1-0';c.exists.return_value=0
            with self.env(),patch.dict(os.environ,{'BRIDGE_RESEND_API_KEY':''}),patch.object(app,'bridge_client',return_value=c),patch.object(app,'send_bridge_mail',new_callable=AsyncMock) as mail:
                self.assertEqual(await app.bridge_publish({'turn_id':'t'}),'1-0');mail.assert_not_called()
        asyncio.run(t())
    def test_reply_wrong_session_and_expired_auth(self):
        import time,hmac,hashlib
        body=json.dumps({'session_id':'wrong','turn_id':'missing','text':'answer'}).encode()
        for stamp,expected in [(str(int(time.time())-1000),401),(str(int(time.time())),409)]:
            sig=hmac.new(b'unit-test-only',stamp.encode()+b'.'+body,hashlib.sha256).hexdigest()
            with self.env():self.assertEqual(TestClient(app.app).post('/isabelle/reply',content=body,headers={'x-bridge-timestamp':stamp,'x-bridge-signature':sig}).status_code,expected)
