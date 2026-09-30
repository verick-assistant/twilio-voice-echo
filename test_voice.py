import asyncio
import base64
import json
import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from twilio.request_validator import RequestValidator
import app

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
            params={'CallSid':'CA-test','From':'+17865271894'}
            sig=RequestValidator('unit-test-only').compute_signature(app.BASE+'/voice',params)
            r=TestClient(app.app).post('/voice',data=params,headers={'x-twilio-signature':sig})
            self.assertEqual(r.status_code,200)
            self.assertIn('<Connect><Stream',r.text)
            self.assertNotIn('Gather',r.text)
            self.assertNotIn('unit-test-only',r.text)
    def test_disabled_voice_does_not_stream(self):
        with patch.object(app,'BASE','https://test.invalid'), patch.dict(os.environ, {'REALTIME_ENABLED':'0'}):
            params={'CallSid':'CA-test','From':'+17865271894'}
            sig=RequestValidator('unit-test-only').compute_signature(app.BASE+'/voice',params)
            r=TestClient(app.app).post('/voice',data=params,headers={'x-twilio-signature':sig})
            self.assertNotIn('<Stream',r.text)
            self.assertIn('<Hangup',r.text)
    def test_session_cutoff_and_post_stream_hangup(self):
        from unittest.mock import AsyncMock
        async def check():
            socket = AsyncMock(); session = app.Session(socket)
            with patch.object(app.asyncio, 'sleep', new_callable=AsyncMock) as sleep:
                await session.enforce_session_limit(1200)
                sleep.assert_awaited_once_with(1200)
                socket.close.assert_awaited_once_with(code=1000)
        asyncio.run(check())
        with patch.object(app,'BASE','https://test.invalid'):
            params={'CallSid':'CA-test','From':'+17865271894'}
            sig=RequestValidator('unit-test-only').compute_signature(app.BASE+'/voice',params)
            result=TestClient(app.app).post('/voice',data=params,headers={'x-twilio-signature':sig})
            self.assertIn('</Stream></Connect><Hangup/>',result.text)
    def test_websocket_signature_uses_configured_wss_url(self):
        from starlette.websockets import WebSocketDisconnect
        from unittest.mock import AsyncMock
        client=TestClient(app.app)
        with patch.object(app,'BASE','https://test.invalid'), patch.object(app.Session,'run',new_callable=AsyncMock):
            for url in ['wss://test.invalid/media-stream','wss://test.invalid/media-stream/']:
                sig=RequestValidator('unit-test-only').compute_signature(url,{})
                with client.websocket_connect('/media-stream',headers={'x-twilio-signature':sig}):pass
            for url in ['https://test.invalid/media-stream','wss://evil.invalid/media-stream']:
                sig=RequestValidator('unit-test-only').compute_signature(url,{})
                with self.assertRaises(WebSocketDisconnect):
                    with client.websocket_connect('/media-stream',headers={'x-twilio-signature':sig}):pass
    def test_router_without_key(self):
        async def check():
            with patch.dict(os.environ, {'OPENROUTER_API_KEY':''}):
                s=app.Session(FakeSocket())
                result=await s.route('Hello')
                self.assertEqual(result,('capable',0,'fallback_no_openrouter_key'))
        asyncio.run(check())
    def test_jev_openrouter_contract_and_fallbacks(self):
        import httpx
        async def check():
            for choice, confidence, expected in [('fast', .9, 'fast'), ('fast', .5, 'capable'), ('unknown', .95, 'capable')]:
                def handler(request):
                    self.assertEqual(str(request.url), 'https://openrouter.ai/api/alpha/decisions')
                    self.assertEqual(request.headers['Authorization'], 'Bearer unit-router')
                    body = json.loads(request.content)
                    self.assertEqual(body['model'], 'typesafe/jev-1.13')
                    self.assertEqual(body['state'], {'utterance': 'Hello'})
                    self.assertEqual(set(body['questions']['route']['criteria']), {'fast', 'capable'})
                    return httpx.Response(200, json={'answers': {'route': {'choice': choice, 'confidence': confidence}}})
                with patch.dict(os.environ, {'OPENROUTER_API_KEY':'unit-router', 'JEV_MODEL':'typesafe/jev-1.13'}):
                    session = app.Session(FakeSocket())
                    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                        session.client = client
                        result = await session.route('Hello')
                    self.assertEqual(result[0], expected)
                    self.assertEqual(result[2], 'jev_openrouter')
            for response in [httpx.Response(503), httpx.Response(200, json={'answers':{}})]:
                with patch.dict(os.environ, {'OPENROUTER_API_KEY':'unit-router'}):
                    session = app.Session(FakeSocket())
                    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: response)) as client:
                        session.client = client
                        result = await session.route('Hello')
                    self.assertEqual(result[0], 'capable')
                    self.assertEqual(result[2], 'fallback')
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
            self.assertLess(abs(int.from_bytes(app.audioop.ulaw2lin(audio[70:71],2),'little',signed=True)-1000),40)
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
    def test_short_pause_fragments_coalesce(self):
        class DG:
            def __aiter__(self): return self.run()
            async def run(self):
                for text in ['Let us see if you can', 'make note of', 'a request.']:
                    yield json.dumps({'type':'Results','is_final':True,'speech_final':True,'channel':{'alternatives':[{'transcript':text}]}})
                    await asyncio.sleep(.1)
        async def check():
            session=app.Session(FakeSocket());session.dg=DG();found=[]
            async def handle(text):found.append(text)
            session.handle_utterance=handle
            await session.listen();await asyncio.sleep(.8)
            self.assertEqual(found,['Let us see if you can make note of a request.'])
        asyncio.run(check())
    def test_noise_speech_start_does_not_cancel_audio(self):
        class DG:
            def __aiter__(self): return self.run()
            async def run(self):yield json.dumps({'type':'SpeechStarted'})
        async def check():
            from unittest.mock import AsyncMock
            session=app.Session(FakeSocket());session.dg=DG();session.playing=True;session.clear=AsyncMock()
            await session.listen();await asyncio.sleep(.3);session.clear.assert_not_awaited()
        asyncio.run(check())
    def test_encoded_audio_rejected(self):
        class Source:
            def __aiter__(self):return self.run()
            async def run(self):yield json.dumps({'audio':base64.b64encode(b'RIFFnot-raw-pcm').decode()})
        async def check():
            session=app.Session(FakeSocket())
            with self.assertRaises(ValueError):await session.consume_tts(Source(),{'start':app.now()})
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
            await s.listen(); await asyncio.sleep(.8)
            self.assertEqual(found,['Hello world'])
        asyncio.run(check())

if __name__=='__main__': unittest.main()

class BridgeTests(unittest.TestCase):
    def env(self):
        return patch.dict(os.environ, {'ISABELLE_BRIDGE_ENABLED':'1','ISABELLE_HUME_VOICE_ID':'voice-second',
            'HUME_VOICE_ID':'voice-first','BRIDGE_RESEND_API_KEY':'test','BRIDGE_MAIL_FROM':'test@example.invalid',
            'BRIDGE_HMAC_ENABLED':'1','BRIDGE_REPLY_SECRET':'unit-test-only','USAGE_REDIS_URL':'redis://test.invalid'})
    def test_ed25519_auth_bound_replay_and_fail_closed(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from unittest.mock import AsyncMock
        import time
        private = Ed25519PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
        body = b'{"session_id":"missing","turn_id":"missing","text":"test"}'
        stamp = str(int(time.time())); nonce = 'unique-test-nonce-123'
        def headers(path='/isabelle/reply', timestamp=stamp, key_id='relay-test'):
            message = (timestamp+'\n'+nonce+'\nPOST\n'+path+'\n').encode()+body
            return {'x-bridge-key-id':key_id,'x-bridge-timestamp':timestamp,'x-bridge-nonce':nonce,
                    'x-bridge-signature':base64.b64encode(private.sign(message)).decode()}
        client = TestClient(app.app); redis = AsyncMock(); redis.set.return_value=True
        with self.env(), patch.dict(os.environ, {'BRIDGE_HMAC_ENABLED':'0', 'BRIDGE_RELAY_PUBLIC_KEYS':json.dumps({'relay-test':public})}), patch.object(app,'bridge_client',return_value=redis):
            self.assertTrue(app.bridge_ready())
            self.assertEqual(client.post('/isabelle/reply',content=body,headers=headers()).status_code,409)
            redis.set.assert_awaited_with('voice:bridge:v1:nonce:relay-test:'+nonce,'1',nx=True,ex=300)
            redis.set.return_value=False
            self.assertEqual(client.post('/isabelle/reply',content=body,headers=headers()).status_code,409)
            for h in [headers(path='/isabelle/brief'), headers(timestamp=str(int(stamp)-121)), headers(key_id='wrong')]:
                self.assertEqual(client.post('/isabelle/reply',content=body,headers=h).status_code,401)
            self.assertEqual(client.post('/isabelle/reply',content=body+b' ',headers=headers()).status_code,401)
            self.assertEqual(client.post('/isabelle/reply',content=body).status_code,401)
            redis.set.side_effect=ConnectionError('offline')
            self.assertEqual(client.post('/isabelle/reply',content=body,headers=headers()).status_code,503)
        with self.env(), patch.dict(os.environ, {'BRIDGE_HMAC_ENABLED':'0','BRIDGE_RELAY_PUBLIC_KEYS':'invalid'}):
            self.assertFalse(app.bridge_ready())
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
            s.speak_text=speak
            s.play_cached=__import__('unittest.mock',fromlist=['AsyncMock']).AsyncMock();s.respond=respond
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
            s.play_cached=__import__('unittest.mock',fromlist=['AsyncMock']).AsyncMock()
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
    def test_brief_requires_verified_authorized_audience(self):
        import time,hmac,hashlib
        async def t():
            f=asyncio.get_running_loop().create_future();app.BRIEF_PENDING['brief-test']={'session_id':'s','future':f}
            def post(value):
                body=json.dumps(value).encode();stamp=str(int(time.time()));sig=hmac.new(b'unit-test-only',stamp.encode()+b'.'+body,hashlib.sha256).hexdigest()
                return TestClient(app.app).post('/isabelle/brief',content=body,headers={'x-bridge-timestamp':stamp,'x-bridge-signature':sig})
            base={'turn_id':'brief-test','session_id':'s','brief':'Public test context','source_reference':'test-only'}
            with self.env():
                self.assertEqual(post(base).status_code,403)
                base.update(audience_verified=True,disclosure_authorized=True)
                self.assertEqual(post(dict(base,brief='x'*1501)).status_code,422)
                self.assertEqual(post(dict(base,session_id='wrong')).status_code,409)
                self.assertEqual(post(base).status_code,200);self.assertEqual(f.result(),base['brief'])
                self.assertEqual(post(base).status_code,409)
            app.BRIEF_PENDING.clear()
        asyncio.run(t())
    def test_brief_request_no_speech_or_llm(self):
        async def t():
            s=app.Session(FakeSocket());s.call_sid='CA-test';seen=[]
            async def publish(e):
                seen.append(e);app.BRIEF_PENDING[e['turn_id']]['future'].set_result('Generic synthetic brief');return None
            with self.env(),patch.object(app,'bridge_publish',side_effect=publish):await s.request_brief()
            self.assertEqual(s.caller_brief,'Generic synthetic brief');self.assertEqual(seen[0]['type'],'context_brief_request');self.assertEqual(seen[0]['caller_identity'],'unverified');self.assertEqual(app.BRIEF_PENDING,{})
        asyncio.run(t())
    def test_owner_name_synthesis_respelling(self):
        class Budget:
            limit=100
            async def reserve(self,text):self.text=text;return 50
        class TTS:
            async def send(self,value):self.value=json.loads(value)
        async def t():
            s=app.Session(FakeSocket());s.budget=Budget();tts=TTS()
            source={'text':"Verick's name is Verick, not Vericka.",'voice':{'id':'test'}}
            await s.send_tts(tts,source,{})
            self.assertEqual(tts.value['text'],"Vairick's name is Vairick, not Vericka.")
            self.assertEqual(s.budget.text,tts.value['text'])
            self.assertEqual(source['text'],"Verick's name is Verick, not Vericka.")
        asyncio.run(t())

class RecordingTests(unittest.IsolatedAsyncioTestCase):
    async def test_cipher_and_events(self):
        from unittest.mock import AsyncMock, MagicMock
        with patch.dict(os.environ, {'USAGE_REDIS_URL':'redis://localhost:6379','TWILIO_AUTH_TOKEN':'private-fixture'}):
            c=app.CallCapture('CA'+'a'*32, 'a'*24)
            fake=MagicMock(); pipe=MagicMock();pipe.execute=AsyncMock();fake.pipeline.return_value=pipe
            c.client=fake
            c.add('stt_final', transcript="What's on my calendar for Friday?")
            await c.flush()
            key, sealed=pipe.rpush.call_args.args
            self.assertNotIn(b'calendar',sealed)
            decoded=json.loads(c.cipher.decrypt(sealed[:12],sealed[12:],key.encode()))
            self.assertEqual(decoded[0]['transcript'],"What's on my calendar for Friday?")
            self.assertLessEqual(c.retention,30*86400)
    async def test_storage_failure_fail_closed(self):
        from unittest.mock import AsyncMock, MagicMock
        with patch.dict(os.environ, {'USAGE_REDIS_URL':'redis://localhost:6379','TWILIO_AUTH_TOKEN':'private-fixture'}):
            c=app.CallCapture('CA'+'a'*32, 'a'*24)
            fake=MagicMock(); pipe=MagicMock();pipe.execute=AsyncMock(side_effect=RuntimeError());fake.pipeline.return_value=pipe;c.client=fake
            c.add('inbound_media',payload='abcd')
            with self.assertRaisesRegex(RuntimeError,'recording_storage_failed'):await c.flush()
            with self.assertRaises(RuntimeError):c.add('more')
    async def test_provider_request_dual(self):
        from unittest.mock import AsyncMock, MagicMock
        with patch.dict(os.environ,{'TWILIO_RECORDING_ENABLED':'1','TWILIO_ACCOUNT_SID':'AC'+'a'*32,'TWILIO_AUTH_TOKEN':'test'}):
            client=MagicMock();response=MagicMock();response.json.return_value={'sid':'RE'+'b'*32,'channels':2};client.post=AsyncMock(return_value=response)
            with patch.object(app,'bridge_client') as factory:
                factory.return_value.zadd=AsyncMock();factory.return_value.aclose=AsyncMock()
                await app.start_provider_recording(client,'CA'+'a'*32)
            data=client.post.call_args.kwargs['data']
            self.assertEqual(data['RecordingChannels'],'dual');self.assertEqual(data['RecordingTrack'],'both')
    async def test_no_recording_auth_public_access(self):
        r=TestClient(app.app).get('/recordings');self.assertEqual(r.status_code,401)
        r=TestClient(app.app).get('/recordings/'+'a'*24);self.assertEqual(r.status_code,401)
    async def test_noise_does_not_strand_final(self):
        class STT:
            def __aiter__(self):return self.run()
            async def run(self):
                yield json.dumps({'type':'Results','is_final':True,'speech_final':True,'channel':{'alternatives':[{'transcript':'calendar Friday'}]}})
                yield json.dumps({'type':'SpeechStarted'})
        from unittest.mock import AsyncMock
        s=app.Session(FakeSocket());s.dg=STT();s.handle_utterance=AsyncMock();await s.listen();await asyncio.sleep(.8)
        s.handle_utterance.assert_awaited_once_with('calendar Friday')

class CachedAudioTests(unittest.IsolatedAsyncioTestCase):
    async def test_cached_hello_starts_without_generation(self):
        from unittest.mock import AsyncMock
        s=app.Session(FakeSocket());s.budget.reserve=AsyncMock();await s.play_cached('hello')
        self.assertEqual(s.ws.sent[0]['event'],'media');s.budget.reserve.assert_not_called()
        data=b''.join(base64.b64decode(m['media']['payload']) for m in s.ws.sent if m['event']=='media')
        self.assertEqual(data,base64.b64decode(app.CACHED_AUDIO['hello']))
    async def test_cached_handoff_is_bounded(self):
        self.assertLess(len(base64.b64decode(app.CACHED_AUDIO['handoff'])),64000)

class AudioQualityTests(unittest.IsolatedAsyncioTestCase):
    async def test_out_of_band_tone_is_filtered(self):
        import numpy as np
        samples=(10000*np.sin(2*np.pi*6000*np.arange(48000)/48000)).astype('<i2')
        class Source:
            def __aiter__(self):return self.run()
            async def run(self):
                for offset in range(0,len(samples),777):
                    yield json.dumps({'audio':base64.b64encode(samples[offset:offset+777].tobytes()).decode()})
        ws=FakeSocket();s=app.Session(ws);ws.session=s;s.stream_sid='test'
        metric={'start':app.now()};await s.consume_tts(Source(),metric)
        audio=b''.join(base64.b64decode(x['media']['payload']) for x in ws.sent if x['event']=='media')
        out=np.frombuffer(app.audioop.ulaw2lin(audio,2),dtype='<i2').astype(float)
        self.assertEqual(len(out),8000)
        self.assertLess(np.sqrt(np.mean(out[300:-300]**2)),5)
        self.assertEqual(metric['resampler'],'soxr_HQ')
    async def test_raw_pcm_capture_and_odd_byte_carry(self):
        from unittest.mock import Mock
        ws=FakeSocket();s=app.Session(ws);ws.session=s;s.stream_sid='test';s.capture=Mock()
        await s.consume_tts(AudioSource(),{'start':app.now()})
        captured=[x for x in s.capture.add.call_args_list if x.args[0]=='hume_pcm']
        self.assertEqual(len(captured),2)
        self.assertEqual(sum(len(base64.b64decode(x.kwargs['audio'])) for x in captured),1920)
        self.assertTrue(all(x.kwargs['sample_rate']==48000 for x in captured))
    async def test_handoff_starts_cached_audio_before_publish(self):
        from unittest.mock import AsyncMock
        s=app.Session(FakeSocket());s.play_cached=AsyncMock();s.process_bridge=AsyncMock()
        with patch.object(app,'bridge_ready',return_value=True):
            await s.handle_utterance('Let me speak to Isabelle')
            await asyncio.sleep(.01)
        s.play_cached.assert_awaited_once_with('handoff')
        self.assertEqual(s.mode,'isabelle')

class CallFeedbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_greeting_delay_point_eight(self):
        from unittest.mock import AsyncMock
        s=app.Session(FakeSocket());s.play_cached=AsyncMock()
        with patch.object(app.asyncio,'sleep',new_callable=AsyncMock) as sleeper:
            await s.greet()
        sleeper.assert_awaited_once_with(.8)
        s.play_cached.assert_awaited_once_with('hello')
    async def test_caller_line_metadata_is_not_authority(self):
        from unittest.mock import AsyncMock
        s=app.Session(FakeSocket());s.caller_number='+17865271894';s.caller_recognized=True
        async def publish(e):
            self.assertEqual(e['caller_number'],'+17865271894')
            self.assertTrue(e['caller_line_recognized'])
            self.assertEqual(e['caller_identity'],'unverified')
            app.BRIDGE_PENDING[e['turn_id']]['future'].set_result('Test reply')
            return 'mock'
        s.speak_text=AsyncMock();s.clear=AsyncMock()
        with patch.object(app,'bridge_publish',side_effect=publish),patch.object(app,'bridge_ack',new_callable=AsyncMock),patch.dict(os.environ,{'ISABELLE_HUME_VOICE_ID':'test'}):
            await s.bridge_queue.put((1,'test'))
            task=asyncio.create_task(s.process_bridge())
            await asyncio.wait_for(s.bridge_queue.join(),1)
            task.cancel();await asyncio.gather(task,return_exceptions=True)
    def test_allowed_lines_exact_match(self):
        with patch.dict(os.environ,{'TEST_FROM_NUMBERS':'+17865271894,+15555555555,bad'}):
            self.assertEqual(app.allowed_callers(),{'+17865271894','+15555555555'})
