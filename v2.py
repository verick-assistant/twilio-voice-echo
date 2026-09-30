"""Realtime telephony adapter. No recordings, transcripts, or credentials in logs."""
import asyncio
import audioop
import base64
import contextlib
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import time
from collections import deque
from urllib.parse import urlencode

import httpx
import websockets
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
from twilio.request_validator import RequestValidator

log = logging.getLogger('voice')
app = FastAPI()
VERSION = '2.0.0'
BASE = os.getenv('BASE_URL', '').rstrip('/')
KEYS = ('DEEPGRAM_API_KEY', 'OPENROUTER_API_KEY', 'HUME_API_KEY', 'TYPESAFE_API_KEY')
# Model IDs are configurable and must be validated against OpenRouter before live use.
MODELS = {'fast': os.getenv('MODEL_FAST', 'openai/gpt-4.1-mini'),
          'capable': os.getenv('MODEL_CAPABLE', 'anthropic/claude-sonnet-4')}
SYSTEM = ('You are a voice assistant on a phone call. Speak naturally in brief sentences. '
          'Do not claim access to private accounts, memory, tools, or actions: this voice service '
          'does not have those capabilities yet. Never claim an action is done. Ask for clarification '
          'when needed. Do not read markdown aloud. Keep most replies under 60 words.')


def now():
    return time.monotonic()


def signature_valid(url, params, supplied):
    token = os.getenv('TWILIO_AUTH_TOKEN', '')
    if not token or not supplied:
        return False
    return RequestValidator(token).validate(url, params, supplied)


def stream_token(call_sid, expiry):
    secret = os.getenv('STREAM_SECRET') or os.getenv('TWILIO_AUTH_TOKEN', '')
    return hmac.new(secret.encode(), f'{call_sid}:{expiry}'.encode(), hashlib.sha256).hexdigest()


def ready():
    return all(os.getenv(k) for k in KEYS if k != 'TYPESAFE_API_KEY') and bool(os.getenv('HUME_VOICE_ID') or os.getenv('HUME_VOICE_NAME'))


@app.get('/health')
async def health():
    return {'ok': True, 'version': VERSION, 'realtime_ready': ready(),
            'providers': {k.removesuffix('_API_KEY').lower(): bool(os.getenv(k)) for k in KEYS},
            'voice_configured': bool(os.getenv('HUME_VOICE_ID') or os.getenv('HUME_VOICE_NAME')),
            'twilio_env': bool(os.getenv('TWILIO_ACCOUNT_SID') and os.getenv('TWILIO_AUTH_TOKEN'))}


@app.api_route('/voice', methods=['POST', 'GET'])
async def voice(request: Request):
    params = dict(await request.form()) if request.method == 'POST' else dict(request.query_params)
    if not BASE or not signature_valid(BASE + '/voice', params, request.headers.get('x-twilio-signature', '')):
        return Response(status_code=403)
    if not ready():
        return Response('<?xml version="1.0"?><Response><Say>The realtime voice service is not ready yet. Please try again later.</Say><Hangup/></Response>', media_type='text/xml')
    sid = params.get('CallSid', '')
    expiry = str(int(time.time()) + 90)
    url = BASE.replace('https://', 'wss://').replace('http://', 'ws://') + '/media-stream'
    body = (f'<Response><Connect><Stream url="{html.escape(url, quote=True)}">'
            f'<Parameter name="expires" value="{expiry}"/>'
            f'<Parameter name="token" value="{stream_token(sid, expiry)}"/>'
            '</Stream></Connect></Response>')
    return Response(body, media_type='text/xml')


@app.post('/call')
async def call(request: Request):
    # POST only. No token in query string and no caller-selectable destination.
    supplied = request.headers.get('x-call-token', '')
    expected = os.getenv('CALL_TOKEN', '')
    if not expected or not hmac.compare_digest(supplied, expected):
        return JSONResponse({'ok': False, 'error': 'unauthorized'}, status_code=401)
    if not ready():
        return JSONResponse({'ok': False, 'error': 'realtime providers not ready'}, status_code=503)
    sid, token = os.getenv('TWILIO_ACCOUNT_SID', ''), os.getenv('TWILIO_AUTH_TOKEN', '')
    source, dest = os.getenv('TWILIO_FROM_NUMBER', ''), os.getenv('TEST_TO_NUMBER', '')
    if not all((sid, token, source, dest, BASE)):
        return JSONResponse({'ok': False, 'error': 'call configuration incomplete'}, status_code=503)
    async with httpx.AsyncClient() as client:
        r = await client.post(f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json',
                              auth=(sid, token), data={'To': dest, 'From': source, 'Url': BASE + '/voice'}, timeout=20)
        if not r.is_success:
            return JSONResponse({'ok': False, 'error': 'Twilio rejected call', 'status': r.status_code}, status_code=502)
        return {'ok': True, 'call_sid': r.json().get('sid')}


class Session:
    def __init__(self, ws):
        self.ws = ws
        self.stream_sid = ''
        self.tasks = set()
        self.turn = None
        self.dg = None
        self.history = []
        self.final_parts = []
        self.playing = False
        self.route_text = ''
        self.route_task = None
        self.started = now()
        self.turn_index = 0
        self.closed = False
        self.audio_queue = asyncio.Queue(maxsize=250) # five seconds of inbound 20ms audio
        self.pending_marks = set()
        self.metrics = deque(maxlen=30)

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def send(self, data):
        await self.ws.send_json(data)

    async def clear(self):
        if self.turn and not self.turn.done():
            self.turn.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self.turn
        if self.playing:
            await self.send({'event': 'clear', 'streamSid': self.stream_sid})
        self.pending_marks.clear()
        self.playing = False

    async def route(self, text):
        # Start on interim text; never block STT/audio transport on routing.
        start = now()
        if not os.getenv('TYPESAFE_API_KEY'):
            return 'capable', 0, 'fallback_no_jev_key'
        criteria = {'fast': 'Short conversation, simple facts, or clarification. Minimize latency and cost.',
                    'capable': 'Complex reasoning, technical planning, sensitive or ambiguous requests. Prioritize capability.'}
        try:
            r = await self.client.post('https://api.typesafe.ai/v1/systemone',
                headers={'Authorization': 'Bearer ' + os.environ['TYPESAFE_API_KEY']},
                json={'model': 'jev-latest', 'state': {'utterance': text},
                      'questions': {'route': {'type': 'choice', 'instructions': 'Choose the response model class.', 'criteria': criteria}}},
                timeout=1.5)
            r.raise_for_status()
            answer = r.json()['answers']['route']
            choice = answer['choice']
            confidence = float(answer.get('confidence', 0))
            if choice not in MODELS or confidence < .75:
                choice = 'capable'
            return choice, round((now()-start)*1000), 'jev'
        except asyncio.CancelledError:
            raise
        except Exception:
            # Explicit degraded routing, not an assertion that Jev ran.
            return 'capable', round((now()-start)*1000), 'fallback'

    async def listen(self):
        async for raw in self.dg:
            msg = json.loads(raw)
            if msg.get('type') == 'SpeechStarted':
                await self.clear()
                continue
            if msg.get('type') == 'Error':
                raise RuntimeError('stt_provider_error')
            if msg.get('type') != 'Results':
                continue
            alternatives = msg.get('channel', {}).get('alternatives', [])
            text = alternatives[0].get('transcript', '').strip() if alternatives else ''
            if text and not msg.get('is_final'):
                if self.route_task is None or self.route_task.done():
                    self.route_text = text
                    self.route_task = self.spawn(self.route(text))
            if msg.get('is_final') and text:
                self.final_parts.append(text)
            if msg.get('speech_final') and self.final_parts:
                utterance = ' '.join(self.final_parts)
                self.final_parts.clear()
                await self.clear()
                self.turn_index += 1
                self.turn = self.spawn(self.respond(utterance))

    async def upload_audio(self):
        while True:
            try:
                audio = await asyncio.wait_for(self.audio_queue.get(), timeout=4)
                await self.dg.send(audio)
            except asyncio.TimeoutError:
                await self.dg.send(json.dumps({'type': 'KeepAlive'}))

    async def llm(self, text, model, metric):
        messages = [{'role': 'system', 'content': SYSTEM}] + self.history[-12:] + [{'role': 'user', 'content': text}]
        async with self.client.stream('POST', 'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': 'Bearer ' + os.environ['OPENROUTER_API_KEY']},
            json={'model': model, 'messages': messages, 'stream': True, 'max_tokens': 160,
                  'provider': {'sort': 'latency'}}, timeout=20) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith('data: '):
                    continue
                value = line[6:]
                if value == '[DONE]':
                    break
                data = json.loads(value)
                if data.get('error'):
                    raise RuntimeError('llm_provider_error')
                choices = data.get('choices', [])
                delta = choices[0].get('delta', {}).get('content', '') if choices else ''
                if delta:
                    if 'llm_first_token_ms' not in metric:
                        metric['llm_first_token_ms'] = round((now()-metric['start'])*1000)
                    yield delta

    async def respond(self, text):
        metric = {'turn': self.turn_index, 'start': now()}
        response_text = ''
        # Connect TTS while the route resolves, hiding connection setup behind routing.
        query = urlencode({'api_key': os.environ['HUME_API_KEY'], 'format_type': 'pcm',
                           'strip_headers': 'true', 'no_binary': 'true', 'instant_mode': 'true'})
        tts_task = asyncio.create_task(websockets.connect('wss://api.hume.ai/v0/tts/stream/input?' + query,
                                                       open_timeout=8).__aenter__())
        tts = None
        consumer = None
        try:
            if self.route_task and text == self.route_text:
                choice, latency, source = await self.route_task
            else:
                if self.route_task and not self.route_task.done():
                    self.route_task.cancel()
                choice, latency, source = await self.route(text)
            metric.update(route_ms=latency, route_source=source, model=MODELS[choice])
            tts = await tts_task
            consumer = asyncio.create_task(self.consume_tts(tts, metric))
            voice = {'id': os.environ['HUME_VOICE_ID'], 'provider': 'HUME_AI'} if os.getenv('HUME_VOICE_ID') else {'name': os.environ['HUME_VOICE_NAME'], 'provider': 'HUME_AI'}
            pending = ''
            first = True
            async for delta in self.llm(text, MODELS[choice], metric):
                response_text += delta
                pending += delta
                # Preserve phrase prosody, but flush the first short phrase promptly.
                if any(p in pending for p in '.!?;\n') or (first and len(pending) >= 45 and ' ' in pending):
                    await tts.send(json.dumps({'text': pending, 'voice': voice, 'flush': True,
                                              'description': 'Warm, clear, natural conversational delivery.'}))
                    pending = ''
                    first = False
                elif len(pending) >= 140:
                    await tts.send(json.dumps({'text': pending, 'voice': voice, 'flush': True}))
                    pending = ''
            if pending:
                await tts.send(json.dumps({'text': pending, 'voice': voice, 'flush': True}))
            await tts.send(json.dumps({'close': True}))
            await asyncio.wait_for(consumer, timeout=30)
            self.history.extend([{'role': 'user', 'content': text}, {'role': 'assistant', 'content': response_text}])
            self.history = self.history[-12:]
            metric['completed'] = True
        except asyncio.CancelledError:
            metric['interrupted'] = True
            raise
        except Exception as exc:
            metric['error_type'] = type(exc).__name__ # never log exception URLs containing API keys
            await self.send({'event': 'clear', 'streamSid': self.stream_sid})
            self.playing = False
        finally:
            if consumer and not consumer.done():
                consumer.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await consumer
            if tts:
                await tts.close()
            elif not tts_task.done():
                tts_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await tts_task
            elif not tts_task.cancelled():
                with contextlib.suppress(Exception):
                    await tts_task.result().close()
            metric['total_ms'] = round((now()-metric.pop('start'))*1000)
            self.metrics.append(metric)
            log.warning('voice_stage_timings %s', json.dumps(metric))

    async def consume_tts(self, tts, metric):
        converter = None
        remainder = b''
        queued = bytearray()
        async for raw in tts:
            msg = json.loads(raw)
            if msg.get('type') == 'error' or msg.get('error'):
                raise RuntimeError('tts_provider_error')
            encoded = msg.get('audio')
            if not encoded:
                continue
            pcm = remainder + base64.b64decode(encoded, validate=True)
            remainder = pcm[len(pcm) - len(pcm)%2:] if len(pcm)%2 else b''
            pcm = pcm[:len(pcm)-len(pcm)%2]
            if not pcm:
                continue
            # Hume PCM is signed 16-bit mono at 48kHz per its official player.
            # Stateful conversion avoids discontinuities between streamed chunks.
            down, converter = audioop.ratecv(pcm, 2, 1, int(os.getenv('HUME_SAMPLE_RATE', '48000')), 8000, converter)
            queued.extend(audioop.lin2ulaw(down, 2))
            frames = 0
            while len(queued) >= 160:
                audio = bytes(queued[:160]); del queued[:160]
                frames += 1
                if 'first_audio_ms' not in metric:
                    metric['first_audio_ms'] = round((now()-metric['start'])*1000)
                self.playing = True
                await self.send({'event': 'media', 'streamSid': self.stream_sid,
                                 'media': {'payload': base64.b64encode(audio).decode()}})
                if frames % 10 == 0:
                    mark = secrets.token_hex(4)
                    self.pending_marks.add(mark)
                    await self.send({'event': 'mark', 'streamSid': self.stream_sid, 'mark': {'name': mark}})
                    deadline = now() + 10
                    while len(self.pending_marks) >= 2:
                        if now() > deadline:
                            raise TimeoutError('playback_ack_timeout')
                        await asyncio.sleep(.01)
            # Backpressure: keep Twilio's queued playback below a short window.
            mark = secrets.token_hex(4)
            self.pending_marks.add(mark)
            await self.send({'event': 'mark', 'streamSid': self.stream_sid, 'mark': {'name': mark}})
            deadline = now() + 10
            while len(self.pending_marks) >= 2:
                if now() > deadline:
                    raise TimeoutError('playback_ack_timeout')
                await asyncio.sleep(.01)
        if queued:
            self.playing = True
            await self.send({'event': 'media', 'streamSid': self.stream_sid,
                             'media': {'payload': base64.b64encode(queued).decode()}})
            mark = secrets.token_hex(4)
            self.pending_marks.add(mark)
            await self.send({'event': 'mark', 'streamSid': self.stream_sid, 'mark': {'name': mark}})

    async def run(self):
        async with httpx.AsyncClient() as self.client:
            try:
                start = await asyncio.wait_for(self.ws.receive_json(), 8)
                if start.get('event') == 'connected':
                    start = await asyncio.wait_for(self.ws.receive_json(), 8)
                data = start.get('start', {})
                parameters = data.get('customParameters', {})
                expiry = parameters.get('expires', '0')
                supplied = parameters.get('token', '')
                sid = data.get('callSid', '')
                if start.get('event') != 'start' or int(expiry) < time.time() or int(expiry) > time.time()+100 or not supplied or not hmac.compare_digest(supplied, stream_token(sid, expiry)):
                    await self.ws.close(code=1008)
                    return
                fmt = data.get('mediaFormat', {})
                if fmt != {'encoding': 'audio/x-mulaw', 'sampleRate': 8000, 'channels': 1}:
                    await self.ws.close(code=1003)
                    return
                self.stream_sid = start['streamSid']
                query = urlencode({'model': 'nova-3', 'encoding': 'mulaw', 'sample_rate': 8000,
                                   'channels': 1, 'interim_results': 'true', 'vad_events': 'true',
                                   'endpointing': os.getenv('ENDPOINTING_MS', '100'), 'smart_format': 'true'})
                async with websockets.connect('wss://api.deepgram.com/v1/listen?' + query,
                     additional_headers={'Authorization': 'Token ' + os.environ['DEEPGRAM_API_KEY']}, open_timeout=8) as self.dg:
                    reader = self.spawn(self.listen())
                    uploader = self.spawn(self.upload_audio())
                    while True:
                        receive = asyncio.create_task(self.ws.receive_json())
                        done, _ = await asyncio.wait({receive, reader, uploader}, return_when=asyncio.FIRST_COMPLETED)
                        if reader in done or uploader in done:
                            receive.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await receive
                            raise RuntimeError('stt_transport_closed')
                        msg = receive.result()
                        if msg.get('event') == 'stop':
                            break
                        if msg.get('event') == 'media':
                            payload = base64.b64decode(msg['media']['payload'], validate=True)
                            if len(payload) > 8000:
                                raise ValueError('oversized_media')
                            self.audio_queue.put_nowait(payload)
                        elif msg.get('event') == 'mark':
                            self.pending_marks.discard(msg.get('mark', {}).get('name'))
                            if not self.pending_marks:
                                self.playing = False
            except (WebSocketDisconnect, asyncio.CancelledError):
                pass
            except Exception as exc:
                log.warning('voice_session_stopped %s', type(exc).__name__)
                with contextlib.suppress(Exception):
                    await self.ws.close(code=1011)
            finally:
                for task in list(self.tasks):
                    task.cancel()
                await asyncio.gather(*list(self.tasks), return_exceptions=True)
                self.history.clear()


@app.websocket('/media-stream')
async def media_stream(ws: WebSocket):
    # Authenticate both the Twilio handshake and a short-lived per-call signed token.
    url = BASE + '/media-stream'
    if not BASE or not ready() or not signature_valid(url, {}, ws.headers.get('x-twilio-signature', '')):
        await ws.close(code=1008)
        return
    await ws.accept()
    await Session(ws).run()
