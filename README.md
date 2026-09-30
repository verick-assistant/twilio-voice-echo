# Realtime voice service v2

FastAPI/ASGI service for Twilio bidirectional Media Streams. Streaming Deepgram Nova-3 recognition feeds Jev typed model routing, OpenRouter streaming responses, and Hume Octave streaming synthesis. Hume 48kHz signed 16-bit mono PCM is statefully converted to 8kHz mu-law for Twilio. All providers must be configured before calls are enabled.

## Deployment

Build: `pip install -r 2-requirements.txt`
Start: `gunicorn -c 3-gunicorn.conf.py v2:app` (ASGI worker configured in 3-gunicorn.conf.py).
Python 3.10+; audioop-lts supplies audioop on Python 3.13+.

Required environment:
- BASE_URL (public HTTPS service origin)
- TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER
- CALL_TOKEN, TEST_TO_NUMBER for the restricted outbound test-call endpoint
- DEEPGRAM_API_KEY, OPENROUTER_API_KEY, HUME_API_KEY
- TYPESAFE_API_KEY enables Jev; missing key uses an explicitly logged capable-model fallback
- HUME_VOICE_ID or HUME_VOICE_NAME (verify the selected British female voice)

Optional: STREAM_SECRET, MODEL_FAST, MODEL_CAPABLE, HUME_SAMPLE_RATE (48000), ENDPOINTING_MS (100).

Twilio voice webhook: POST `/voice`. WebSocket `/media-stream` validates Twilio signatures and a short-lived signed per-call token. Outbound `/call` is POST-only, requires X-Call-Token, and can dial only the configured test destination. `/health` exposes readiness booleans, never credentials.

## Behavior and limits

- Endpointing starts at 100ms silence, not a claim of 300ms total latency. Tune using real conversations; short pauses can split turns.
- Jev routing is attempted on interim speech and reused only when its input exactly matches the final turn. TTS connection setup overlaps route resolution.
- Jev failure/low confidence uses the capable route. Logs explicitly identify degraded routing.
- LLM text is flushed to TTS at phrase boundaries, without waiting for the complete response.
- SpeechStarted cancels generation, closes old TTS, and clears Twilio playback.
- Playback marks bound queued audio; transport queues and timeouts bound memory.
- Timing logs include model, routing status, first token and first audio. No audio recordings, transcript logging, or persistent conversation storage.
- The voice service has no access to private accounts, persistent memory, or action tools. Do not mistake a conversational model response for an action taken by an assistant.
- Render free instances can spin down for 50+ seconds. Warm tests are not cold-call guarantees.

Run local tests: `python -m unittest -v test_voice.py`. Mock tests cover signatures, TwiML, transcript assembly, audio conversion, and cancellation. Live provider and PSTN tests are separate and must not be represented as passing based on mocks.

## Sources

- https://www.twilio.com/docs/voice/media-streams
- https://www.twilio.com/docs/usage/webhooks/webhooks-security
- https://developers.deepgram.com/docs/endpointing
- https://docs.typesafe.ai/introduction/quickstart.md
- https://openrouter.ai/docs/api/reference/streaming
- https://dev.hume.ai/reference/text-to-speech-tts/stream-input.mdx
- https://raw.githubusercontent.com/HumeAI/hume-python-sdk/main/src/hume/empathic_voice/chat/audio/audio_utilities.py
