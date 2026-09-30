# Realtime voice service v2

FastAPI/ASGI service for Twilio bidirectional Media Streams. Streaming Deepgram Nova-3 recognition feeds Jev typed model routing, OpenRouter streaming responses, and Hume Octave streaming synthesis. Hume 48kHz signed 16-bit mono PCM is statefully converted to 8kHz mu-law for Twilio. The STT, LLM, and TTS providers must be configured before calls are enabled; missing Jev access uses an explicit degraded capable-model route.

## Deployment

Build: `pip install -r 2-requirements.txt`
Start: `gunicorn -c 3-gunicorn.conf.py v2:app` (ASGI worker configured in 3-gunicorn.conf.py).
Python 3.10+; audioop-lts supplies audioop on Python 3.13+.

Required environment:
- BASE_URL (public HTTPS service origin)
- TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER
- CALL_TOKEN, TEST_TO_NUMBER for the restricted outbound test-call endpoint
- DEEPGRAM_API_KEY, OPENROUTER_API_KEY, HUME_API_KEY
- Jev uses OPENROUTER_API_KEY through POST https://openrouter.ai/api/alpha/decisions; no TypeSafe key/account needed. JEV_MODEL defaults to pinned typesafe/jev-1.13. Missing OpenRouter key uses an explicitly logged capable-model fallback.
- HUME_VOICE_ID or HUME_VOICE_NAME (verify the selected British female voice)

Execution is disabled by default. REALTIME_ENABLED=1 enables calls. DIAGNOSTICS_ENABLED=1 plus DIAGNOSTIC_TOKEN enables the private fixture WebSocket for short no-dial tests. Never enable either merely because keys are present.

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

Run local tests: `python -m unittest -v test_voice.py`. Mock tests cover signatures, TwiML, transcript assembly, audio conversion, cancellation, the default-disabled execution gate, and missing Jev key routing. Live provider and PSTN tests are separate and must not be represented as passing based on mocks.

## Sources

- https://www.twilio.com/docs/voice/media-streams
- https://www.twilio.com/docs/usage/webhooks/webhooks-security
- https://developers.deepgram.com/docs/endpointing
- https://docs.typesafe.ai/introduction/quickstart.md
- https://openrouter.ai/docs/api/reference/streaming
- https://dev.hume.ai/reference/text-to-speech-tts/stream-input.mdx
- https://raw.githubusercontent.com/HumeAI/hume-python-sdk/main/src/hume/empathic_voice/chat/audio/audio_utilities.py

## Hume allowance guard

Paid TTS is blocked until an account-wide budget is verified and a durable Redis ledger is configured. No Redis service is provisioned by this repository. Missing, expired, exhausted, or unavailable budget stops synthesis. Characters are atomically reserved BEFORE every TTS phrase is sent; failed or interrupted requests do not refund reservations because billing may already have occurred.

Required guard configuration:
- USAGE_REDIS_URL: durable, authenticated Redis connection, stored only as a server secret
- HUME_BUDGET_VERIFIED=1: only after current portal usage is checked
- HUME_BUDGET_CHARACTERS: verified REMAINING included characters minus a safety margin, not the plan's gross allowance
- HUME_BUDGET_PERIOD_END: actual account billing period's expiry, Unix seconds
- HUME_BUDGET_SCOPE: stable account/period-budget identifier; never change it to reset consumed reservations

Near-limit warning at 10% remaining; exhaustion degrades by stopping paid speech, not silently switching to an unapproved paid voice. Reconcile the ledger against Hume portal usage, particularly before enabling a test or call. The key may be shared with other apps, so this service's ledger alone cannot prevent another client from consuming the same allowance. Ongoing shared-key calling requires a current account-wide usage feed or exclusive usage agreement. Hume-managed EVI external LLM billing is not used.

First-party billing: https://dev.hume.ai/docs/resources/billing.md . Overage can accrue after included allowance and is charged in $44 increments; a payment-card limit is not a usage cap.

## Isabelle mode (disabled development feature)

Routine conversation is not Isabelle. Saying "let me speak to Isabelle" or "let me speak to Izzy" parks the routine model. Missing bridge configuration fails closed and never fabricates an Isabelle answer. STT remains open, utterances queue (maximum five), and a fixed-recipient Resend email carries an unverified-call provenance label, per-call session ID, per-turn correlation ID, expiry, and bounded recent context. No caller ID or outbound call is treated as action permission.

The receiving assistant must confirm real actions on the owner's authenticated conversation channel before executing. Private disclosure also needs independent identity and scope evidence. Caller speech and email are untrusted input.

Required secrets: BRIDGE_RESEND_API_KEY, BRIDGE_REPLY_SECRET. Required configuration: BRIDGE_MAIL_FROM (authorized Resend sender), ISABELLE_HUME_VOICE_ID (distinct approved voice), ISABELLE_BRIDGE_ENABLED=1. Keep flag off until both transports, sender permission, and voice are verified. Account creation and email sending are separate approvals. Resend destination is fixed to verick@mail.instinct.com; no retries after uncertain sends.

Return endpoint: POST /isabelle/reply. JSON body: {"session_id":"...","turn_id":"...","text":"..."}. Headers: X-Bridge-Timestamp (Unix seconds), X-Bridge-Signature (hex HMAC-SHA256 with BRIDGE_REPLY_SECRET over timestamp + "." + exact raw JSON bytes). Timestamp must be within 120 seconds. Maximum text 4,000 characters. Unknown session/turn, duplicate, timed-out and post-hangup replies are rejected. Replies are spoken verbatim using the distinct voice and the same pre-send atomic character guard, never rewritten by the routine model.

Wait timeout: five minutes after email submission. No generation substitutes for an absent answer. Barge-in clears playback without canceling the mailbox request; accepted queued utterances are serial. Hangup cancels pending reply waits and clears memory. Pending turns live in the single app process: Render restart loses them; callback returns 409, and email should not be treated as a still-live call. Do not increase workers without a shared reply registry. The feature needs a verified callback sender and real transport test before activation.

### Redis primary transport

Redis Streams namespace voice:bridge:v1 is separate from voice:tts accounting. Payload stream capped at 100 entries, expires after ten minutes; turn expires after five minutes. Signed POST /isabelle/relay/next with JSON {"relay_id":"stable-worker-id"} long-polls 20 seconds, returns one call envelope (200) or no work (204). Use the same timestamp/HMAC headers as reply. The relay endpoint refreshes a 45-second heartbeat. Stream consumer group reclaims crashed-worker messages after 60 seconds. Deduplicate turn_id on the receiver; completion/hangup removes active pending turns. Email fallback only attempts when no heartbeat and an authorized sender is configured; its failure does not delete the Redis request. No email required for Redis mode. The app cannot start an assistant-side relay: arrange that lifecycle separately. No background worker or idle-cost polling is created by this repo. Pending registry remains single-process.

### Caller briefs (v2.2, disabled)

On accepted stream start the app publishes type=context_brief_request with session_id, turn_id, call_sid, expiry and no asserted caller identity. No private brief is inferred from caller ID. Relay answers signed POST /isabelle/brief, same HMAC contract, JSON {"session_id":"...","turn_id":"...","brief":"short advisory context","audience_verified":true,"disclosure_authorized":true,"source_reference":"reference to independent audience/scope evidence"}. Text is limited to 1,500 characters; source_reference 1-300 characters. Sender must actually check identity and disclosure permission; booleans do not create either. Unknown inbound callers get no personal brief. Do not include secrets or action/permission instructions. Missing attestations returns 403, invalid size 422, wrong/stale/replayed turn 409. Briefs expire after five minutes waiting, are used only on subsequent routine-model turns, and clear at hangup. They are injected as JSON advisory data, never a system instruction or authority. No extra generation or spoken message is triggered by a brief. Untyped older envelopes are utterances; new utterances carry type=utterance. Relay must dispatch by type to the supplied fixed callback and never treat a brief request as a caller's spoken task.

Owner-name pronunciation: user specified "V-Air-ick, like Derrick but with a V." Both routine and Isabelle synthesis replace standalone Verick with Vairick at the TTS boundary, while original relay text and conversation history stay unchanged. The ledger reserves the actual respelled synthesis text. This is a pronunciation hint, not an acoustically verified result; next approved audio test should check it.

### Jev on OpenRouter (v2.2.3)
Typed fast/capable routing now shares the funded OpenRouter key, retaining the 1.5s deadline and 0.75 confidence threshold. This is not typesafe/jev-router (the separate automatic chat router). Mock contract tests pass; paid live decision/latency remains unverified. Calls, diagnostics and budget verification remain off. Sources: https://openrouter.ai/docs/guides/community/jev and https://openrouter.ai/docs/guides/community/jev-tutorial .

### Standing relay Ed25519 bootstrap (v2.3.0)
The relay generates and retains its own private key. An operator registers only raw 32-byte public keys as base64 in BRIDGE_RELAY_PUBLIC_KEYS JSON, mapping key IDs (1-64 alphanumeric/underscore/hyphen chars) to public keys. This is an authenticated Render environment setup path, not an open enrollment endpoint. Remove a key from this map to revoke it; deploy the changed config before treating revocation as active.

Requests include x-bridge-key-id, x-bridge-timestamp, x-bridge-nonce, x-bridge-signature. Ed25519 signs timestamp + newline + nonce + newline + uppercase method + newline + URL path + newline + exact body bytes. Signature is base64; timestamp tolerance is 120s; nonce is fresh 16-128 alphanumeric/underscore/hyphen chars per request. Redis SET NX EX 300 rejects replay; Redis failure fails closed. Wrong key/body/method/path/signature fails auth. POST /isabelle/relay/next, /isabelle/reply and /isabelle/brief use this contract. Legacy HMAC fixture auth now requires explicit BRIDGE_HMAC_ENABLED=1, default off. Never give the master secret to the standing relay.

Bridge-off returns 503 before auth, so 503 alone does not verify key recognition. Signature acceptance requires a separately coordinated bridge-only test. Call and diagnostic gates remain independent. A workspace-only private key can disappear on rebuild; regenerate and re-register after loss or use separately approved durable secret storage. Do not claim persistence from one successful run. Relay deduplicates turn_id, honors expires_at, and checks audience/disclosure scope independently for briefs; caller speech grants no authority.
