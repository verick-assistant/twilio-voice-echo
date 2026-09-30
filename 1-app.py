import html
import os

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

TWILIO_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER", "+17372324091")
TO_NUMBER = os.environ.get("TEST_TO_NUMBER", "+17865271894")
CALL_TOKEN = os.environ.get("CALL_TOKEN", "")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
VOICE = "Polly.Matthew"

GREETING = (
    "Hi, this is Verick's assistant running a voice plumbing test. "
    "Say a short sentence after the beep, and I will repeat it back to you."
)


def twiml(inner):
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?><Response>' + inner + "</Response>",
        mimetype="text/xml",
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify(ok=True, twilio_env=bool(TWILIO_SID and TWILIO_TOKEN))


@app.route("/voice", methods=["POST", "GET"])
def voice():
    inner = (
        f'<Gather input="speech" action="/gather" method="POST" '
        f'speechTimeout="auto" timeout="6" language="en-US">'
        f'<Say voice="{VOICE}">{html.escape(GREETING)}</Say></Gather>'
        f'<Say voice="{VOICE}">I did not hear anything. The outbound dial and text to speech work though. Goodbye.</Say>'
    )
    return twiml(inner)


@app.route("/gather", methods=["POST"])
def gather():
    speech = (request.form.get("SpeechResult") or "").strip()
    if speech:
        say = (
            f"You said: {speech}. "
            "That completes the loop: outbound dial, speech out, speech recognition in, and a spoken reply. Goodbye."
        )
    else:
        say = "No words came through that time, but the call plumbing itself works. Goodbye."
    return twiml(f'<Say voice="{VOICE}">{html.escape(say)}</Say><Hangup/>')


@app.route("/call", methods=["POST", "GET"])
def call():
    token = (
        request.args.get("token")
        or request.form.get("token")
        or request.headers.get("X-Call-Token", "")
    )
    if not CALL_TOKEN or token != CALL_TOKEN:
        return jsonify(ok=False, error="unauthorized"), 401
    if not (TWILIO_SID and TWILIO_TOKEN):
        return jsonify(ok=False, error="twilio env vars not set"), 500
    base = BASE_URL or request.host_url.rstrip("/")
    try:
        r = requests.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Calls.json",
            auth=(TWILIO_SID, TWILIO_TOKEN),
            data={"To": TO_NUMBER, "From": FROM_NUMBER, "Url": base + "/voice"},
            timeout=20,
        )
        payload = r.json()
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 502
    return jsonify(ok=r.ok, status=r.status_code, twilio=payload), (200 if r.ok else 502)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
