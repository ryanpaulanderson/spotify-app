"""Minimal Flask app to obtain a Spotify authorization code using PKCE."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from urllib.parse import quote, urlparse

from flask import Flask, Response, jsonify, redirect, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", secrets.token_hex(16))

DEFAULT_REDIRECT_URI = "https://localhost:8888/callback"
CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID")
REDIRECT_URI = os.environ.get("SPOTIFY_REDIRECT_URI", DEFAULT_REDIRECT_URI)
SCOPES = os.environ.get("SPOTIFY_SCOPES", "user-read-email")

parsed_redirect = urlparse(REDIRECT_URI)
DEFAULT_PORT = parsed_redirect.port or (443 if parsed_redirect.scheme == "https" else 80)
SERVER_PORT = int(os.environ.get("PORT", DEFAULT_PORT))
USE_ADHOC_HTTPS = parsed_redirect.scheme == "https"


def _generate_verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()


def _generate_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@app.route("/")
def index() -> Response:
    if not CLIENT_ID:
        missing = "SPOTIFY_CLIENT_ID"
    else:
        missing = None

    content = f"""
    <html>
        <head><title>Spotify PKCE Helper</title></head>
        <body>
            <h1>Spotify Authorization Code with PKCE</h1>
            <p>This helper app starts the PKCE OAuth flow for Spotify.</p>
            <ul>
                <li><strong>Client ID set:</strong> {bool(CLIENT_ID)}</li>
                <li><strong>Redirect URI:</strong> {REDIRECT_URI}</li>
                <li><strong>Scopes:</strong> {SCOPES}</li>
                <li><strong>Server port:</strong> {SERVER_PORT}</li>
                <li><strong>HTTPS (adhoc certificate):</strong> {USE_ADHOC_HTTPS}</li>
            </ul>
            <p><a href="{url_for('start_auth')}">Begin Authorization</a></p>
            {f'<p style="color:red;">Missing env var: {missing}</p>' if missing else ''}
        </body>
    </html>
    """
    return Response(content, mimetype="text/html")


@app.route("/login")
def start_auth():
    if not CLIENT_ID:
        return jsonify({"error": "SPOTIFY_CLIENT_ID is not configured."}), 400

    state = secrets.token_urlsafe(16)
    verifier = _generate_verifier()
    challenge = _generate_challenge(verifier)

    session["state"] = state
    session["verifier"] = verifier

    auth_url = (
        "https://accounts.spotify.com/authorize"
        f"?response_type=code&client_id={quote(CLIENT_ID)}"
        f"&scope={quote(SCOPES)}"
        f"&redirect_uri={quote(REDIRECT_URI)}"
        f"&state={quote(state)}"
        "&code_challenge_method=S256"
        f"&code_challenge={quote(challenge)}"
    )

    return redirect(auth_url)


@app.route("/callback")
def handle_callback():
    returned_state = request.args.get("state")
    if not returned_state or returned_state != session.get("state"):
        return jsonify({"error": "Invalid or missing state parameter."}), 400

    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Authorization code not found in callback."}), 400

    verifier = session.get("verifier")
    session.pop("state", None)
    session.pop("verifier", None)

    payload = {
        "authorization_code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    }
    return jsonify(payload)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=SERVER_PORT, ssl_context="adhoc" if USE_ADHOC_HTTPS else None)
