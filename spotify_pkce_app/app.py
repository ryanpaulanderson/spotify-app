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
CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET")
DEFAULT_SCOPES = " ".join(
    [
        "user-read-email",
        "user-read-private",
        "streaming",
        "user-read-playback-state",
        "user-modify-playback-state",
        "user-read-currently-playing",
        "playlist-read-private",
        "playlist-read-collaborative",
        "playlist-modify-private",
        "playlist-modify-public",
        "user-library-read",
        "user-library-modify",
        "user-follow-read",
        "user-follow-modify",
        "user-top-read",
        "user-read-recently-played",
        "app-remote-control",
    ]
)
REDIRECT_URI = os.environ.get("SPOTIFY_REDIRECT_URI", DEFAULT_REDIRECT_URI)
SCOPES = os.environ.get("SPOTIFY_SCOPES", DEFAULT_SCOPES)

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
            <form method="post" action="{url_for('start_auth')}">
                <div>
                    <label for="client_id">Client ID</label><br />
                    <input name="client_id" id="client_id" type="text" value="{CLIENT_ID or ''}" required />
                </div>
                <div>
                    <label for="client_secret">Client Secret (optional)</label><br />
                    <input name="client_secret" id="client_secret" type="text" value="{CLIENT_SECRET or ''}" />
                </div>
                <div>
                    <label for="scopes">Scopes (space separated)</label><br />
                    <textarea name="scopes" id="scopes" rows="4" cols="80">{SCOPES}</textarea>
                </div>
                <div>
                    <button type="submit">Begin Authorization</button>
                </div>
            </form>
            {f'<p style="color:red;">Missing env var: {missing}</p>' if missing else ''}
        </body>
    </html>
    """
    return Response(content, mimetype="text/html")


@app.route("/login", methods=["GET", "POST"])
def start_auth():
    client_id = (request.form.get("client_id") or CLIENT_ID or "").strip()
    client_secret = (request.form.get("client_secret") or CLIENT_SECRET or "").strip()
    scopes = (request.form.get("scopes") or SCOPES or "").strip()

    if not client_id:
        return jsonify({"error": "SPOTIFY_CLIENT_ID is not configured."}), 400

    state = secrets.token_urlsafe(16)
    verifier = _generate_verifier()
    challenge = _generate_challenge(verifier)

    session["state"] = state
    session["verifier"] = verifier
    session["client_id"] = client_id
    session["client_secret"] = client_secret
    session["scopes"] = scopes

    auth_url = (
        "https://accounts.spotify.com/authorize"
        f"?response_type=code&client_id={quote(client_id)}"
        f"&scope={quote(scopes)}"
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
    payload = {
        "authorization_code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
        "client_id": session.get("client_id"),
        "client_secret": session.get("client_secret"),
        "scopes": session.get("scopes", SCOPES),
    }
    session.pop("state", None)
    session.pop("verifier", None)
    session.pop("client_id", None)
    session.pop("client_secret", None)
    session.pop("scopes", None)
    return jsonify(payload)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=SERVER_PORT, ssl_context="adhoc" if USE_ADHOC_HTTPS else None)
