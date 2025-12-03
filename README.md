# Spotify Authorization Code with PKCE Helper

This package provides a minimal Flask web app that kicks off Spotify's Authorization Code with PKCE flow so you can capture the authorization code and matching code verifier. It is intended for local testing and tooling and does not exchange the code for tokens.

## Setup

1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set the required environment variables:
   ```bash
   export SPOTIFY_CLIENT_ID="your_client_id"
   export SPOTIFY_REDIRECT_URI="https://localhost:8888/callback"  # must match the Spotify app setting
   export SPOTIFY_SCOPES="user-read-email"  # customize scopes as needed
   # Optional: export APP_SECRET_KEY to control the Flask session key
   # Optional: export PORT to override the server port (defaults to the port in SPOTIFY_REDIRECT_URI)
   ```

When `SPOTIFY_REDIRECT_URI` uses `https://`, the helper starts with an ad-hoc self-signed certificate suitable for local testing.
Your browser will likely prompt you to trust the certificate the first time you open the site.

## Running the app

Launch the helper server (uses an ad-hoc HTTPS certificate when the redirect URI starts with `https://`):
```bash
python -m spotify_pkce_app.app
```

The app listens on the same port defined in `SPOTIFY_REDIRECT_URI` when possible (default `8888`). Navigate to `https://localhost:8888` (or the host/port in your redirect URI) and click **Begin Authorization** to start the Spotify login flow. After granting access, Spotify redirects to `/callback` and the app responds with a JSON payload that includes:

- `authorization_code` – the code returned by Spotify.
- `code_verifier` – the matching PKCE verifier to exchange for tokens.
- `redirect_uri` – the redirect URI you configured.

Use these values to perform the token exchange against Spotify's token endpoint in your own tooling.

## Notes

- The app stores the PKCE verifier and state in the Flask session to protect against cross-site request forgery.
- Ensure the redirect URI matches what is registered in your Spotify Developer Dashboard.
- Adjust the `SPOTIFY_SCOPES` environment variable to request additional permissions as needed.
