"""End-to-end OAuth browser login, consent and PKCE exchange."""
from __future__ import annotations

import base64
import hashlib
import re
from urllib.parse import parse_qs, urlencode, urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.oauth import OAuth
from kali_mcp.store import Store
from kali_mcp.webui import Admin


def test_browser_authorization_and_pkce(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "TEST_ADMIN_PASSWORD_ABOVE_SIXTEEN")
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    auth = OAuth(cfg, store)
    admin = Admin(cfg, store)

    class LoginMiddleware:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                admin.authenticate_request(Request(scope, receive))
            await self.app(scope, receive, send)

    app = LoginMiddleware(Starlette(routes=[
        Route("/register", auth.register, methods=["POST"]),
        Route("/authorize", auth.authorize_get, methods=["GET"]),
        Route("/authorize", auth.authorize_post, methods=["POST"]),
        Route("/token", auth.token, methods=["POST"]),
        Route("/login", admin.login_get, methods=["GET"]),
        Route("/login", admin.login_post, methods=["POST"]),
    ]))

    verifier = "g" * 55
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    callback = "https://chatgpt.com/oauth/callback"
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        registration = client.post("/register", json={"client_name": "MCP E2E",
            "redirect_uris": [callback]})
        assert registration.status_code == 201
        client_id = registration.json()["client_id"]
        values = {
            "client_id": client_id, "redirect_uri": callback,
            "response_type": "code", "code_challenge": challenge,
            "code_challenge_method": "S256", "state": "random-state-123",
            "scope": "mcp:tools", "resource": cfg.resource,
        }
        entry = client.get("/authorize?" + urlencode(values))
        assert entry.status_code == 303
        assert entry.headers["location"].startswith("/login?")
        # An admin login is required even after successful Cloudflare OAuth discovery.
        login = client.post("/login", data={"password": "TEST_ADMIN_PASSWORD_ABOVE_SIXTEEN",
            "next": "/authorize?" + urlencode(values)})
        assert login.status_code == 303
        consent = client.get(login.headers["location"])
        assert consent.status_code == 200
        assert "Authorize MCP client" in consent.text
        csrf = re.search(r'name="csrf" value="([^"]+)"', consent.text)
        assert csrf
        granted = client.post("/authorize", data={**values, "csrf": csrf.group(1)})
        assert granted.status_code == 303
        redirect = urlsplit(granted.headers["location"])
        assert redirect.scheme == "https" and redirect.netloc == "chatgpt.com"
        returned = parse_qs(redirect.query)
        assert returned["state"] == ["random-state-123"]
        token_response = client.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": callback, "code": returned["code"][0],
            "code_verifier": verifier, "resource": cfg.resource,
        })
        assert token_response.status_code == 200, token_response.text
        assert auth.verify_bearer(token_response.json()["access_token"]) == client_id
    store.close()
