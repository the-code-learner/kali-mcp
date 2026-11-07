"""Security regression checks for the named WebUI/CLI superuser."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.store import Store
from kali_mcp.superuser import make_record, read_record, save_record, verify
from kali_mcp.webui import Admin


PASSWORD = "Long_unique_superuser_password_for_tests_2026!"


def test_hashed_superuser_never_persists_plaintext(tmp_path):
    filename = tmp_path / "superuser.json"
    save_record(filename, make_record("operator", PASSWORD))
    raw = filename.read_text()
    assert PASSWORD not in raw
    assert filename.stat().st_mode & 0o777 == 0o600
    assert "operator" in raw
    credential = read_record(filename)
    assert verify(credential, "operator", PASSWORD)
    assert not verify(credential, "operator", "invalid-password")
    assert not verify(credential, "someoneelse", PASSWORD)
    assert not verify(credential, "operator", PASSWORD + "!")


def test_webui_named_login_and_password_rotation_revoke_session(tmp_path, monkeypatch):
    credentials = tmp_path / "superuser.json"
    save_record(credentials, make_record("operator", PASSWORD))
    monkeypatch.setenv("KALI_MCP_SUPERUSER_FILE", str(credentials))
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "")
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    auth = Admin(cfg, store)

    async def dashboard(request):
        if not request.state.admin:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse({"superuser": request.state.admin_username})

    class AuthMiddleware:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                auth.authenticate_request(Request(scope, receive))
            await self.app(scope, receive, send)

    app = AuthMiddleware(Starlette(routes=[
        Route("/login", auth.login_get, methods=["GET"]),
        Route("/login", auth.login_post, methods=["POST"]),
        Route("/dashboard", dashboard, methods=["GET"]),
        Route("/logout", auth.logout, methods=["POST"]),
    ]))
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        assert client.get("/dashboard").status_code == 401
        page = client.get("/login")
        assert "Username" in page.text and "Password" in page.text
        login = client.post("/login", data={"username": "operator", "password": PASSWORD,
                                             "next": "/dashboard"})
        assert login.status_code == 303
        assert client.get("/dashboard").json()["superuser"] == "operator"
        cookies = login.headers["set-cookie"]
        assert "Secure" in cookies and "HttpOnly" in cookies
        assert "SameSite=lax" in cookies
        # A credential rotation must invalidate all earlier browser sessions.
        save_record(credentials, make_record("operator", PASSWORD + "_rotated"))
        assert client.get("/dashboard").status_code == 401
    store.close()


def test_public_http_limits_and_response_headers(tmp_path, monkeypatch):
    # Exercise the ingress middleware using an isolated local Starlette app.
    from kali_mcp import runtime
    monkeypatch.setattr(runtime, "cfg", Config.from_env())
    async def endpoint(request):
        return JSONResponse({"ok": True})
    app = runtime.SecurityGate(Starlette(routes=[
        Route("/login", endpoint, methods=["POST"]),
        Route("/register", endpoint, methods=["POST"]),
    ]))
    with TestClient(app, base_url=runtime.cfg.base_url) as client:
        assert client.post("/login", content=b"x" * 18000).status_code == 413
        bad_host = client.post("/login", data={"x":"y"}, headers={"Host":"evil.example"})
        assert bad_host.status_code == 400
        response = client.post("/login", data={"x":"y"})
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
