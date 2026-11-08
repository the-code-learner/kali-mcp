"""API token lifecycle and MCP-only browser CORS/credential regressions."""
from __future__ import annotations

import hashlib
import time

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.oauth import OAuth
from kali_mcp.store import Store
from kali_mcp.webui import Admin


def test_api_tokens_hash_expiry_revocation_and_oauth_isolation(tmp_path):
    store = Store(tmp_path / "app.db")
    resource = "https://kali.example.test/mcp"
    fingerprint = "a" * 64
    token_id, secret = store.create_api_token("llama.cpp", resource, fingerprint,
                                              days=30, allowed_tools=["system_status"])
    assert token_id not in secret.split(".")[-1]
    assert secret.startswith("kmp_")
    raw_db = (tmp_path / "app.db").read_bytes()
    assert secret.encode() not in raw_db
    assert store.verify_api_token(secret, resource, fingerprint)["allowed_tools"] == ["system_status"]
    assert store.verify_api_token(secret, resource, "b" * 64) is None
    assert store.verify_api_token(secret, "https://other.example/mcp", fingerprint) is None
    assert store.verify_api_token(secret + "x", resource, fingerprint) is None
    assert store.list_api_tokens()[0]["token_id"] == token_id
    assert "token_hash" not in store.list_api_tokens()[0]
    assert store.revoke_api_token(token_id)
    assert store.verify_api_token(secret, resource, fingerprint) is None
    assert not store.revoke_api_token(token_id)
    second, token2 = store.create_api_token("expiring", resource, fingerprint, days=1)
    with store.transaction():
        store.db.execute("UPDATE api_tokens SET expires=? WHERE token_id=?",
                         (int(time.time()) - 1, second))
    assert store.verify_api_token(token2, resource, fingerprint) is None
    store.close()


def test_mcp_cors_header_and_per_tool_permissions(tmp_path, monkeypatch):
    # runtime imports server.py, which opens its DB at import time.
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))
    from kali_mcp import runtime

    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_BROWSER_ORIGINS", "https://llm.example.test")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "TEST_ADMIN_PASSWORD_ABOVE_SIXTEEN")
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    admin = Admin(cfg, store)
    monkeypatch.setattr(runtime, "cfg", cfg)
    monkeypatch.setattr(runtime, "store", store)
    monkeypatch.setattr(runtime, "oauth", OAuth(cfg, store))
    monkeypatch.setattr(runtime, "admin", admin)

    _, token = store.create_api_token("restricted browser", cfg.resource,
                                      admin._credential()[1], allowed_tools=["system_status"])
    async def endpoint(request):
        return JSONResponse({"actor": runtime.core.ACTOR.get()})

    app = runtime.SecurityGate(Starlette(routes=[Route(
        "/mcp", endpoint, methods=["GET", "POST", "DELETE"])]))
    origin = "https://llm.example.test"
    with TestClient(app, base_url=cfg.base_url) as client:
        preflight = client.options("/mcp", headers={
            "Origin": origin, "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type"})
        assert preflight.status_code == 204
        assert preflight.headers["access-control-allow-origin"] == origin
        assert preflight.headers["vary"] == "Origin"
        assert "Authorization" in preflight.headers["access-control-allow-headers"]
        assert client.options("/mcp", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"}).status_code == 403

        headers = {"Origin": origin, "Authorization": "Bearer " + token}
        allowed = client.post("/mcp", headers=headers,
                              json={"jsonrpc": "2.0", "method": "tools/call",
                                    "params": {"name": "system_status"}, "id": 1})
        assert allowed.status_code == 200
        assert allowed.json()["actor"].startswith("mcp:api:")
        assert allowed.headers["access-control-allow-origin"] == origin

        denied = client.post("/mcp", headers=headers,
                             json={"jsonrpc": "2.0", "method": "tools/call",
                                   "params": {"name": "terminal_open"}, "id": 2})
        assert denied.status_code == 403
        assert denied.json()["error"] == "tool_not_allowed"
        assert client.get("/mcp", headers={"Origin": "https://evil.example",
                              "Authorization": "Bearer " + token}).status_code == 403
        no_auth = client.get("/mcp", headers={"Origin": origin})
        assert no_auth.status_code == 401
        assert "Bearer" in no_auth.headers["www-authenticate"]
        assert no_auth.headers["access-control-allow-origin"] == origin

        custom = client.get("/mcp", headers={"X-Kali-MCP-API-Key": token})
        assert custom.status_code == 200
        assert client.get("/mcp", headers={
            "Authorization": "Bearer " + token,
            "X-Kali-MCP-API-Key": token}).status_code == 400
        assert client.get("/mcp", headers=[
            ("Authorization", "Bearer " + token),
            ("Authorization", "Bearer " + token)]).status_code == 400
        assert "access-control-allow-origin" not in client.get(
            "/mcp", headers={"Origin": "https://evil.example"}).headers
    store.close()


def test_browser_origins_must_be_exact_and_secure(monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    for value in ("*", "null", "http://evil.example",
                  "https://evil.example/path", "https://evil.example,https://evil.example"):
        monkeypatch.setenv("KALI_MCP_BROWSER_ORIGINS", value)
        try:
            Config.from_env()
        except ValueError:
            pass
        else:
            raise AssertionError("Accepted insecure browser origin: " + value)



def test_webui_token_creation_one_time_and_csrf(tmp_path, monkeypatch):
    import re

    from starlette.requests import Request
    from kali_mcp.webui import UI

    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "TEST_ADMIN_PASSWORD_ABOVE_SIXTEEN")
    cfg = Config.from_env()
    store = Store(tmp_path / "webui.db")
    admin = Admin(cfg, store)
    ui = UI(cfg, store, None, None, None)

    class AuthGate:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                admin.authenticate_request(Request(scope, receive))
            await self.app(scope, receive, send)

    app = AuthGate(Starlette(routes=[
        Route("/login", admin.login_post, methods=["POST"]),
        Route("/", ui.dashboard, methods=["GET"]),
        Route("/api/v1/api-tokens/create", ui.create_api_token, methods=["POST"]),
        Route("/api/v1/api-tokens/revoke", ui.revoke_api_token, methods=["POST"]),
    ]))
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        login = client.post("/login", data={
            "username": "admin", "password": "TEST_ADMIN_PASSWORD_ABOVE_SIXTEEN"})
        assert login.status_code == 303
        page = client.get("/")
        assert page.status_code == 200
        assert "MCP Clients" in page.text
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        data = {"name": "llama.cpp", "days": "30", "allowed_tools": "system_status",
                "csrf": csrf, "password": "TEST_ADMIN_PASSWORD_ABOVE_SIXTEEN"}
        assert client.post("/api/v1/api-tokens/create", data={
            **data, "csrf": "wrong"}).status_code == 403
        assert client.post("/api/v1/api-tokens/create", data={
            **data, "password": "wrong"}).status_code == 403
        created = client.post("/api/v1/api-tokens/create", data=data)
        assert created.status_code == 200
        secret = re.search(r"kmp_[0-9a-f]{32}\.[A-Za-z0-9_-]{64}", created.text)
        assert secret
        token = secret.group()
        assert "no-store" in created.headers["cache-control"]
        dashboard = client.get("/")
        assert token not in dashboard.text
        entry = store.list_api_tokens()[0]
        assert entry["name"] == "llama.cpp"
        assert client.post("/api/v1/api-tokens/revoke", data={
            "csrf": csrf, "password": data["password"],
            "token_id": entry["token_id"]}).status_code == 303
        assert store.verify_api_token(token, cfg.resource, admin._credential()[1]) is None
    store.close()
