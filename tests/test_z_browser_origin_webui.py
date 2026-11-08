"""WebUI browser origin management keeps CSRF and password boundaries."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.store import Store
from kali_mcp.policy import Policy
from kali_mcp.webui import UI


def test_browser_origins_management_and_token_onboarding(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_BROWSER_ORIGINS", "https://existing.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "TEST_ONLY_LONG_SUPERUSER_PASSWORD_2026")
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    ui = UI(cfg, store, Policy(cfg, store), None, None)

    calls = []
    def broker(_socket, operation, payload=None, **kwargs):
        calls.append((operation, payload))
        if operation == "browser_origins_status":
            return {"ok": True,
                    "configured": ["https://existing.example.test"],
                    "deployment": {"state": "active"}}
        if operation == "browser_origins_update":
            return {"ok": True, "scheduled": True,
                    "configured": ["https://existing.example.test",
                                   "https://llm.example.test"]}
        return {"ok": True, "broker": "test"}
    monkeypatch.setattr("kali_mcp.broker_client.call", broker)

    class Auth:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                request = Request(scope, receive)
                request.state.admin = True
                request.state.admin_username = "admin"
                request.state.csrf = "expected-csrf"
            await self.app(scope, receive, send)

    app = Auth(Starlette(routes=[
        Route("/", ui.dashboard, methods=["GET"]),
        Route("/api/v1/browser-origins", ui.browser_origins_update, methods=["POST"]),
        Route("/api/v1/browser-origins/check", ui.browser_origins_check, methods=["POST"]),
        Route("/api/v1/api-tokens/create", ui.create_api_token, methods=["POST"]),
    ]))
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "MCP Browser Origins / CORS" in dashboard.text
        assert "Active in Core:" in dashboard.text
        assert "https://existing.example.test" in dashboard.text
        assert 'class="api-token-form"' in dashboard.text
        assert 'class="table-scroll"' in dashboard.text

        valid = {"csrf": "expected-csrf", "action": "add",
                 "origin": "https://llm.example.test",
                 "password": "TEST_ONLY_LONG_SUPERUSER_PASSWORD_2026"}
        start = len(calls)
        assert client.post("/api/v1/browser-origins",
                           data={**valid, "csrf": "invalid"}).status_code == 403
        assert len(calls) == start
        assert client.post("/api/v1/browser-origins",
                           data={**valid, "origin": "https://*.example.test"}).status_code == 403
        assert len(calls) == start

        approved = client.post("/api/v1/browser-origins", data=valid)
        assert approved.status_code == 303
        assert approved.headers["location"] == "/?cors=scheduled"
        assert calls[-1][0] == "browser_origins_update"
        assert calls[-1][1]["superuser_name"] == "admin"
        assert calls[-1][1]["origin"] == "https://llm.example.test"

        # A browser origin is NOT an authentication token. Creating a token
        # before the origin is active should guide the operator to CORS settings.
        denied = client.post("/api/v1/api-tokens/create", data={
            "csrf": "expected-csrf", "name": "Browser",
            "browser_origin": "https://llm.example.test",
            "days": "30", "password": "TEST_ONLY_LONG_SUPERUSER_PASSWORD_2026",
        })
        assert denied.status_code == 409
        assert "Browser origin not authorized" in denied.text
        assert not store.list_api_tokens()

        # Browser diagnostic must never display the supplied secret.
        monkeypatch.setattr(ui, "_browser_probe",
                            lambda origin, host, bearer: {
                                "cors": "allowed", "host": "passed",
                                "mcp": "initialize succeeded"})
        response = client.post("/api/v1/browser-origins/check", data={
            "csrf": "expected-csrf", "origin": "https://existing.example.test",
            "bearer": "kmp_TEST_SECRET_NOT_TO_BE_ECHOED",
        })
        assert response.status_code == 200
        assert "initialize succeeded" in response.text
        assert "kmp_TEST_SECRET_NOT_TO_BE_ECHOED" not in response.text
    store.close()
