"""Secure WebUI deployment form: visible inventory and protected scope edits."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.store import Store
from kali_mcp.policy import Policy
from kali_mcp.webui import UI
from kali_mcp.deployment_settings import public_inventory


def test_inventory_form_and_no_unauthorized_deployment_changes(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    cfg = Config.from_env()
    store = Store(tmp_path / "core.db")
    ui = UI(cfg, store, Policy(cfg, store), None, None)
    calls = []

    def fake_agent(_sock, operation, payload=None, **kwargs):
        calls.append((operation, payload))
        if operation == "deployment_settings_get":
            return {"ok": True, "fields": public_inventory({
                "KALI_MCP_PUBLIC_URL": "https://kali.example.test",
                "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
                "KALI_MCP_DENIED_CIDRS": "",
                "KALI_MCP_ALLOW_ALL_TARGETS": "false",
                "KALI_MCP_ADMIN_PASSWORD": "NEVER_RENDER_SECRET_123",
            }, {}), "deployment": {"state": "active"}}
        if operation == "deployment_settings_update":
            return {"ok": True, "scheduled": True, "keys": list(payload["changes"])}
        return {"ok": True}
    monkeypatch.setattr("kali_mcp.broker_client.call", fake_agent)

    class Auth:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                request = Request(scope, receive)
                request.state.admin = True
                request.state.admin_username = "admin"
                request.state.csrf = "known-csrf"
            await self.app(scope, receive, send)

    app = Auth(Starlette(routes=[
        Route("/settings/deployment", ui.deployment_settings, methods=["GET"]),
        Route("/settings/deployment", ui.deployment_settings_save, methods=["POST"]),
    ]))
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        page = client.get("/settings/deployment")
        assert page.status_code == 200
        assert "Authorized Scope" in page.text
        assert "Allow all except blacklist" in page.text
        assert "KALI_MCP_DENIED_CIDRS" in page.text
        assert "KALI_MCP_ALLOWED_CIDRS" in page.text
        assert "KALI_MCP_ALLOW_HOST_ROOT" in page.text
        assert "KALI_MCP_SUPERUSER_FILE" in page.text
        assert "NEVER_RENDER_SECRET_123" not in page.text
        assert "(hidden)" in page.text

        submitted = {"section": "scope", "csrf": "known-csrf",
                     "KALI_MCP_ALLOW_ALL_TARGETS": "true",
                     "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
                     "KALI_MCP_DENIED_CIDRS": "192.168.137.0/24",
                     "confirm": "ALLOW ALL",
                     "password": "EXAMPLE_REAL_PASSWORD_NEVER_ECHO"}
        count = len(calls)
        assert client.post("/settings/deployment", data={
            **submitted, "csrf": "wrong"},
            headers={"Accept": "text/html"}).status_code == 403
        assert len(calls) == count

        assert client.post("/settings/deployment", data={
            **submitted, "password": ""},
            headers={"Accept": "text/html"}).status_code == 403
        assert len(calls) == count

        approved = client.post("/settings/deployment", data=submitted,
                               headers={"Accept": "text/html"})
        assert approved.status_code == 303
        assert approved.headers["location"] == "/settings/deployment?apply=scheduled"
        assert calls[-1][0] == "deployment_settings_update"
        assert calls[-1][1]["changes"]["KALI_MCP_DENIED_CIDRS"] == "192.168.137.0/24"
        assert calls[-1][1]["superuser_name"] == "admin"
        assert calls[-1][1]["confirm"] == "ALLOW ALL"
        assert "EXAMPLE_REAL_PASSWORD_NEVER_ECHO" not in page.text

        one = client.post("/settings/deployment", data={
            "section": "variable", "csrf": "known-csrf",
            "key": "KALI_MCP_UPDATE_CHECK_SECONDS", "value": "3600",
            "password": "EXAMPLE_REAL_PASSWORD_NEVER_ECHO"},
            headers={"Accept": "text/html"})
        assert one.status_code == 303
        assert calls[-1][1]["changes"] == {"KALI_MCP_UPDATE_CHECK_SECONDS": "3600"}
    store.close()
