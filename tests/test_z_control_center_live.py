"""Live Control Center contract, asset CSP and no fake/demo admin actions."""
from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.deployment_settings import public_inventory
from kali_mcp.policy import Policy
from kali_mcp.store import Store
from kali_mcp.webui import UI


def test_control_center_is_authenticated_and_loads_real_status(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    monkeypatch.setenv("KALI_MCP_BROWSER_ORIGINS", "https://llm.example.test")
    cfg = Config.from_env()
    store = Store(tmp_path / "core.db")
    ui = UI(cfg, store, Policy(cfg, store), None, None)
    authenticated = [True]
    calls = []
    def fake_agent(_socket, op, payload=None, **kwargs):
        calls.append((op, payload))
        if op == "ping":
            return {"ok": True, "broker": "systemd-host-agent"}
        if op == "deployment_settings_get":
            return {"ok": True, "fields": public_inventory({
                "KALI_MCP_PUBLIC_URL": "https://kali.example.test",
                "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
                "KALI_MCP_DENIED_CIDRS": "192.168.137.0/24",
                "KALI_MCP_ALLOW_ALL_TARGETS": "false",
                "KALI_MCP_ADMIN_PASSWORD": "NEVER_RETURN_THIS_CREDENTIAL",
            }, {}), "deployment": {"state": "active"}}
        if op == "browser_origins_status":
            return {"ok": True, "configured": ["https://llm.example.test"],
                    "deployment": {"state": "active"}}
        if op == "update_status_get":
            return {"ok": True, "update": {
                "state": "running", "phase": "healthcheck",
                "tag": "v0.1.0-beta.12", "detail": "Service health checks",
                "updated_at": "2026-11-08T20:10:00+00:00"}}
        return {"ok": False, "error": "Invalid operation"}
    monkeypatch.setattr("kali_mcp.broker_client.call", fake_agent)

    class Authentication:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                request = Request(scope, receive)
                request.state.admin = authenticated[0]
                request.state.admin_username = "admin" if authenticated[0] else ""
                request.state.csrf = "valid-csrf"
            await self.app(scope, receive, send)

    app = Authentication(Starlette(routes=[
        Route("/", ui.control_center, methods=["GET"]),
        Route("/api/v1/ui/snapshot", ui.control_center_snapshot, methods=["GET"]),
        Route("/api/v1/ui/settings", ui.deployment_settings_save, methods=["POST"]),
    ]))
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        doc = client.get("/")
        assert doc.status_code == 200
        assert 'name="kali-csrf" content="valid-csrf"' in doc.text
        assert "Kali MCP" in doc.text and "control-center.js" in doc.text
        assert "<script>" not in doc.text
        assert "unsafe-inline" not in doc.headers["content-security-policy"]
        assert "no-store" in doc.headers["cache-control"]
        assert "data-action=\"logout\"" in doc.text

        snapshot = client.get("/api/v1/ui/snapshot")
        assert snapshot.status_code == 200
        data = snapshot.json()
        assert data["ok"]
        assert data["agent"]["online"] is True
        assert data["updates"]["run"]["state"] == "running"
        assert data["updates"]["run"]["phase"] == "healthcheck"
        assert data["origins"]["configured"] == ["https://llm.example.test"]
        assert "runtime" in data and "jobs" in data and "audit" in data
        field_map = {row["name"]: row for row in data["fields"]}
        assert field_map["KALI_MCP_ALLOW_ALL_TARGETS"]["editable"] is True
        assert field_map["KALI_MCP_ADMIN_PASSWORD"]["value"] == "(hidden)"
        assert "NEVER_RETURN_THIS_CREDENTIAL" not in snapshot.text

        # The same page and snapshot are inaccessible without a valid
        # administrator session; the SPA cannot disclose privileged state.
        authenticated[0] = False
        assert client.get("/").status_code == 303
        denied = client.get("/api/v1/ui/snapshot")
        assert denied.status_code == 401
        assert denied.json()["error"] == "Administrator login required"
    store.close()


def test_batch_settings_honors_csrf_and_never_handles_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    cfg = Config.from_env()
    store = Store(tmp_path / "core.db")
    ui = UI(cfg, store, Policy(cfg, store), None, None)
    requests = []
    def fake_agent(_socket, op, payload=None, **kwargs):
        requests.append((op, payload))
        return {"ok": True, "scheduled": True}
    monkeypatch.setattr("kali_mcp.broker_client.call", fake_agent)

    class Auth:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                r = Request(scope, receive)
                r.state.admin = True
                r.state.admin_username = "admin"
                r.state.csrf = "expected"
            await self.app(scope, receive, send)
    app = Auth(Starlette(routes=[
        Route("/settings/deployment", ui.deployment_settings_save, methods=["POST"])
    ]))
    import json
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        valid = {"csrf": "expected", "section": "batch",
                 "changes": json.dumps({
                     "KALI_MCP_UPDATE_CHECK_SECONDS": "3600",
                     "KALI_MCP_RELEASE_CHANNEL": "beta",
                 }), "password": "superuser-confirmation"}
        invalid = client.post("/settings/deployment", data={**valid, "csrf": "bad"},
                              headers={"Accept": "text/html"})
        assert invalid.status_code == 403
        assert requests == []

        hidden = client.post("/settings/deployment",
            data={**valid, "changes": json.dumps({"KALI_MCP_SUPERUSER_FILE": "/tmp/key"})},
            headers={"Accept": "text/html"})
        # Schema validation occurs independently inside the Host Agent.
        assert hidden.status_code == 303
        assert requests[-1][0] == "deployment_settings_update"
        assert requests[-1][1]["changes"] == {"KALI_MCP_SUPERUSER_FILE": "/tmp/key"}
        requests.clear()

        denied = client.post("/settings/deployment",
            data={**valid, "changes": json.dumps({"KALI_MCP_ALLOW_ALL_TARGETS": "true"})},
            headers={"Accept": "text/html"})
        assert denied.status_code == 400 and not requests
        approved = client.post("/settings/deployment", data=valid,
                               headers={"Accept": "text/html"})
        assert approved.status_code == 303
        assert requests[-1][1]["changes"]["KALI_MCP_UPDATE_CHECK_SECONDS"] == "3600"
    store.close()


def test_control_center_js_no_inline_demo_timers():
    root = Path(__file__).resolve().parents[1] / "src/kali_mcp/static"
    document = (root / "control-center.html").read_text()
    script = (root / "control-center.js").read_text()
    assert "control-center.css" in document
    assert 'control-center.js' in document
    assert "setInterval(tick,1400)" not in script
    assert "/api/v1/ui/snapshot" in script
    assert "/api/v1/updates/install" in script
    assert "LIVE_PHASES" in script
    assert "startLive();" in script
