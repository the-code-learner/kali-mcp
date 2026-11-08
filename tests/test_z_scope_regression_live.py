"""Regression: never show fake scope defaults or acknowledge scheduled work as applied."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.policy import Policy
from kali_mcp.store import Store
from kali_mcp.webui import UI
from kali_mcp.deployment_settings import FIELD_MAP


def wrap_ui(ui):
    class Session:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                r = Request(scope, receive)
                r.state.admin = True
                r.state.admin_username = "admin"
                r.state.csrf = "expected"
            await self.app(scope, receive, send)

    return Session(Starlette(routes=[
        Route("/api/v1/ui/snapshot", ui.control_center_snapshot, methods=["GET"]),
        Route("/settings/deployment", ui.deployment_settings_save, methods=["POST"]),
    ]))


def test_agent_offline_lists_all_settings_as_unavailable_not_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    monkeypatch.setenv("KALI_MCP_DENIED_CIDRS", "192.168.137.0/24")
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    ui = UI(cfg, store, Policy(cfg, store), None, None)

    def unavailable(*args, **kwargs):
        raise OSError("UNTRUSTED_TOKEN_SHOULD_NOT_LEAK")
    monkeypatch.setattr("kali_mcp.broker_client.call", unavailable)

    with TestClient(wrap_ui(ui), base_url=cfg.base_url) as client:
        response = client.get("/api/v1/ui/snapshot")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "private, no-store"
        snapshot = response.json()
        assert snapshot["agent"]["online"] is False
        assert snapshot["agent"]["inventory_available"] is False
        assert snapshot["deployment"]["state"] == "unavailable"
        assert snapshot["effective_scope"]["allowed"] == ["127.0.0.1/32"]
        assert snapshot["effective_scope"]["denied"] == ["192.168.137.0/24"]
        fields = {item["name"]: item for item in snapshot["fields"]}
        assert set(FIELD_MAP).issubset(fields)
        assert fields["KALI_MCP_DENIED_CIDRS"]["value"] == "Non disponibile"
        assert fields["KALI_MCP_ALLOWED_CIDRS"]["editable"] is False
        assert fields["KALI_MCP_ALLOW_ALL_TARGETS"]["editable"] is False
        assert "KALI_MCP_SUPERUSER_FILE" in fields
        assert "UNTRUSTED_TOKEN_SHOULD_NOT_LEAK" not in response.text
    store.close()


def test_scope_update_json_acknowledges_schedule_not_completion(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    ui = UI(cfg, store, Policy(cfg, store), None, None)
    sent = []

    def fake_agent(_socket, op, payload, **kwargs):
        sent.append((op, payload))
        assert op == "deployment_settings_update"
        return {"ok": True, "scheduled": True}
    monkeypatch.setattr("kali_mcp.broker_client.call", fake_agent)
    body = {
        "csrf": "expected", "section": "scope",
        "KALI_MCP_ALLOW_ALL_TARGETS": "true",
        "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
        "KALI_MCP_DENIED_CIDRS": "192.168.137.0/24",
        "confirm": "ALLOW ALL", "password": "CI_ONLY_SUPERUSER_PASSWORD"
    }
    with TestClient(wrap_ui(ui), base_url=cfg.base_url,
                    follow_redirects=False) as client:
        forbidden = client.post("/settings/deployment",
            data={**body, "csrf": "incorrect"},
            headers={"Accept": "application/json"})
        assert forbidden.status_code == 403
        assert not sent

        scheduled = client.post("/settings/deployment", data=body,
                                headers={"Accept": "application/json"})
        assert scheduled.status_code == 202
        assert scheduled.headers["content-type"].startswith("application/json")
        assert scheduled.json() == {
            "ok": True, "scheduled": True, "unchanged": False,
            "keys": sorted(["KALI_MCP_ALLOWED_CIDRS",
                            "KALI_MCP_DENIED_CIDRS",
                            "KALI_MCP_ALLOW_ALL_TARGETS"])}
        assert sent[-1][1]["changes"]["KALI_MCP_DENIED_CIDRS"] == "192.168.137.0/24"
        assert "CI_ONLY_SUPERUSER_PASSWORD" not in scheduled.text

        # Legacy browser form semantics remain functional.
        html = client.post("/settings/deployment", data=body,
                           headers={"Accept": "text/html"})
        assert html.status_code == 303
        assert html.headers["location"] == "/settings/deployment?apply=scheduled"
    store.close()


def test_live_frontend_preserves_pending_scope_and_does_not_fake_completion():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] /
          "src/kali_mcp/static/control-center.js").read_text()
    assert "state.scopePending" in js
    assert "state.inventoryAvailable" in js
    assert "Non disponibile" in js or "non disponibile" in js
    assert "state.deploymentState==='active'" in js
    assert "expectJSON:true" in js
    assert "state.scopeDirty=false" in js
    assert "Nessun risultato verificabile" in js
    assert "simulatore locale" in js.lower() or "Simulatore locale" in js
