"""Regression coverage for reliable WebUI upgrade messages and version state."""
from __future__ import annotations

from types import SimpleNamespace

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.policy import Policy
from kali_mcp.releases import installed_release_tag, is_update_available
from kali_mcp.reports import report_html
from kali_mcp.store import Store
from kali_mcp.webui import UI


def test_installed_release_distinct_from_latest(tmp_path):
    version = tmp_path / "VERSION"
    version.write_text("0.1.0-beta.5\n", encoding="utf-8")
    assert installed_release_tag(version) == "v0.1.0-beta.5"
    assert is_update_available("v0.1.0-beta.5", "v0.1.0-beta.6") is True
    assert is_update_available("v0.1.0-beta.6", "v0.1.0-beta.6") is False
    assert is_update_available("v0.1.0", "v0.1.0-beta.6") is False
    assert is_update_available(None, "v0.1.0-beta.6") is None
    version.write_text("not-a-release\n", encoding="utf-8")
    assert installed_release_tag(version) is None


def test_scheduled_update_is_not_reported_as_installed():
    report = report_html({
        "id": "test-id", "tool_id": "core-upgrade",
        "state": "completed", "result": {
            "ok": True, "scheduled": True, "tag": "v0.1.0-beta.6"
        }
    }, [])
    assert "Upgrade scheduled (not yet confirmed installed)" in report
    assert "Installed" in report
    assert "v0.1.0-beta.6" in report


def test_webui_shows_installed_version_and_friendly_disabled_notice(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    monkeypatch.setenv("KALI_MCP_ALLOW_MCP_UPDATES", "true")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "UNIT_TEST_SUPERUSER_PASSWORD_2026")
    cfg = Config.from_env()
    store = Store(tmp_path / "ui.db")
    policy = Policy(cfg, store)

    class FakeUpdates:
        def status(self):
            return {
                "channel": "beta", "latest": "v0.1.0-beta.6",
                "checked": True, "error": "", "install_automatic": False,
            }

        def check(self, force=False):
            return self.status()

    class Jobs:
        def submit(self, **kwargs):
            return {"job_id": "scheduled-123"}

    ui = UI(cfg, store, policy, Jobs(), FakeUpdates())

    class AuthGate:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                req = Request(scope, receive)
                req.state.admin = True
                req.state.admin_username = "test"
                req.state.csrf = "test-csrf"
            await self.app(scope, receive, send)

    app = AuthGate(Starlette(routes=[
        Route("/", ui.dashboard, methods=["GET"]),
        Route("/api/v1/status", ui.status, methods=["GET"]),
        Route("/api/v1/updates/install", ui.update_install, methods=["POST"]),
    ]))

    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "Installed: v0.1.0-beta.5" in page.text
        assert "Latest available: v0.1.0-beta.6" in page.text
        assert "Enable" in page.text and "MCP Updates" in page.text
        assert 'id="install-update" disabled' in page.text

        status = client.get("/api/v1/status")
        assert status.status_code == 200
        assert status.json()["updates"]["installed"] == "v0.1.0-beta.5"
        assert status.json()["updates"]["install_allowed"] is False

        data = {"csrf": "test-csrf", "confirm_update": "yes"}
        blocked = client.post("/api/v1/updates/install", data=data)
        assert blocked.status_code == 403
        assert "Update blocked" in blocked.text
        assert "Enable" in blocked.text
        assert "application/json" not in blocked.headers.get("content-type", "")

        store.set_setting("mcp_updates", True, "test")
        page = client.get("/")
        assert 'id="install-update" disabled' not in page.text
        status = client.get("/api/v1/status")
        assert status.json()["updates"]["install_allowed"] is True
        scheduled = client.post("/api/v1/updates/install", data=data)
        assert scheduled.status_code == 303
        assert scheduled.headers["location"] == "/jobs/scheduled-123"
    store.close()
