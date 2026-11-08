"""Regression: expired administrator sessions never apply a WebUI permission POST."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.policy import Policy
from kali_mcp.store import Store
from kali_mcp.superuser import make_record, save_record
from kali_mcp.webui import Admin, UI, _csrf_for


USER = "operator"
PASSWORD = "LONG_UNIT_TEST_SUPERUSER_PASSWORD_2026"


def test_expired_browser_form_redirects_to_login_without_applying_permissions(
        tmp_path, monkeypatch):
    credentials = tmp_path / "superuser.json"
    save_record(credentials, make_record(USER, PASSWORD))
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_SUPERUSER_FILE", str(credentials))
    monkeypatch.setenv("KALI_MCP_ALLOW_MCP_UPDATES", "true")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "false")
    cfg = Config.from_env()
    store = Store(tmp_path / "webui.db")
    auth = Admin(cfg, store)

    class FakeUpdates:
        def status(self):
            return {"channel": "beta", "latest": None, "checked": False,
                    "error": ""}

    ui = UI(cfg, store, Policy(cfg, store), None, FakeUpdates())

    class WithAdmin:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                auth.authenticate_request(Request(scope, receive))
            await self.app(scope, receive, send)

    app = WithAdmin(Starlette(routes=[
        Route("/", ui.dashboard, methods=["GET"]),
        Route("/login", auth.login_get, methods=["GET"]),
        Route("/login", auth.login_post, methods=["POST"]),
        Route("/api/v1/settings", ui.settings, methods=["POST"]),
        Route("/api/v1/status", ui.status, methods=["GET"]),
    ]))
    with TestClient(app, base_url=cfg.base_url,
                    follow_redirects=False) as client:
        signed_in = client.post("/login", data={
            "username": USER, "password": PASSWORD, "next": "/",
        }, headers={"Accept": "text/html"})
        assert signed_in.status_code == 303
        assert client.cookies.get("kali_admin")
        assert client.get("/").status_code == 200

        cookie = client.cookies.get("kali_admin")
        csrf = _csrf_for(cookie, auth._credential()[1])
        data = {"feature": "mcp_updates", "enabled": "true", "csrf": csrf}
        assert store.get_setting("mcp_updates") is False

        # Simulate an expired or server-revoked session while the old dashboard
        # and its capability form are still open in the browser.
        store.db.execute("UPDATE admin_sessions SET expires=0")
        blocked = client.post("/api/v1/settings", data=data,
                              headers={"Accept": "text/html"})
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/login?reason=session-expired&next=/"
        assert "kali_admin" in blocked.headers.get("set-cookie", "")
        assert "Max-Age=0" in blocked.headers["set-cookie"]
        assert store.get_setting("mcp_updates") is False
        warning = client.get(blocked.headers["location"])
        assert warning.status_code == 200
        assert "administrator session has expired" in warning.text
        assert "repeat your change" in warning.text

        # API fetch clients still get a machine-readable 401.
        api = client.post("/api/v1/settings", data=data,
                          headers={"Accept": "application/json"})
        assert api.status_code == 401
        assert api.json() == {"error": "Administrator login required"}
        assert store.get_setting("mcp_updates") is False

        signed_in_again = client.post("/login", data={
            "username": USER, "password": PASSWORD, "next": "/",
        }, headers={"Accept": "text/html"})
        assert signed_in_again.status_code == 303
        fresh_cookie = client.cookies.get("kali_admin")
        fresh_csrf = _csrf_for(fresh_cookie, auth._credential()[1])

        # A valid cookie is never enough if the dashboard has a stale CSRF.
        wrong_csrf = client.post("/api/v1/settings",
            data={**data, "csrf": csrf}, headers={"Accept": "text/html"})
        assert wrong_csrf.status_code == 403
        assert "Change not applied" in wrong_csrf.text
        assert store.get_setting("mcp_updates") is False

        ok = client.post("/api/v1/settings",
            data={**data, "csrf": fresh_csrf}, headers={"Accept": "text/html"})
        assert ok.status_code == 303
        assert ok.headers["location"] == "/"
        assert store.get_setting("mcp_updates") is True

        # Superuser credential rotation also invalidates sessions. The old
        # session must never disable an existing setting or apply anything.
        save_record(credentials, make_record(USER, PASSWORD + "_changed"))
        revoked = client.post("/api/v1/settings", data={
            "feature": "mcp_updates", "enabled": "false", "csrf": fresh_csrf,
        }, headers={"Accept": "text/html"})
        assert revoked.status_code == 303
        assert revoked.headers["location"].startswith("/login?")
        assert store.get_setting("mcp_updates") is True
    store.close()
