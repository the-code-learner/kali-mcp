"""WebUI same-origin HTML forms must work in Chrome without weakening CSRF."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.policy import Policy
from kali_mcp.store import Store
from kali_mcp.webui import UI


def test_origin_null_requires_referer_fetch_metadata_and_csrf(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_HOST_AGENT", "true")
    monkeypatch.setenv("KALI_MCP_ALLOW_MCP_UPDATES", "true")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "LONG_UNIT_TEST_PASSWORD_2026")
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))

    # Importing runtime initializes its own MCP singleton, so do this only
    # after isolating its datastore; never depend on the import-time origin.
    from kali_mcp import runtime
    cfg = Config.from_env()
    store = Store(tmp_path / "form.db")

    class TestAdmin:
        def authenticate_request(self, request):
            request.state.admin = True
            request.state.admin_username = "operator"
            request.state.csrf = "expected-csrf"
            return True, "expected-csrf"

    class TestUpdates:
        def status(self):
            return {"latest": "v0.1.0-beta.6", "checked": True,
                    "error": "", "channel": "beta"}

        def check(self, *, force=False):
            return self.status()

    monkeypatch.setattr(runtime, "cfg", cfg)
    monkeypatch.setattr(runtime, "admin", TestAdmin())
    ui = UI(cfg, store, Policy(cfg, store), None, TestUpdates())
    app = runtime.SecurityGate(Starlette(routes=[
        Route("/", ui.dashboard, methods=["GET"]),
        Route("/api/v1/updates/check", ui.update_check, methods=["POST"]),
    ]))

    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        dashboard = client.get("/")
        assert dashboard.status_code == 200
        # This is necessary for Chrome to submit a verifiable same-origin
        # Referer when it sends Origin: null on a form submission.
        assert dashboard.headers["referrer-policy"] == "same-origin"
        assert 'action="/api/v1/updates/check"' in dashboard.text

        good_headers = {
            "Origin": "null",
            "Referer": "https://kali.example.test/",
            "Sec-Fetch-Site": "same-origin",
            "Accept": "text/html",
        }
        accepted = client.post("/api/v1/updates/check",
                               data={"csrf": "expected-csrf"}, headers=good_headers)
        assert accepted.status_code == 303
        assert accepted.headers["location"] == "/"

        # Origin:null is NOT a bypass: the matching Referer and Fetch
        # Metadata are both required, alongside the application's CSRF token.
        for removed in ("Referer", "Sec-Fetch-Site"):
            headers = {key: val for key, val in good_headers.items() if key != removed}
            blocked = client.post("/api/v1/updates/check",
                                  data={"csrf": "expected-csrf"}, headers=headers)
            assert blocked.status_code == 403
            assert "Request blocked" in blocked.text
            assert 'href="/"' in blocked.text
        blocked_csrf = client.post("/api/v1/updates/check",
                                   data={"csrf": "invalid"}, headers=good_headers)
        assert blocked_csrf.status_code == 403
        assert "Change not applied" in blocked_csrf.text
        assert "No change was saved" in blocked_csrf.text

        # Clients explicitly requesting JSON retain the original CSRF API
        # contract, rather than receiving an HTML navigation response.
        api_csrf = client.post("/api/v1/updates/check",
            data={"csrf": "invalid"},
            headers={**good_headers, "Accept": "application/json"})
        assert api_csrf.status_code == 403
        assert api_csrf.json() == {"error": "Invalid CSRF token"}

        cross_site = dict(good_headers, Origin="https://evil.example")
        assert client.post("/api/v1/updates/check", data={"csrf": "expected-csrf"},
                           headers=cross_site).status_code == 403

        # API clients receive the unchanged machine-readable diagnostic.
        api_reject = client.post("/api/v1/updates/check", data={"csrf": "expected-csrf"},
                                 headers={"Origin": "https://evil.example",
                                          "Accept": "application/json"})
        assert api_reject.status_code == 403
        assert api_reject.json() == {"error": "origin_mismatch"}

    store.close()
