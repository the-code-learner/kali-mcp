"""Interactive browser forms should not show raw JSON, API contracts stay JSON."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.policy import Policy
from kali_mcp.store import Store
from kali_mcp.webui import Admin, UI, _csrf_for

PASSWORD = "CI_WEBUI_BROWSER_FORMS_PASSWORD_2026"


def test_login_token_and_oauth_revoke_browser_errors_are_readable(
        tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.delenv("KALI_MCP_SUPERUSER_FILE", raising=False)
    cfg = Config.from_env()
    store = Store(tmp_path / "webui.db")
    auth = Admin(cfg, store)
    ui = UI(cfg, store, Policy(cfg, store), None, None)

    class Gate:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                auth.authenticate_request(Request(scope, receive))
            await self.app(scope, receive, send)

    app = Gate(Starlette(routes=[
        Route("/login", auth.login_post, methods=["POST"]),
        Route("/api/v1/api-tokens/create", ui.create_api_token, methods=["POST"]),
        Route("/api/v1/api-tokens/revoke", ui.revoke_api_token, methods=["POST"]),
        Route("/api/v1/clients/revoke", ui.revoke_client, methods=["POST"]),
    ]))
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        invalid = client.post("/login", data={
            "username": "admin", "password": "wrong"},
            headers={"Accept": "text/html"})
        assert invalid.status_code == 401
        assert invalid.headers["content-type"].startswith("text/html")
        assert "Sign in unsuccessful" in invalid.text
        assert "Return to sign in" in invalid.text
        assert "<html" in invalid.text
        assert "{" not in invalid.text

        # Use a different source address to avoid an intentional login retry
        # throttle after the deliberately invalid login above.
        auth.failures.clear()
        authenticated = client.post("/login", data={
            "username": "admin", "password": PASSWORD},
            headers={"Accept": "text/html"})
        assert authenticated.status_code == 303
        cookie = client.cookies["kali_admin"]
        csrf = _csrf_for(cookie, auth._credential()[1])
        payload = {"csrf": csrf, "name": "test API", "days": "30"}

        denied = client.post("/api/v1/api-tokens/create", data=payload,
                             headers={"Accept": "text/html"})
        assert denied.status_code == 403
        assert denied.headers["content-type"].startswith("text/html")
        assert "Change not applied" in denied.text
        assert "Return to dashboard" in denied.text
        assert not store.list_api_tokens()

        api_denied = client.post("/api/v1/api-tokens/create", data=payload,
                                 headers={"Accept": "application/json"})
        assert api_denied.status_code == 403
        assert api_denied.json() == {
            "error": "Superuser password confirmation required"}

        invalid_days = client.post("/api/v1/api-tokens/create", data={
            **payload, "password": PASSWORD, "days": "0"},
            headers={"Accept": "text/html"})
        assert invalid_days.status_code == 400
        assert "Invalid token request" in invalid_days.text

        bad_client = client.post("/api/v1/clients/revoke", data={
            "csrf": csrf, "client_id": "bad!"},
            headers={"Accept": "text/html"})
        assert bad_client.status_code == 400
        assert "Invalid client identifier" in bad_client.text

        unknown_token = client.post("/api/v1/api-tokens/revoke", data={
            "csrf": csrf, "password": PASSWORD, "token_id": "bad"},
            headers={"Accept": "text/html"})
        assert unknown_token.status_code == 400
        assert "Invalid API token ID" in unknown_token.text
    store.close()
