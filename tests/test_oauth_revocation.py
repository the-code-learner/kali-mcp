"""Administrator can revoke MCP OAuth bearer/refresh tokens immediately."""
from __future__ import annotations

import hashlib
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.store import Store, digest
from kali_mcp.oauth import OAuth
from kali_mcp.webui import UI
from kali_mcp.jobs import Jobs
from kali_mcp.policy import Policy
from kali_mcp.releases import UpdateChecker


def test_mcp_token_revoke_and_webui_csrf(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    cli_id = "a" * 32
    access = "secrettoken"
    with store.transaction():
        store.db.execute("INSERT INTO oauth_clients VALUES (?,?,?,?)",
                         (cli_id, "Test MCP client", '["https://client.example/cb"]', "2026-11-07"))
        store.db.execute("INSERT INTO oauth_tokens VALUES (?,?,?,?,?,?,0,?)",
                         (digest(access), cli_id, "access", "mcp:tools",
                          cfg.resource, int(time.time()) + 3600, "family1"))
    oauth = OAuth(cfg, store)
    assert oauth.verify_bearer(access) == cli_id
    jobs = Jobs(cfg, store)
    ui = UI(cfg, store, Policy(cfg, store), jobs,
            UpdateChecker(cfg.repo, cfg.update_channel, cfg.check_interval))

    class AdminMiddleware:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                scope.setdefault("state", {})["admin"] = True
                scope["state"]["admin_username"] = "operator"
                scope["state"]["csrf"] = "csrf-test"
            return await self.app(scope, receive, send)

    app = AdminMiddleware(Starlette(routes=[
        Route("/api/v1/clients/revoke", ui.revoke_client, methods=["POST"])
    ]))
    try:
        client = TestClient(app, base_url=cfg.base_url, follow_redirects=False)
        bad = client.post("/api/v1/clients/revoke",
                          data={"client_id": cli_id, "csrf": "wrong"})
        assert bad.status_code == 403
        assert oauth.verify_bearer(access) == cli_id
        good = client.post("/api/v1/clients/revoke",
                           data={"client_id": cli_id, "csrf": "csrf-test"})
        assert good.status_code == 303
        assert oauth.verify_bearer(access) is None
        assert store.list_clients()[0]["active"] == 0
    finally:
        jobs.shutdown()
        store.close()
