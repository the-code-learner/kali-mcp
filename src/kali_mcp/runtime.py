"""HTTP composition: self-hosted OAuth + protected streamable MCP + admin WebUI."""
from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlparse
import json
import os

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route

from . import server as core
from .oauth import OAuth
from .webui import Admin, UI
from .telemetry import ToolCallObserver

cfg, store = core.cfg, core.store
oauth = OAuth(cfg, store)
admin = Admin(cfg, store)
ui = UI(cfg, store, core.policy, core.jobs, core.updates)


class SecurityGate:
    """Pure ASGI auth middleware: do not interfere with MCP streaming responses."""
    def __init__(self, app):
        self.app = app
        self.host = urlparse(cfg.base_url).hostname

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        host = headers.get("host", "").split(":", 1)[0].strip("[]")
        if host not in {self.host, "localhost", "127.0.0.1", "::1", "kali-mcp-core"}:
            return await JSONResponse({"error": "Unrecognized Host"}, status_code=400)(scope, receive, send)
        request = Request(scope, receive)
        admin.authenticate_request(request)
        if path == "/mcp" or path.startswith("/mcp/"):
            origin = headers.get("origin")
            if origin and origin.rstrip("/") != cfg.base_url:
                return await JSONResponse({"error": "Origin not allowed"}, status_code=403)(scope, receive, send)
            authorization = headers.get("authorization", "")
            token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
            client_id = oauth.verify_bearer(token)
            if not client_id:
                response = JSONResponse({"error": "unauthorized"}, status_code=401,
                    headers={"WWW-Authenticate": f'Bearer resource_metadata="{cfg.base_url}/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"',
                             "Cache-Control": "no-store"})
                return await response(scope, receive, send)
            if not scope.get("state"):
                scope["state"] = {}
            scope["state"]["oauth_client_id"] = client_id
            context_token = core.ACTOR.set("mcp:" + client_id)
            try:
                # Record every authenticated MCP invocation even if a tool spawns child processes.
                store.audit("mcp:" + client_id, "mcp.request", "allow", path)
                return await self.app(scope, receive, send)
            finally:
                core.ACTOR.reset(context_token)
        return await self.app(scope, receive, send)


async def health(request: Request):
    return JSONResponse({"ok": True, "service": "kali-mcp-core", "version": os.getenv("KALI_MCP_REF", "development")})


async def lifespan_check():
    while True:
        await asyncio.to_thread(core.updates.check)
        await asyncio.sleep(cfg.check_interval)


@contextlib.asynccontextmanager
async def lifespan(app):
    if not cfg.admin_password or len(cfg.admin_password) < 16:
        raise RuntimeError("Set KALI_MCP_ADMIN_PASSWORD to a strong 16+ character value in your private Compose stack")
    task = asyncio.create_task(lifespan_check())
    try:
        async with core.mcp.session_manager.run():
            yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        core.jobs.shutdown()


from mcp.server.transport_security import TransportSecuritySettings

_host = urlparse(cfg.base_url).hostname
_mcp_app = core.mcp.streamable_http_app(
    streamable_http_path="/mcp", stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1:*", "localhost:*", "kali-mcp-core:*", f"{_host}:*"],
        allowed_origins=["http://localhost:*", "http://127.0.0.1:*", cfg.base_url],
    ),
)

app = SecurityGate(Starlette(
    routes=[
        Route("/healthz", health, methods=["GET"]),
        Route("/readyz", health, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", oauth.protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", oauth.protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", oauth.metadata, methods=["GET"]),
        Route("/register", oauth.register, methods=["POST"]),
        Route("/authorize", oauth.authorize_get, methods=["GET"]),
        Route("/authorize", oauth.authorize_post, methods=["POST"]),
        Route("/token", oauth.token, methods=["POST"]),
        Route("/login", admin.login_get, methods=["GET"]),
        Route("/login", admin.login_post, methods=["POST"]),
        Route("/logout", admin.logout, methods=["GET"]),
        Route("/", ui.dashboard, methods=["GET"]),
        Route("/api/v1/status", ui.status, methods=["GET"]),
        Route("/api/v1/settings", ui.settings, methods=["POST"]),
        Route("/api/v1/updates/check", ui.update_check, methods=["POST"]),
        Route("/jobs/{job_id}", ui.job_report, methods=["GET"]),
        Route("/api/v1/jobs/{job_id}", ui.job_detail, methods=["GET"]),
        Route("/api/v1/events", ui.events, methods=["GET"]),
        Route("/static/{name}", ui.static, methods=["GET"]),
        Mount("/", app=ToolCallObserver(_mcp_app, store)),
    ],
    lifespan=lifespan,
))


if __name__ == "__main__":
    uvicorn.run(app, host=os.getenv("MCP_HOST", "0.0.0.0"), port=int(os.getenv("MCP_PORT", "8000")))
