"""HTTP composition: self-hosted OAuth + protected streamable MCP + admin WebUI."""
from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlparse
import json
import os
from collections import deque
import threading
import time

from .superuser import read_record

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
    """Single HTTP ingress: host/origin checks, bounded bodies and auth.

    Proxy-specific IP headers are deliberately NOT trusted for rate limiting.
    TLS and edge rules must be enforced by the HTTPS reverse proxy.
    """

    def __init__(self, app):
        self.app = app
        self.host = urlparse(cfg.base_url).hostname
        self._rate_lock = threading.Lock()
        self._recent: dict[str, deque[float]] = {}
        self._shared = deque()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def safe_send(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ])
                if cfg.base_url.startswith("https://"):
                    headers.append((b"strict-transport-security", b"max-age=31536000"))
                if scope.get("path", "").startswith(("/api/", "/jobs/", "/login", "/logout", "/authorize", "/token", "/register")):
                    headers.append((b"cache-control", b"no-store"))
            return await send(message)

        path = scope.get("path", "")
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        method = scope.get("method", "GET").upper()
        raw_host = headers.get("host", "")
        try:
            host = urlparse("http://" + raw_host).hostname
        except ValueError:
            host = None
        if host not in {self.host, "localhost", "127.0.0.1", "::1", "kali-mcp-core"}:
            return await JSONResponse({"error": "Unrecognized Host"}, status_code=400)(scope, receive, safe_send)

        if method == "POST" and path in {"/register", "/token", "/authorize", "/login"}:
            source = str(scope.get("client", ("unknown", 0))[0])
            now = time.monotonic()
            with self._rate_lock:
                history = self._recent.setdefault(source, deque())
                while history and history[0] < now - 60:
                    history.popleft()
                while self._shared and self._shared[0] < now - 60:
                    self._shared.popleft()
                excessive = len(history) >= 45 or len(self._shared) >= 240
                if not excessive:
                    history.append(now)
                    self._shared.append(now)
                if len(self._recent) > 2048:
                    self._recent.clear()
            if excessive:
                return await JSONResponse({"error": "rate_limited"}, status_code=429)(scope, receive, safe_send)

        if method == "POST" and path in {"/login", "/authorize", "/logout",
                                        "/api/v1/settings", "/api/v1/clients/revoke", "/api/v1/updates/check",
                                        "/api/v1/updates/install"}:
            origin = headers.get("origin", "")
            if origin and origin not in {cfg.base_url, "http://localhost:8787",
                                        "http://127.0.0.1:8787"}:
                return await JSONResponse({"error": "origin_mismatch"}, status_code=403)(scope, receive, safe_send)

        if method == "POST":
            max_size = 262144 if path.startswith("/mcp") else 16384
            try:
                declared = int(headers.get("content-length", "0"))
            except ValueError:
                declared = max_size + 1
            if declared > max_size:
                return await JSONResponse({"error": "request_too_large"}, status_code=413)(scope, receive, safe_send)
            # Also enforce the limit for chunked/streaming uploads without
            # Content-Length, before invoking any parser or the MCP transport.
            chunks = []
            total = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                if message["type"] != "http.request":
                    continue
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > max_size:
                    return await JSONResponse({"error": "request_too_large"}, status_code=413)(scope, receive, safe_send)
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            payload = b"".join(chunks)
            replayed = False
            original_receive = receive

            async def replay_receive():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": payload, "more_body": False}
                return await original_receive()

            receive = replay_receive

        request = Request(scope, receive)
        admin.authenticate_request(request)
        if path == "/mcp" or path.startswith("/mcp/"):
            origin = headers.get("origin")
            if origin and origin.rstrip("/") != cfg.base_url:
                return await JSONResponse({"error": "Origin not allowed"}, status_code=403)(scope, receive, safe_send)
            authorization = headers.get("authorization", "")
            token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
            client_id = oauth.verify_bearer(token)
            if not client_id:
                response = JSONResponse({"error": "unauthorized"}, status_code=401,
                    headers={"WWW-Authenticate": f'Bearer resource_metadata="{cfg.base_url}/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"',
                             "Cache-Control": "no-store"})
                return await response(scope, receive, safe_send)
            scope.setdefault("state", {})["oauth_client_id"] = client_id
            context_token = core.ACTOR.set("mcp:" + client_id)
            try:
                store.audit("mcp:" + client_id, "mcp.request", "allow", path)
                return await self.app(scope, receive, safe_send)
            finally:
                core.ACTOR.reset(context_token)
        return await self.app(scope, receive, safe_send)


async def health(request: Request):
    return JSONResponse({"ok": True, "service": "kali-mcp-core", "version": os.getenv("KALI_MCP_REF", "development")})


async def lifespan_check():
    while True:
        await asyncio.to_thread(core.updates.check)
        await asyncio.sleep(cfg.check_interval)


@contextlib.asynccontextmanager
async def lifespan(app):
    auth_file = os.getenv("KALI_MCP_SUPERUSER_FILE")
    if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() == "true":
        if not auth_file:
            raise RuntimeError("Host Agent mode requires hashed superuser credentials")
        read_record(__import__("pathlib").Path(auth_file))
    elif not auth_file and (not cfg.admin_password or len(cfg.admin_password) < 16):
        raise RuntimeError("Configure a superuser or a legacy Docker-only admin password")
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
        Route("/logout", admin.logout, methods=["POST"]),
        Route("/", ui.dashboard, methods=["GET"]),
        Route("/api/v1/status", ui.status, methods=["GET"]),
        Route("/api/v1/settings", ui.settings, methods=["POST"]),
        Route("/api/v1/clients/revoke", ui.revoke_client, methods=["POST"]),
        Route("/api/v1/updates/check", ui.update_check, methods=["POST"]),
        Route("/api/v1/updates/install", ui.update_install, methods=["POST"]),
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
