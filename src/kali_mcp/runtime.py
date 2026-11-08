"""HTTP composition: self-hosted OAuth + protected streamable MCP + admin WebUI."""
from __future__ import annotations

import asyncio
import contextlib
import html
from urllib.parse import urlparse
import json
import os
import secrets
from collections import deque
import threading
import time

from .superuser import read_record
from .transfers import TransferError, MAX_OPENLINK_FILE

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from starlette.routing import Mount, Route

from . import server as core
from .oauth import OAuth
from .webui import Admin, UI
from .telemetry import ToolCallObserver

cfg, store = core.cfg, core.store
oauth = OAuth(cfg, store)
admin = Admin(cfg, store)
ui = UI(cfg, store, core.policy, core.jobs, core.updates)


def _ingress_error(path: str, headers: dict[str, str], code: str, status: int):
    """Make browser navigation failures readable; keep API and MCP error JSON."""
    browser = ("text/html" in headers.get("accept", "").lower() and
               path.startswith(("/api/v1/", "/login", "/logout", "/authorize")))
    if not browser:
        return JSONResponse({"error": code}, status_code=status,
                            headers={"Cache-Control": "no-store"})
    messages = {
        "ambiguous_headers": "The browser sent conflicting request headers. Reload the page.",
        "Unrecognized Host": "The requested hostname is not authorized for this server.",
        "origin_mismatch": "The browser origin did not match the WebUI address. Reload the dashboard.",
        "request_too_large": "The submitted request is too large.",
        "rate_limited": "Too many requests. Retry later.",
    }
    message = messages.get(code, "The request was blocked by a security check.")
    body = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>Kali MCP — Request not completed</title>
    <link rel="stylesheet" href="/static/app.css"></head><body>
    <main class="report"><section><h2>Request not completed</h2><p>""" +
    html.escape(message) + """</p><p>No changes were made by this request.</p>
    <a href="/">Return to dashboard</a></section></main></body></html>""")
    return HTMLResponse(body, status_code=status, headers={
        "Cache-Control": "no-store", "Referrer-Policy": "same-origin",
        "Content-Security-Policy": "default-src 'none'; style-src 'self'; base-uri 'none'",
    })


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
        self._mcp_recent: dict[str, deque[float]] = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        is_mcp = path == "/mcp" or path.startswith("/mcp/")
        is_file_link = path.startswith("/files/openlink/")
        method = scope.get("method", "GET").upper()
        raw_headers = [(k.decode("latin1").lower(), v.decode("latin1"))
                       for k, v in scope.get("headers", [])]
        headers = dict(raw_headers)
        origin = headers.get("origin", "")
        mcp_origins = {cfg.base_url, *cfg.browser_origins}
        cors_allowed = (is_mcp or is_file_link) and origin in mcp_origins
        if any(sum(1 for name, _ in raw_headers if name == field) > 1
               for field in ("host", "origin")):
            # Duplicated Host/Origin values can be interpreted differently by
            # the edge proxy and the MCP transport; reject at our ingress.
            return await _ingress_error(path, headers, "ambiguous_headers", 400)(
                scope, receive, send)

        async def safe_send(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                if not any(k.lower() == b"referrer-policy" for k, _ in headers):
                    headers.append((b"referrer-policy", b"same-origin"))
                headers.extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ])
                if cors_allowed:
                    existing = {k.lower() for k, _ in headers}
                    for key, value in (
                        (b"access-control-allow-origin", origin.encode("latin1")),
                        (b"vary", b"Origin"),
                        (b"access-control-expose-headers",
                         b"Content-Disposition, Content-Length" if is_file_link else b"Mcp-Session-Id"),
                    ):
                        if key not in existing:
                            headers.append((key, value))
                    if b"cache-control" not in existing:
                        headers.append((b"cache-control", b"no-store"))
                if cfg.base_url.startswith("https://"):
                    headers.append((b"strict-transport-security", b"max-age=31536000"))
                if scope.get("path", "").startswith(("/api/", "/jobs/", "/login", "/logout", "/authorize", "/token", "/register")):
                    headers.append((b"cache-control", b"no-store"))
            return await send(message)

        raw_host = headers.get("host", "")
        try:
            host = urlparse("http://" + raw_host).hostname
        except ValueError:
            host = None
        if host not in {self.host, "localhost", "127.0.0.1", "::1", "kali-mcp-core"}:
            return await _ingress_error(path, headers, "Unrecognized Host", 400)(scope, receive, safe_send)

        # OpenLink PUT/GET capabilities are narrow, origin-limited transfer
        # endpoints, never general API CORS or an authorization bypass for MCP.
        if is_file_link and method == "OPTIONS":
            if not cors_allowed or headers.get("access-control-request-method", "").upper() not in {"PUT", "GET"}:
                return await JSONResponse({"error": "Origin not allowed"}, status_code=403)(
                    scope, receive, safe_send)
            return await PlainTextResponse("", status_code=204, headers={
                "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Max-Age": "600",
                "Cache-Control": "no-store",
            })(scope, receive, safe_send)
        if is_file_link and origin and not cors_allowed:
            return await JSONResponse({"error": "Origin not allowed"}, status_code=403)(
                scope, receive, safe_send)

        if method == "OPTIONS" and path == "/mcp":
            if not cors_allowed or not headers.get("access-control-request-method", "").upper() in {
                    "GET", "POST", "DELETE"}:
                return await JSONResponse({"error": "Origin not allowed"}, status_code=403)(
                    scope, receive, safe_send)
            response = PlainTextResponse("", status_code=204, headers={
                "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": (
                    "Authorization, Content-Type, Accept, MCP-Protocol-Version, "
                    "Mcp-Session-Id, Last-Event-ID, X-Kali-MCP-API-Key"),
                "Access-Control-Max-Age": "600"})
            return await response(scope, receive, safe_send)

        if is_mcp and origin and not cors_allowed:
            return await JSONResponse({"error": "Origin not allowed"}, status_code=403)(
                scope, receive, safe_send)

        if is_mcp:
            source = str(scope.get("client", ("unknown", 0))[0])
            now = time.monotonic()
            with self._rate_lock:
                history = self._mcp_recent.setdefault(source, deque())
                while history and history[0] < now - 60:
                    history.popleft()
                excessive = len(history) >= 600
                if not excessive:
                    history.append(now)
                if len(self._mcp_recent) > 2048:
                    self._mcp_recent.clear()
            if excessive:
                return await _ingress_error(path, headers, "rate_limited", 429)(
                    scope, receive, safe_send)

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
                return await _ingress_error(path, headers, "rate_limited", 429)(scope, receive, safe_send)

        if method == "POST" and path in {"/login", "/authorize", "/logout",
                                        "/api/v1/settings", "/api/v1/clients/revoke", "/api/v1/updates/check",
                                        "/api/v1/updates/install", "/api/v1/api-tokens/create",
                                        "/api/v1/api-tokens/revoke", "/api/v1/api-tokens/rotate",
                                        "/api/v1/browser-origins", "/api/v1/browser-origins/check",
                                         "/settings/deployment"}:
            admin_origins = {cfg.base_url, "http://localhost:8787", "http://127.0.0.1:8787"}
            referrer = headers.get("referer", "")
            referer_ok = any(referrer.startswith(base + "/") for base in admin_origins)
            # Chrome occasionally sends Origin:null on HTTPS form submits. Only
            # accept it with a verifiable same-origin Referer and Fetch Metadata.
            null_ok = (origin == "null" and referer_ok and
                       headers.get("sec-fetch-site") == "same-origin")
            if ((origin and origin not in admin_origins and not null_ok)
                    or (not origin and referrer and not referer_ok)):
                # A browser form needs usable feedback, whereas API clients
                # continue to receive the machine-readable error code.
                if "text/html" in headers.get("accept", "").lower():
                    return await HTMLResponse(
                        """<!doctype html><html lang="en"><head><meta charset="utf-8">
                        <meta name="viewport" content="width=device-width">
                        <title>Kali MCP — Request blocked</title>
                        <link rel="stylesheet" href="/static/app.css"></head><body>
                        <main class="report"><section><h2>Request blocked</h2>
                        <p>The browser's Origin or Referer does not match the configured
                        Kali MCP WebUI origin. No setting or update was changed.</p>
                        <p>Return to the dashboard and reload the page. If this repeats,
                        verify KALI_MCP_PUBLIC_URL matches the HTTPS WebUI address
                        in your deployment configuration.</p>
                        <a href="/">Return to dashboard</a></section></main></body></html>""",
                        status_code=403, headers={
                            "Cache-Control": "no-store",
                            "Content-Security-Policy": (
                                "default-src 'none'; style-src 'self'; base-uri 'none'"),
                        })(scope, receive, safe_send)
                return await JSONResponse({"error": "origin_mismatch"}, status_code=403)(
                    scope, receive, safe_send)

        if method == "POST":
            max_size = 262144 if path.startswith("/mcp") else 16384
            try:
                declared = int(headers.get("content-length", "0"))
            except ValueError:
                declared = max_size + 1
            if declared > max_size:
                return await _ingress_error(path, headers, "request_too_large", 413)(scope, receive, safe_send)
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
                    return await _ingress_error(path, headers, "request_too_large", 413)(scope, receive, safe_send)
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
            # Fail closed on duplicate credentials or simultaneous bearer/header.
            bearer_headers = [v for k, v in raw_headers if k == "authorization"]
            api_headers = [v for k, v in raw_headers if k == "x-kali-mcp-api-key"]
            if (len(bearer_headers) > 1 or len(api_headers) > 1 or
                    (bearer_headers and api_headers)):
                return await JSONResponse({"error": "ambiguous_credentials"}, status_code=400)(
                    scope, receive, safe_send)
            bearer = bearer_headers[0] if bearer_headers else ""
            if bearer and not bearer.lower().startswith("bearer "):
                bearer = ""
            token = bearer[7:].strip() if bearer else ""
            if api_headers:
                if os.getenv("KALI_MCP_API_HEADER_ENABLED", "true").lower() != "true":
                    return await JSONResponse({"error": "custom_header_disabled"}, status_code=403)(
                        scope, receive, safe_send)
                token = api_headers[0]
            identity = None
            allowed_tools = []
            # Never interpret a named API key as an OAuth credential.
            if token.startswith("kmp_"):
                try:
                    fingerprint = admin._credential()[1]
                    api = store.verify_api_token(token, cfg.resource, fingerprint)
                except (OSError, ValueError, RuntimeError):
                    api = None
                if api:
                    identity = "mcp:api:" + api["token_id"]
                    allowed_tools = api["allowed_tools"]
            elif not api_headers:
                client_id = oauth.verify_bearer(token)
                if client_id:
                    identity = "mcp:oauth:" + client_id
            if not identity:
                response = JSONResponse({"error": "unauthorized"}, status_code=401,
                    headers={"WWW-Authenticate": f'Bearer resource_metadata="{cfg.base_url}/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"',
                             "Cache-Control": "no-store"})
                return await response(scope, receive, safe_send)
            if allowed_tools and method == "POST":
                # Restriction applies to tools/call regardless of transport.
                # Reject JSON-RPC batches for restricted API credentials.
                try:
                    rpc = json.loads(payload)
                    if not isinstance(rpc, dict):
                        raise ValueError("RPC batch not permitted for restricted API key")
                    if rpc.get("method") == "tools/call":
                        name = rpc.get("params", {}).get("name")
                        if name not in allowed_tools:
                            return await JSONResponse({"error": "tool_not_allowed"}, status_code=403)(
                                scope, receive, safe_send)
                except (ValueError, TypeError, AttributeError):
                    return await JSONResponse({"error": "invalid_rpc"}, status_code=400)(
                        scope, receive, safe_send)
            scope.setdefault("state", {})["mcp_actor"] = identity
            context_token = core.ACTOR.set(identity)
            try:
                store.audit(identity, "mcp.request", "allow", path)
                return await self.app(scope, receive, safe_send)
            finally:
                core.ACTOR.reset(context_token)
        return await self.app(scope, receive, safe_send)


async def openlink_get(request: Request):
    """One-use, ten-minute bearer capability to download a Core workspace file.

    The URL itself is the credential. No client can select an arbitrary path.
    """
    secret = request.path_params["ticket"]
    selection = core.vault.consume_download(secret)
    if not selection:
        return PlainTextResponse("Download link invalid, expired or already used", status_code=404,
                                 headers={"Cache-Control": "no-store"})
    path, name = selection
    return FileResponse(path, filename=name, content_disposition_type="attachment",
                        media_type="application/octet-stream",
                        headers={"Cache-Control": "private, no-store",
                                 "Referrer-Policy": "no-referrer",
                                 "Content-Security-Policy": "default-src 'none'"})


async def openlink_put(request: Request):
    """Receive a bounded raw byte stream from a prepared one-use OpenLink."""
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/octet-stream":
        return JSONResponse({"error": "Use Content-Type: application/octet-stream"},
                            status_code=415, headers={"Cache-Control": "no-store"})
    length = request.headers.get("content-length")
    try:
        declared = int(length) if length is not None else None
    except ValueError:
        return JSONResponse({"error": "Invalid Content-Length"}, status_code=400)
    if declared is not None and (declared < 0 or declared > MAX_OPENLINK_FILE):
        return JSONResponse({"error": "Upload exceeds 8 MiB limit"}, status_code=413)
    try:
        result = await core.vault.receive_upload(request.path_params["ticket"],
                                                  request.stream(), declared)
        return JSONResponse(result, status_code=201, headers={"Cache-Control": "no-store"})
    except TransferError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400,
                            headers={"Cache-Control": "no-store"})


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


def sdk_allowed_hosts(public_url: str) -> list[str]:
    """SDK DNS-rebinding allowlist: match bare HTTPS Host AND explicit ports.

    The MCP SDK's 'hostname:*' wildcard does not match a portless Host.
    Keep both the origin's exact hostname and its port variant; do NOT
    disable the SDK's DNS-rebinding protection or trust X-Forwarded-Host.
    """
    public_host = urlparse(public_url).hostname
    if not public_host:
        raise ValueError("KALI_MCP_PUBLIC_URL requires a valid host")
    if ":" in public_host:
        public_host = "[" + public_host + "]"
    hosts = ("127.0.0.1", "localhost", "kali-mcp-core", public_host)
    return list(dict.fromkeys(item for host in hosts for item in (host, host + ":*")))


_mcp_app = core.mcp.streamable_http_app(
    streamable_http_path="/mcp", stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sdk_allowed_hosts(cfg.base_url),
        allowed_origins=["http://localhost:*", "http://127.0.0.1:*", cfg.base_url, *cfg.browser_origins],
    ),
)

app = SecurityGate(Starlette(
    routes=[
        Route("/healthz", health, methods=["GET"]),
        Route("/files/openlink/{ticket}", openlink_get, methods=["GET"]),
        Route("/files/openlink/{ticket}", openlink_put, methods=["PUT"]),
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
        Route("/", ui.control_center, methods=["GET"]),
        Route("/legacy", ui.dashboard, methods=["GET"]),
        Route("/api/v1/ui/snapshot", ui.control_center_snapshot, methods=["GET"]),
        Route("/api/v1/status", ui.status, methods=["GET"]),
        Route("/api/v1/settings", ui.settings, methods=["POST"]),
        Route("/settings/deployment", ui.deployment_settings, methods=["GET"]),
        Route("/settings/deployment", ui.deployment_settings_save, methods=["POST"]),
        Route("/api/v1/clients/revoke", ui.revoke_client, methods=["POST"]),
        Route("/api/v1/api-tokens/create", ui.create_api_token, methods=["POST"]),
        Route("/api/v1/api-tokens/revoke", ui.revoke_api_token, methods=["POST"]),
        Route("/api/v1/api-tokens/rotate", ui.rotate_api_token, methods=["POST"]),
        Route("/api/v1/browser-origins", ui.browser_origins_update, methods=["POST"]),
        Route("/api/v1/browser-origins/check", ui.browser_origins_check, methods=["POST"]),
        Route("/api/v1/updates/check", ui.update_check, methods=["POST"]),
        Route("/api/v1/updates/install", ui.update_install, methods=["POST"]),
        Route("/jobs/{job_id}", ui.job_report_live, methods=["GET"]),
        Route("/api/v1/jobs/{job_id}", ui.job_detail, methods=["GET"]),
        Route("/api/v1/events", ui.events, methods=["GET"]),
        Route("/static/{name}", ui.static, methods=["GET"]),
        Mount("/", app=ToolCallObserver(_mcp_app, store)),
    ],
    lifespan=lifespan,
))


if __name__ == "__main__":
    uvicorn.run(app, host=os.getenv("MCP_HOST", "0.0.0.0"), port=int(os.getenv("MCP_PORT", "8000")))
