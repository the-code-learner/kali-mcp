"""Admin-only WebUI and API. Never use an OAuth bearer to enable host/root privileges."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import secrets
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse, FileResponse

from .config import Config
from .browser_origins import validate_browser_origin
from .policy import Policy, PolicyDenied
from .releases import UpdateChecker, installed_release_tag, is_update_available
from .store import Store, digest
from .jobs import Jobs
from .superuser import read_record, record_fingerprint, verify
from .reports import report_html


def _csrf_for(cookie: str, credential_fingerprint: str) -> str:
    return hmac.new(credential_fingerprint.encode(), cookie.encode(), hashlib.sha256).hexdigest()


class Admin:
    """Web administrator sessions bound to the current superuser credential."""

    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store
        candidate = os.getenv("KALI_MCP_SUPERUSER_FILE", "").strip()
        self.credential_path = Path(candidate) if candidate else None
        self.failures: dict[str, tuple[int, float]] = {}
        self.global_failures: tuple[int, float] = (0, 0.0)
        self.hash_gate = asyncio.Semaphore(2)

    def _credential(self) -> tuple[str, str, dict | None]:
        if self.credential_path is not None:
            record = read_record(self.credential_path)
            return record["username"], record_fingerprint(record), record
        if not self.cfg.admin_password or len(self.cfg.admin_password) < 16:
            raise RuntimeError("Superuser not configured")
        # Compatibility for older Docker-only deployment. Hybrid never falls
        # back to a plaintext environment password.
        return "admin", hashlib.sha256(self.cfg.admin_password.encode()).hexdigest(), None

    def authenticate_request(self, request: Request) -> tuple[bool, str]:
        request.state.admin = False
        request.state.admin_username = ""
        request.state.csrf = ""
        cookie = request.cookies.get("kali_admin", "")
        if not cookie or len(cookie) > 256:
            return False, ""
        try:
            username, fingerprint, _ = self._credential()
        except (RuntimeError, ValueError, OSError):
            return False, ""
        with self.store.lock:
            row = self.store.db.execute(
                "SELECT * FROM admin_sessions WHERE hash=? AND expires>?",
                (digest(cookie), int(time.time()))).fetchone()
        if not row:
            return False, ""
        csrf = _csrf_for(cookie, fingerprint)
        if not secrets.compare_digest(row["csrf_hash"], digest(csrf)):
            return False, ""
        request.state.admin = True
        request.state.admin_username = username
        request.state.csrf = csrf
        return True, csrf

    async def login_get(self, request: Request) -> HTMLResponse:
        nxt = str(request.query_params.get("next", "/"))
        if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
            nxt = "/"
        session_notice = ("<p role=\"alert\">Your administrator session has expired or is no longer valid. "
                          "Please sign in again, then return to the dashboard and repeat your change.</p>"
                          if request.query_params.get("reason") == "session-expired" else "")
        return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8">
          <title>Kali MCP · Superuser login</title>
          <meta name="viewport" content="width=device-width">
          <link rel="stylesheet" href="/static/app.css"></head>
          <body><main class="login"><h1>Kali MCP</h1>
          <p>Superuser authentication</p>
          {session_notice}
          <form method="post" action="/login">
            <input type="hidden" name="next" value="{html.escape(nxt,quote=True)}">
            <label>Username<input name="username" autocomplete="username" required maxlength="32"></label>
            <label>Password<input type="password" name="password" required autocomplete="current-password"></label>
            <button type="submit">Sign in</button></form></main></body></html>""",
            headers={"Cache-Control": "no-store",
                     "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'"})

    def _rate_limited(self, source: str) -> bool:
        count, until = self.failures.get(source, (0, 0.0))
        global_count, global_until = self.global_failures
        return until > time.monotonic() or global_until > time.monotonic()

    @staticmethod
    def _login_error(request: Request, message: str, status_code: int):
        if "text/html" not in request.headers.get("accept", "").lower():
            return JSONResponse({"error": message}, status_code=status_code,
                                headers={"Cache-Control": "no-store"})
        page = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width">
        <title>Kali MCP — Sign in</title>
        <link rel="stylesheet" href="/static/app.css"></head><body>
        <main class="report"><section><h2>Sign in unsuccessful</h2><p>""" +
        html.escape(message) +
        """</p><a href="/login">Return to sign in</a></section></main></body></html>""")
        return HTMLResponse(page, status_code=status_code, headers={
            "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; style-src 'self'; base-uri 'none'",
        })

    async def login_post(self, request: Request):
        try:
            expected_user, fingerprint, record = self._credential()
        except (RuntimeError, ValueError, OSError):
            return self._login_error(request, "Superuser setup is incomplete", 503)
        source = request.client.host if request.client else "unknown"
        if self._rate_limited(source):
            return self._login_error(request, "Too many login attempts. Try again later.", 429)
        if int(request.headers.get("content-length", "0")) > 4096:
            return self._login_error(request, "Login request is too large", 413)
        form = await request.form()
        username = str(form.get("username") or "admin")[:64]
        password = str(form.get("password") or "")
        if len(password) > 256:
            return self._login_error(request, "Invalid username or password", 401)
        if record is not None:
            async with self.hash_gate:
                valid = await asyncio.to_thread(verify, record, username, password)
        else:
            valid = (secrets.compare_digest(username, "admin")
                     and secrets.compare_digest(password, self.cfg.admin_password))
        if not valid:
            count, _ = self.failures.get(source, (0, 0.0))
            count += 1
            self.failures[source] = (count, time.monotonic() + min(600, 2 ** min(count, 9)))
            global_count, _ = self.global_failures
            global_count += 1
            self.global_failures = (global_count, time.monotonic() + 300 if global_count >= 40 else 0)
            if len(self.failures) > 4096:
                self.failures.clear()
            self.store.audit("webui", "admin.login", "deny", "authentication rejected")
            return self._login_error(request, "Invalid username or password", 401)
        self.failures.pop(source, None)
        self.global_failures = (0, 0)
        cookie = secrets.token_urlsafe(48)
        csrf = _csrf_for(cookie, fingerprint)
        with self.store.transaction():
            self.store.db.execute("INSERT INTO admin_sessions VALUES(?,?,?)",
                                  (digest(cookie), digest(csrf), int(time.time()) + 4 * 3600))
            self.store._audit("webui:" + expected_user, "admin.login", "allow")
        nxt = str(form.get("next") or "/")
        if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
            nxt = "/"
        response = RedirectResponse(nxt, status_code=303)
        response.set_cookie("kali_admin", cookie, httponly=True,
                            secure=self.cfg.base_url.startswith("https:"),
                            samesite="lax", max_age=4 * 3600, path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    async def logout(self, request: Request):
        if not request.state.admin or not request.state.csrf:
            return (RedirectResponse("/login?reason=session-expired&next=/", status_code=303)
                    if "text/html" in request.headers.get("accept", "").lower()
                    else JSONResponse({"error": "Login required"}, status_code=401))
        form = await request.form()
        if not secrets.compare_digest(str(form.get("csrf") or ""), request.state.csrf):
            return self._login_error(request, "Logout form is invalid; reload the dashboard.", 403)
        cookie = request.cookies.get("kali_admin", "")
        if cookie:
            with self.store.lock:
                self.store.db.execute("DELETE FROM admin_sessions WHERE hash=?", (digest(cookie),))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("kali_admin", path="/")
        return response


class UI:
    def __init__(self, cfg: Config, store: Store, policy: Policy, jobs: Jobs, updates: UpdateChecker):
        self.cfg, self.store, self.policy, self.jobs, self.updates = cfg, store, policy, jobs, updates

    def _upgrade_gate(self) -> tuple[bool, str]:
        """Explain both deployment and administrator gates, without changing policy."""
        if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() != "true":
            return False, "WebUI installation requires the native systemd Host Agent."
        if not self.cfg.ceilings()["mcp_updates"]["allowed"]:
            return False, ("Update installation is disabled by the deployment ceiling "
                           "KALI_MCP_ALLOW_MCP_UPDATES=false. Enable it in the "
                           "Deployment & Security → Permissions, and then enable "
                           "the MCP Updates switch in WebUI.")
        if not self.store.get_setting("mcp_updates"):
            return False, ("Update installation is currently off. Enable "
                           "'MCP Updates' under 'Execution capabilities', "
                           "confirming the superuser password.")
        return True, "Installation is authorized; the services will restart."

    @staticmethod
    def _upgrade_notice(title: str, message: str, status_code: int = 403) -> HTMLResponse:
        """Provide usable navigation and human-readable errors to browser forms."""
        body = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width">
        <title>Kali MCP — Update status</title>
        <link rel="stylesheet" href="/static/app.css"></head><body>
        <main class="report"><section><h2>""" + html.escape(title) +
        "</h2><p>" + html.escape(message) +
        """</p><p>No new upgrade was started by this request.</p>
        <a href="/">Return to dashboard</a></section></main></body></html>""")
        return HTMLResponse(body, status_code=status_code,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                     "X-Frame-Options": "DENY",
                     "Content-Security-Policy": "default-src 'none'; style-src 'self'; base-uri 'none'"})

    @staticmethod
    def _html_form(request: Request) -> bool:
        """Browser navigation form, not an API fetch that expects JSON."""
        return (request.method.upper() == "POST"
                and "text/html" in request.headers.get("accept", "").lower())

    @staticmethod
    def _form_failure(request: Request, message: str, status_code: int = 403):
        """Friendly browser feedback while keeping API error contracts intact."""
        if not UI._html_form(request):
            return JSONResponse({"error": message}, status_code=status_code,
                                headers={"Cache-Control": "no-store"})
        body = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
          <meta name="viewport" content="width=device-width">
          <title>Kali MCP — Change not applied</title>
          <link rel="stylesheet" href="/static/app.css"></head><body>
          <main class="report"><section><h2>Change not applied</h2>
          <p>""" + html.escape(message[:250]) +
          """</p><p>No change was saved by this request.</p>
          <a href="/">Return to dashboard</a></section></main></body></html>""")
        return HTMLResponse(body, status_code=status_code, headers={
            "Cache-Control": "no-store", "Referrer-Policy": "same-origin",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'self'; base-uri 'none'"),
        })

    def _admin(self, request: Request):
        if request.state.admin:
            return None
        if self._html_form(request):
            # A POST must NEVER be replayed after login. Return to GET dashboard
            # and require the administrator to confirm the action anew.
            response = RedirectResponse(
                "/login?reason=session-expired&next=/", status_code=303,
                headers={"Cache-Control": "no-store"})
            response.delete_cookie("kali_admin", path="/")
            return response
        return JSONResponse({"error": "Administrator login required"}, status_code=401,
                            headers={"Cache-Control": "no-store"})

    def _csrf(self, request: Request, submitted: str):
        if not request.state.csrf or not secrets.compare_digest(request.state.csrf, submitted):
            if self._html_form(request):
                return self._form_failure(request,
                    "The form is no longer valid. Reload the dashboard and retry.", 403)
            return JSONResponse({"error": "Invalid CSRF token"}, status_code=403,
                                headers={"Cache-Control": "no-store"})
        return None

    async def _confirm_token_action(self, request: Request, password: str) -> bool:
        """Reauthenticate the superuser for sensitive token lifecycle operations."""
        if not password or len(password) > 256:
            return False
        path = os.getenv("KALI_MCP_SUPERUSER_FILE", "").strip()
        if path:
            try:
                record = read_record(Path(path))
                return await asyncio.to_thread(verify, record, request.state.admin_username, password)
            except (ValueError, OSError):
                return False
        return bool(self.cfg.admin_password and secrets.compare_digest(password, self.cfg.admin_password))

    def _token_fingerprint(self) -> str:
        path = os.getenv("KALI_MCP_SUPERUSER_FILE", "").strip()
        if path:
            return record_fingerprint(read_record(Path(path)))
        return hashlib.sha256(self.cfg.admin_password.encode()).hexdigest()

    def _show_one_time_token(self, token_id: str, token: str) -> HTMLResponse:
        body = ("""<!doctype html><html><head><meta charset="utf-8">
          <title>Kali MCP - one-time token</title></head><body>
          <h1>API token created</h1><p>Copy this secret now; it cannot be retrieved later.</p>
          <textarea readonly rows="4" cols="90">"""
          + html.escape(token) + """</textarea><p>Credential ID: <code>"""
          + html.escape(token_id) + """</code></p>
          <p>Store in a password manager; browser-side llama.cpp may retain it in its profile.</p>
          <a href="/">Return to dashboard</a></body></html>""")
        return HTMLResponse(body, headers={"Cache-Control": "no-store", "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'"})


    async def create_api_token(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        if not await self._confirm_token_action(request, str(form.get("password") or "")):
            return self._form_failure(request, "Superuser password confirmation required", 403)
        try:
            browser_origin = str(form.get("browser_origin") or "").strip()
            if browser_origin:
                browser_origin = validate_browser_origin(browser_origin)
                if browser_origin not in self.cfg.browser_origins:
                    return self._browser_notice(
                        "Browser origin not authorized",
                        "First authorize " + browser_origin +
                        " in the MCP Browser Origins / CORS section, then create your token.", 409)
            names = [v.strip() for v in str(form.get("allowed_tools") or "").split(",") if v.strip()]
            token_id, token = self.store.create_api_token(
                str(form.get("name") or ""), self.cfg.resource,
                self._token_fingerprint(), days=int(form.get("days") or 30),
                allowed_tools=names, actor="webui:" + request.state.admin_username)
        except (ValueError, OSError) as exc:
            return self._form_failure(request, "Invalid token request: " + str(exc)[:160], 400)
        return self._show_one_time_token(token_id, token)

    async def rotate_api_token(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        if not await self._confirm_token_action(request, str(form.get("password") or "")):
            return self._form_failure(request, "Superuser password confirmation required", 403)
        try:
            token_id, token = self.store.rotate_api_token(
                str(form.get("token_id") or ""), self.cfg.resource,
                self._token_fingerprint(), days=int(form.get("days") or 30),
                actor="webui:" + request.state.admin_username)
        except (ValueError, OSError) as exc:
            return self._form_failure(request, "Invalid token request: " + str(exc)[:160], 400)
        return self._show_one_time_token(token_id, token)

    async def revoke_api_token(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        if not await self._confirm_token_action(request, str(form.get("password") or "")):
            return self._form_failure(request, "Superuser password confirmation required", 403)
        try:
            revoked = self.store.revoke_api_token(str(form.get("token_id") or ""),
                        actor="webui:" + request.state.admin_username)
        except ValueError:
            return self._form_failure(request, "Invalid API token ID", 400)
        if not revoked:
            return self._form_failure(request, "API token not found or already revoked", 404)
        return RedirectResponse("/", status_code=303)

    @staticmethod
    def _browser_notice(title: str, message: str, code: int = 200) -> HTMLResponse:
        body = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
          <title>Kali MCP — Browser CORS</title>
          <meta name="viewport" content="width=device-width">
          <link rel="stylesheet" href="/static/app.css"></head>
          <body><main class="report"><section><h2>""" +
          html.escape(title) + "</h2><p>" + html.escape(message) +
          """</p><a href="/">Return to dashboard</a></section></main></body></html>""")
        return HTMLResponse(body, status_code=code, headers={
            "Cache-Control": "no-store", "Referrer-Policy": "same-origin",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'self'; base-uri 'none'",
        })

    async def browser_origins_update(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() != "true":
            return self._browser_notice("Unavailable", "Native Host Agent is required.", 403)
        try:
            origin = validate_browser_origin(str(form.get("origin") or ""))
            action = str(form.get("action") or "")
            if action not in {"add", "remove"}:
                raise ValueError("Invalid action")
            password = str(form.get("password") or "")
            if not password or len(password) > 256:
                raise ValueError("Superuser password confirmation is required")
            from .broker_client import call
            outcome = await asyncio.to_thread(
                call, self.cfg.broker_socket, "browser_origins_update", {
                    "origin": origin, "action": action,
                    "superuser_name": request.state.admin_username,
                    "superuser_password": password,
                }, timeout=30)
            self.store.audit("webui:" + request.state.admin_username,
                             "browser_origins." + action, "allow", origin)
            if outcome.get("unchanged"):
                return RedirectResponse("/?cors=unchanged", status_code=303)
            return RedirectResponse("/?cors=scheduled", status_code=303)
        except (ValueError, OSError, RuntimeError) as exc:
            self.store.audit("webui", "browser_origins.update", "deny",
                             type(exc).__name__)
            return self._browser_notice("Browser origin not changed",
                                        str(exc)[:220], 403)

    @staticmethod
    def _browser_probe(origin: str, host: str, bearer: str) -> dict:
        """Local-only real HTTP CORS/Host/MCP check, never echo the Bearer secret."""
        base = "http://127.0.0.1:8000/mcp"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        shared = {"Host": host, "Origin": origin}
        def fetch(request):
            try:
                with opener.open(request, timeout=8) as response:
                    return response.status, response.headers, response.read(8192)
            except urllib.error.HTTPError as exc:
                return exc.code, exc.headers, exc.read(8192)
        try:
            preflight = urllib.request.Request(base, method="OPTIONS", headers={
                **shared, "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers":
                    "authorization,content-type,mcp-protocol-version",
            })
            cors_status, cors_headers, _ = fetch(preflight)
            allowed = cors_status == 204 and cors_headers.get(
                "Access-Control-Allow-Origin") == origin
            result = {"cors": "allowed" if allowed else "denied",
                      "preflight_http": cors_status, "host": "not tested",
                      "mcp": "not tested"}
            if not allowed:
                return result
            if not bearer:
                result["mcp"] = ("No credential supplied: MCP authentication and "
                                 "SDK Host validation were not tested.")
                return result
            if len(bearer) > 512 or "\r" in bearer or "\n" in bearer:
                raise ValueError("Bearer token must be nonempty, bounded and free of newlines")
            headers = {**shared, "Authorization": "Bearer " + bearer,
                       "Content-Type": "application/json",
                       "Accept": "application/json, text/event-stream",
                       "MCP-Protocol-Version": "2025-06-18"}
            def rpc(method, params):
                payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                                      "method": method, "params": params}).encode()
                return fetch(urllib.request.Request(base, method="POST",
                                                    data=payload, headers=headers))
            status, _, body = rpc("initialize", {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "kali-mcp-cors-check", "version": "1.0"}})
            result["initialize_http"] = status
            if status == 421:
                result["host"] = "rejected by MCP SDK (421)"
                result["mcp"] = "not initialized"
                return result
            if status == 401:
                result["host"] = "not reached (invalid or revoked credential)"
                result["mcp"] = "authentication rejected (401)"
                return result
            if status != 200:
                result["host"] = "MCP error (HTTP " + str(status) + ")"
                return result
            try:
                info = json.loads(body)
                if "serverInfo" not in info.get("result", {}):
                    raise ValueError("Missing MCP serverInfo")
            except (ValueError, TypeError):
                result["host"] = "passed"
                result["mcp"] = "invalid initialize response"
                return result
            result["host"] = "passed (no-port public Host)"
            list_status, _, list_body = rpc("tools/list", {})
            result["tools_list_http"] = list_status
            if list_status == 200:
                try:
                    tools = json.loads(list_body).get("result", {}).get("tools", [])
                    result["mcp"] = "initialize and tools/list succeeded (" + str(len(tools)) + " tools)"
                except (ValueError, TypeError):
                    result["mcp"] = "tools/list returned malformed JSON"
            else:
                result["mcp"] = "tools/list rejected (HTTP " + str(list_status) + ")"
            return result
        except (OSError, ValueError) as exc:
            return {"cors": "probe failed", "host": "unknown", "mcp": "not tested",
                    "error": type(exc).__name__}

    async def browser_origins_check(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        try:
            origin = validate_browser_origin(str(form.get("origin") or ""))
            bearer = str(form.get("bearer") or "")
            public_host = urlparse(self.cfg.base_url).hostname
            if not public_host:
                raise ValueError("Public host is not configured")
            if ":" in public_host:
                public_host = "[" + public_host + "]"
            result = await asyncio.to_thread(self._browser_probe, origin,
                                             public_host, bearer)
            details = " | ".join(str(k) + ": " + str(v) for k, v in result.items())
            return self._browser_notice("MCP browser CORS diagnostic", details)
        except ValueError as exc:
            return self._browser_notice("Invalid browser origin", str(exc), 400)

    async def deployment_settings(self, request: Request):
        from .deployment_webui import view
        return await view(self, request)

    async def deployment_settings_save(self, request: Request):
        from .deployment_webui import save
        return await save(self, request)

    async def control_center(self, request: Request):
        from .control_center import page
        return await page(self, request)

    async def control_center_snapshot(self, request: Request):
        from .control_center import snapshot
        return await snapshot(self, request)

    async def job_report_live(self, request: Request):
        if (error := self._admin(request)):
            return error
        job_id = str(request.path_params["job_id"])
        if self.store.get_job(job_id) is None:
            return self._browser_notice("Job not found",
                                        "The selected job is not available.", 404)
        return RedirectResponse("/?page=files&job=" + job_id,
                                status_code=303, headers={"Cache-Control": "no-store"})

    async def dashboard(self, request: Request):
        if not request.state.admin:
            return RedirectResponse("/login", status_code=303)
        toggles = []
        for key in ("host_exec", "host_root", "package_install", "network_changes", "mcp_updates"):
            allowed = self.cfg.ceilings()[key]["allowed"]
            active = self.store.get_setting(key)
            variable = self.cfg.ceilings()[key]["yaml"]
            disabled = "" if allowed else " disabled"
            if key == "host_root":
                note = """<label class="consent"><input type="checkbox" name="disclaimer" value="yes" required>
                I understand this authorizes full root access to Kali Linux for permitted MCP clients,
                and can change or destroy host data and configurations.</label>"""
            else:
                note = ""
            toggles.append(f"""<form method="post" action="/api/v1/settings" class="toggle">
              <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}">
              <input type="hidden" name="feature" value="{key}">
              <input type="hidden" name="enabled" value="{'false' if active else 'true'}">
              <div><strong>{html.escape(key.replace('_', ' ').title())}</strong>
              <div class="muted">Deployment ceiling: <code>{variable}</code> = {'true' if allowed else 'false'}</div></div>
              {note if not active else ''}
              {('<label>Confirm superuser password<input type="password" name="superuser_password" required autocomplete="current-password"></label>' if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() == "true" and key in {"host_exec","host_root","package_install","network_changes","mcp_updates"} else '')}
              <button type="submit" {disabled}>{'Disable' if active else 'Enable'}</button>
            </form>""")
        rows = "".join(f"<tr><td>{html.escape(j['tool_id'])}</td><td>{html.escape(j['actor'])}</td><td>{html.escape(j['state'])}</td><td><a href='/jobs/{j['id']}'>{j['id'][:12]}</a></td></tr>"
                       for j in self.store.list_jobs(30))
        clients = self.store.list_clients(50)
        client_rows = "".join(
            "<tr><td>" + html.escape(str(c["name"])) + "</td><td><code>"
            + html.escape(str(c["client_id"])[:12]) + "</code></td><td>"
            + ("Active" if c["active"] else "Revoked / expired") + "</td><td>"
            + '<form action="/api/v1/clients/revoke" method="post">'
            + '<input type="hidden" name="csrf" value="' + html.escape(request.state.csrf) + '">'
            + '<input type="hidden" name="client_id" value="' + html.escape(c["client_id"]) + '">'
            + '<button type="submit">Revoke access</button></form>'
            + "</td></tr>"
            for c in clients)
        api_rows = "".join(
            "<tr><td>" + html.escape(t["name"]) + "</td><td><code>"
            + html.escape(t["token_id"][:12]) + "</code></td><td>"
            + ("Revoked" if t["revoked"] else
               ("Expired" if t["expires"] <= int(time.time()) else "Active"))
            + "</td><td>" + datetime.fromtimestamp(t["expires"], timezone.utc).strftime("%Y-%m-%d")
            + "</td><td>"
            + (datetime.fromtimestamp(t["last_used"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
               if t["last_used"] else "Never")
            + "</td><td>" + html.escape(", ".join(json.loads(t["allowed_tools"])) or "All")
            + "</td><td>"
            + (('<form class="token-action" method="post" action="/api/v1/api-tokens/revoke">'
                '<input type="hidden" name="csrf" value="' + html.escape(request.state.csrf) + '">'
                '<input type="hidden" name="token_id" value="' + html.escape(t["token_id"]) + '">'
                '<input type="password" name="password" placeholder="Superuser password" required>'
                '<button type="submit">Revoke</button></form>'
                '<form class="token-action" method="post" action="/api/v1/api-tokens/rotate">'
                '<input type="hidden" name="csrf" value="' + html.escape(request.state.csrf) + '">'
                '<input type="hidden" name="token_id" value="' + html.escape(t["token_id"]) + '">'
                '<input type="number" name="days" min="1" max="90" value="30" required>'
                '<input type="password" name="password" placeholder="Superuser password" required>'
                '<button type="submit">Rotate</button></form>') if not t["revoked"] else "")
            + "</td></tr>" for t in self.store.list_api_tokens(100))
        active_origins = self.cfg.browser_origins
        host_origins = list(active_origins)
        deploy_state = "unknown"
        deploy_detail = ""
        if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() == "true":
            try:
                from .broker_client import call
                observed = await asyncio.to_thread(
                    call, self.cfg.broker_socket, "browser_origins_status", timeout=3)
                host_origins = observed.get("configured", host_origins)
                deploy = observed.get("deployment", {})
                deploy_state = str(deploy.get("state") or "unknown")
                deploy_detail = str(deploy.get("detail") or "")[:180]
            except Exception:
                deploy_state = "Host Agent status unavailable"
        origin_items = "".join(
            '<li class="cors-origin-item"><code>' + html.escape(origin) +
            '</code><form method="post" action="/api/v1/browser-origins" class="origin-remove">' +
            '<input type="hidden" name="csrf" value="' + html.escape(request.state.csrf) + '">' +
            '<input type="hidden" name="action" value="remove">' +
            '<input type="hidden" name="origin" value="' + html.escape(origin, quote=True) + '">' +
            '<input type="password" name="password" required placeholder="Superuser password" autocomplete="current-password" aria-label="Superuser password to remove origin">' +
            '<button type="submit">Remove</button></form></li>'
            for origin in host_origins
        ) or "<li>No additional browser origins authorized.</li>"
        active_label = ", ".join(active_origins) or "none (fail closed)"
        configured_label = ", ".join(host_origins) or "none"
        cors_notice = ""
        if request.query_params.get("cors") == "scheduled":
            cors_notice = ("Configuration scheduled; Core may restart. Refresh this page "
                           "to see the active allowlist and deployment state.")
        elif request.query_params.get("cors") == "unchanged":
            cors_notice = "Origin list was already in the requested state."

        latest = (self.updates.status() if self.updates is not None else {}).get("latest")
        installed = installed_release_tag()
        comparison = is_update_available(installed, latest)
        upgrade_allowed, upgrade_guidance = self._upgrade_gate()
        if comparison is False:
            upgrade_guidance = "This Core already has the newest eligible GitHub release."
        elif comparison is None and upgrade_allowed:
            upgrade_guidance = ("A newer release cannot be confirmed yet. Click Check now to refresh.")
        install_disabled = "" if upgrade_allowed and comparison is True and not (self.updates.status() if self.updates is not None else {}).get("error") else " disabled"

        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
        <title>Kali MCP — Dashboard</title><link rel="stylesheet" href="/static/app.css"></head><body>
        <header><h1>Kali MCP <small>Control Plane</small></h1>
        <nav><a href="/settings/deployment">Deployment &amp; Security</a></nav>
        <form method="post" action="/logout">
        <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}">
        <button type="submit">Logout</button></form></header>
        <main><section class="summary"><h2>Status</h2><div id="status">Loading ...</div></section>
        <section><h2>Live activity</h2><p class="muted">MCP calls, broker jobs and results tracked by the job engine.</p>
        <table><thead><tr><th>Tool</th><th>Client</th><th>State</th><th>Result</th></tr></thead><tbody id="jobs">{rows}</tbody></table></section>
        <section><h2>Execution capabilities</h2><p class="warning">Host execution is privileged by design. These switches authorize client operations, not protection from control-plane compromise.</p>
        {''.join(toggles)}</section>
        <section><h2>Updates</h2>
        <p id="updates" role="status">Installed: {html.escape(installed or "unknown")} ·
        Latest available: {html.escape(latest or "checking ...")}</p>
        <form method="post" action="/api/v1/updates/check">
        <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}"><button>Check now</button></form>
        <p class="muted">Checking GitHub only discovers releases; it never installs one.</p>
        <p id="update-guidance" class="muted" role="status">{html.escape(upgrade_guidance)}</p>
        <form method="post" action="/api/v1/updates/install">
        <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}">
        <label><input type="checkbox" name="confirm_update" value="yes" required>
        I understand this schedules an update of the native Agent and Core, including service restarts.</label>
        <button type="submit" id="install-update"{install_disabled}>Install available release</button></form></section>
        <section><h2>Authorized MCP clients</h2>
        <p class="muted">Revocation invalidates all active bearer and refresh tokens for that client.</p>
        <table><thead><tr><th>Client</th><th>ID</th><th>State</th><th>Action</th></tr></thead>
        <tbody>{client_rows}</tbody></table></section>
        <section class="api-panel"><h2>MCP Browser Origins / CORS</h2>
         <p class="muted">Only these exact HTTPS browser origins can connect directly to /mcp.
         Origin authorization is NOT an API credential. Admin endpoints remain same-origin.</p>
         <p><strong>Active in Core:</strong> <code>{html.escape(active_label)}</code></p>
         <p><strong>Saved on Host:</strong> <code>{html.escape(configured_label)}</code></p>
         <p class="muted" role="status">Deployment: {html.escape(deploy_state)}
            {html.escape(deploy_detail)} {html.escape(cors_notice)}</p>
         <ul class="cors-origins">{origin_items}</ul>
         <form method="post" action="/api/v1/browser-origins" class="cors-form">
           <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}">
           <input type="hidden" name="action" value="add">
           <label>Browser origin (exact HTTPS URL, no path)
             <input type="url" name="origin" required maxlength="255"
                    placeholder="https://llm.example.com"></label>
           <label>Confirm superuser password
             <input type="password" name="password" required autocomplete="current-password"></label>
           <button type="submit">Authorize browser origin</button>
         </form>
         <h3>Check CORS / MCP connection</h3>
         <p class="muted">Tests a real OPTIONS preflight. For SDK Host and MCP
         initialize/tools/list tests, optionally paste a valid Bearer token.
         This token is not logged, stored or shown in the result.</p>
         <form method="post" action="/api/v1/browser-origins/check" class="cors-form">
           <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}">
           <label>Browser origin to test
             <input type="url" name="origin" required maxlength="255"
                    placeholder="https://llm.example.com"></label>
           <label>Optional API Bearer token (not saved)
             <input type="password" name="bearer" maxlength="512" autocomplete="off"></label>
           <button type="submit">Check CORS</button>
         </form>
        </section>
        <section class="api-panel"><h2>MCP Clients &mdash; API Tokens</h2>
         <p>API tokens and OAuth Code + PKCE use the same /mcp endpoint. Tokens expire,
         are shown once, and do not enable host/root. For browser clients, authorize
         the origin in the section above before creating a token.</p>
         <form action="/api/v1/api-tokens/create" method="post" class="api-token-form">
           <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}">
           <label>Client name<input name="name" maxlength="80" required placeholder="llama.cpp WebUI"></label>
           <label>Expires in days (1-90)<input type="number" min="1" max="90" name="days" value="30" required></label>
           <label>Tool allowlist (blank permits all)
             <input name="allowed_tools" placeholder="system_status,tools_search"></label>
           <label>Browser origin (optional; must already be authorized)
             <input type="url" name="browser_origin" maxlength="255"
                    placeholder="https://llm.example.com"></label>
           <label>Confirm superuser password
             <input type="password" name="password" required autocomplete="current-password"></label>
           <button type="submit">Create API Token (show once)</button>
         </form>
         <div class="table-scroll" role="region" aria-label="API tokens" tabindex="0">
           <table><thead><tr><th>Client</th><th>ID</th><th>Status</th><th>Expires</th>
           <th>Last used</th><th>Tools</th><th>Action</th></tr></thead><tbody>{api_rows}</tbody></table>
         </div>
        </section>
         <section><h2>Audit</h2><pre id="audit">Loading ...</pre></section>
        </main><script src="/static/app.js?v={html.escape(installed or 'unknown', quote=True)}" defer></script></body></html>"""
        return HTMLResponse(body, headers={"Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'",
            "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"})

    async def status(self, request: Request):
        if (error := self._admin(request)):
            return error
        broker = "unknown"
        try:
            from .broker_client import call
            broker = call(self.cfg.broker_socket, "ping", timeout=2).get("broker", "unknown")
        except Exception:
            broker = "offline"
        release_status = self.updates.status()
        installed = installed_release_tag()
        comparison = is_update_available(installed, release_status.get("latest"))
        allowed, guidance = self._upgrade_gate()
        if comparison is False:
            guidance = "Already installed: the newest eligible GitHub release."
        elif comparison is None and allowed:
            guidance = ("A newer release cannot be verified yet. Click Check now; "
                        "installation remains disabled.")
        release_status = {**release_status, "installed": installed,
                          "update_available": comparison,
                          "install_allowed": allowed and comparison is True and not bool(release_status.get("error")),
                          "install_guidance": guidance}
        return JSONResponse({
            "broker": broker, "jobs": self.store.list_jobs(100),
            "audit": self.store.list_audit(25),
            "updates": release_status,
            "settings": {key: {"enabled": self.store.get_setting(key), **item}
                         for key, item in self.cfg.ceilings().items()},
        }, headers={"Cache-Control": "no-store"})

    async def settings(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        name = str(form.get("feature") or "")
        enabled = str(form.get("enabled") or "").lower() == "true"
        if enabled and name == "host_root" and str(form.get("disclaimer") or "") != "yes":
            return self._form_failure(request, "Root disclaimer must be accepted", 400)
        tracked = ("host_exec", "host_root", "package_install",
                   "network_changes", "mcp_updates")
        previous = {feature: self.store.get_setting(feature) for feature in tracked}
        try:
            self.policy.set_webui(name, enabled)
            if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() == "true" and name in tracked:
                from .broker_client import call
                provided = str(form.get("superuser_password") or "")
                if not provided:
                    raise PolicyDenied("Confirm superuser password to change host permissions")
                call(self.cfg.broker_socket, "settings_set",
                     {"feature": name, "enabled": enabled,
                      "superuser_name": request.state.admin_username,
                      "superuser_password": provided}, timeout=15)
        except Exception as exc:
            # host_exec=off also revokes root. Restore the WHOLE snapshot
            # if host authentication/IPC failed, avoiding split-brain policy.
            for feature, prior in previous.items():
                if self.store.get_setting(feature) != prior:
                    self.store.set_setting(feature, prior, "webui-rollback")
            return self._form_failure(request,
                "Setting not changed: " + str(exc)[:180], 403)
        return RedirectResponse("/", status_code=303)

    async def update_check(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        self.updates.check(force=True)
        self.store.audit("webui", "updates.check", "allow")
        return RedirectResponse("/", status_code=303)

    async def update_install(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        if str(form.get("confirm_update") or "") != "yes":
            return self._upgrade_notice("Update not started",
                                        "Administrator confirmation is required.", 400)
        allowed, guidance = self._upgrade_gate()
        if not allowed:
            self.store.audit("webui", "upgrade.request", "deny", guidance[:200])
            return self._upgrade_notice("Update blocked", guidance)
        try:
            self.policy.require("mcp_updates", actor="webui")
            checked = self.updates.check(force=True)
            if checked.get("error"):
                return self._upgrade_notice("Update check failed",
                    "GitHub could not be checked: " + str(checked["error"])[:200], 503)
            tag = checked.get("latest")
            if not tag:
                return self._upgrade_notice("Update not started",
                                            "No eligible release was returned by GitHub.", 503)
            installed = installed_release_tag()
            comparison = is_update_available(installed, tag)
            if comparison is False:
                return self._upgrade_notice("Already up to date",
                    "Installed: " + str(installed) + ". Latest available: " + str(tag) + ".", 409)
            if comparison is None:
                return self._upgrade_notice("Update not started",
                    "Cannot verify the installed version; check the Core deployment.", 503)
            result = self.jobs.submit(actor="webui", tool_id="core-upgrade",
                                      mode="systemd", operation="updates_install", payload={"tag": tag})
            self.store.audit("webui", "upgrade.request", "allow", tag)
            return RedirectResponse("/jobs/" + result["job_id"], status_code=303)
        except (PolicyDenied, ValueError) as exc:
            return self._upgrade_notice("Update blocked", str(exc))

    async def revoke_client(self, request: Request):
        if (error := self._admin(request)):
            return error
        form = await request.form()
        if (error := self._csrf(request, str(form.get("csrf") or ""))):
            return error
        try:
            done = self.store.revoke_client(str(form.get("client_id") or ""),
                                            actor="webui:" + request.state.admin_username)
        except ValueError:
            return self._form_failure(request, "Invalid client identifier", 400)
        if not done:
            return self._form_failure(request, "OAuth client not found or already revoked", 404)
        return RedirectResponse("/", status_code=303)

    async def job_report(self, request: Request):
        if (error := self._admin(request)):
            return error
        job_id = str(request.path_params["job_id"])
        job = self.store.get_job(job_id)
        if job is None:
            return HTMLResponse("Job not found", status_code=404)
        return HTMLResponse(report_html(job, self.store.job_events(job_id)),
            headers={"Cache-Control": "private, no-store",
                     "X-Content-Type-Options": "nosniff",
                     "X-Frame-Options": "DENY",
                     "Content-Security-Policy": "default-src 'none'; style-src 'self'; base-uri 'none'",
                     "Referrer-Policy": "no-referrer"})

    async def job_detail(self, request: Request):
        if (error := self._admin(request)):
            return error
        job = self.store.get_job(str(request.path_params["job_id"]))
        if job is None:
            return JSONResponse({"error": "Job not found"}, status_code=404)
        return JSONResponse(job, headers={"Cache-Control": "no-store"})

    async def events(self, request: Request):
        if (error := self._admin(request)):
            return error
        try:
            after = max(0, int(request.query_params.get("after", "0")))
        except ValueError:
            after = 0

        async def event_stream():
            current = after
            while True:
                if await request.is_disconnected():
                    break
                events = self.store.events(current, 100)
                for event in events:
                    current = event["id"]
                    yield f"id: {current}\ndata: {json.dumps(event)}\n\n"
                yield ": heartbeat\n\n"
                await asyncio.sleep(2)
        return StreamingResponse(event_stream(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    async def static(self, request: Request):
        name = str(request.path_params["name"])
        if name not in {"app.css", "app.js", "control-center.css",
                        "control-center.js"}:
            return Response(status_code=404)
        return FileResponse(Path(__file__).resolve().parent / "static" / name,
                            headers={"Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff"})
