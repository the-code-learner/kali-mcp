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
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse, FileResponse

from .config import Config
from .policy import Policy, PolicyDenied
from .releases import UpdateChecker
from .store import Store, digest
from .jobs import Jobs
from .reports import report_html


def _csrf_for(cookie: str, password: str) -> str:
    return hmac.new(password.encode(), cookie.encode(), hashlib.sha256).hexdigest()


class Admin:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store
        self.failures: dict[str, tuple[int, float]] = {}

    def authenticate_request(self, request: Request) -> tuple[bool, str]:
        request.state.admin = False
        request.state.csrf = ""
        cookie = request.cookies.get("kali_admin", "")
        if not cookie:
            return False, ""
        with self.store.lock:
            row = self.store.db.execute(
                "SELECT * FROM admin_sessions WHERE hash=? AND expires>?", (digest(cookie), int(time.time()))).fetchone()
        if not row:
            return False, ""
        csrf = _csrf_for(cookie, self.cfg.admin_password)
        if not secrets.compare_digest(row["csrf_hash"], digest(csrf)):
            return False, ""
        request.state.admin = True
        request.state.csrf = csrf
        return True, csrf

    async def login_get(self, request: Request) -> HTMLResponse:
        nxt = request.query_params.get("next", "/")
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = "/"
        return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8"><title>Kali MCP Login</title>
          <meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/static/app.css"></head>
          <body><main class="login"><h1>Kali MCP</h1>
          <p>Administrator login</p>
          <form method="post" action="/login">
            <input type="hidden" name="next" value="{html.escape(nxt,quote=True)}">
            <label>Administrator password<input type="password" name="password" required autocomplete="current-password"></label>
            <button type="submit">Sign in</button></form></main></body></html>""",
            headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'"})

    async def login_post(self, request: Request):
        if not self.cfg.admin_password or len(self.cfg.admin_password) < 16:
            return JSONResponse({"error": "Configure KALI_MCP_ADMIN_PASSWORD (16+ characters) in the private YAML stack"}, status_code=503)
        source = request.client.host if request.client else "unknown"
        count, until = self.failures.get(source, (0, 0.0))
        if until > time.monotonic():
            return JSONResponse({"error": "Too many attempts"}, status_code=429)
        form = await request.form()
        password = str(form.get("password") or "")
        if not secrets.compare_digest(password, self.cfg.admin_password):
            count += 1
            self.failures[source] = (count, time.monotonic() + min(300, 2 ** min(count, 8)))
            self.store.audit(source, "admin.login", "deny", "password mismatch")
            return HTMLResponse("Invalid credentials", status_code=401)
        self.failures.pop(source, None)
        cookie = secrets.token_urlsafe(48)
        csrf = _csrf_for(cookie, self.cfg.admin_password)
        with self.store.transaction():
            self.store.db.execute("INSERT INTO admin_sessions VALUES(?,?,?)", (digest(cookie), digest(csrf), int(time.time()) + 8 * 3600))
            self.store._audit(source, "admin.login", "allow")
        nxt = str(form.get("next") or "/")
        if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
            nxt = "/"
        response = RedirectResponse(nxt, status_code=303)
        response.set_cookie("kali_admin", cookie, httponly=True, secure=self.cfg.base_url.startswith("https:"),
                            samesite="lax", max_age=8 * 3600, path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    async def logout(self, request: Request):
        cookie = request.cookies.get("kali_admin", "")
        if cookie:
            with self.store.lock:
                self.store.db.execute("DELETE FROM admin_sessions WHERE hash=?", (digest(cookie),))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("kali_admin")
        return response


class UI:
    def __init__(self, cfg: Config, store: Store, policy: Policy, jobs: Jobs, updates: UpdateChecker):
        self.cfg, self.store, self.policy, self.jobs, self.updates = cfg, store, policy, jobs, updates

    def _admin(self, request: Request):
        if not request.state.admin:
            return JSONResponse({"error": "Administrator login required"}, status_code=401,
                headers={"Cache-Control": "no-store"})
        return None

    def _csrf(self, request: Request, submitted: str):
        if not request.state.csrf or not secrets.compare_digest(request.state.csrf, submitted):
            return JSONResponse({"error": "Invalid CSRF token"}, status_code=403)
        return None

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
              <button type="submit" {disabled}>{'Disable' if active else 'Enable'}</button>
            </form>""")
        rows = "".join(f"<tr><td>{html.escape(j['tool_id'])}</td><td>{html.escape(j['actor'])}</td><td>{html.escape(j['state'])}</td><td><a href='/jobs/{j['id']}'>{j['id'][:12]}</a></td></tr>"
                       for j in self.store.list_jobs(30))
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
        <title>Kali MCP — Dashboard</title><link rel="stylesheet" href="/static/app.css"></head><body>
        <header><h1>Kali MCP <small>Control Plane</small></h1><a href="/logout">Logout</a></header>
        <main><section class="summary"><h2>Status</h2><div id="status">Loading ...</div></section>
        <section><h2>Live activity</h2><p class="muted">MCP calls, broker jobs and results tracked by the job engine.</p>
        <table><thead><tr><th>Tool</th><th>Client</th><th>State</th><th>Result</th></tr></thead><tbody id="jobs">{rows}</tbody></table></section>
        <section><h2>Execution capabilities</h2><p class="warning">The native Host Agent has privileged host authority. These switches are authorization controls, not a hardened isolation guarantee.</p>
        {''.join(toggles)}</section>
        <section><h2>Updates</h2><p id="updates">Checking ...</p>
        <form method="post" action="/api/v1/updates/check">
        <input type="hidden" name="csrf" value="{html.escape(request.state.csrf)}"><button>Check now</button></form>
        <p class="muted">Update installation is manual. A release is never installed automatically.</p></section>
        <section><h2>Audit</h2><pre id="audit">Loading ...</pre></section>
        </main><script src="/static/app.js" defer></script></body></html>"""
        return HTMLResponse(body, headers={"Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'",
            "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})

    async def status(self, request: Request):
        if (error := self._admin(request)):
            return error
        broker = "unknown"
        try:
            from .broker_client import call
            broker = call(self.cfg.broker_socket, "ping", timeout=2).get("broker", "unknown")
        except Exception:
            broker = "offline"
        return JSONResponse({
            "broker": broker, "jobs": self.store.list_jobs(100),
            "audit": self.store.list_audit(25),
            "updates": self.updates.status(),
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
            return JSONResponse({"error": "Root disclaimer must be accepted"}, status_code=400)
        previous = self.store.get_setting(name)
        try:
            self.policy.set_webui(name, enabled)
            if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() == "true" and name in {
                    "host_exec", "host_root", "package_install", "network_changes"}:
                from .broker_client import call
                try:
                    call(self.cfg.broker_socket, "settings_set",
                         {"feature": name, "enabled": enabled}, timeout=6)
                except Exception:
                    self.store.set_setting(name, previous, "webui-rollback")
                    raise
        except (PolicyDenied, Exception) as exc:
            return JSONResponse({"error": str(exc)[:300]}, status_code=403)
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
        if name not in {"app.css", "app.js"}:
            return Response(status_code=404)
        return FileResponse(Path(__file__).resolve().parent / "static" / name,
                            headers={"Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff"})
