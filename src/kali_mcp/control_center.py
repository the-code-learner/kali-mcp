"""Authenticated Control Center: approved staging design backed by real data.

The HTML shell contains zero demo data and no inline JavaScript. All data
is loaded through a same-origin, administrator-only no-store JSON snapshot.
Legacy WebUI handlers retain their existing CSRF and second-factor checks.
"""
from __future__ import annotations

import asyncio
import html
from pathlib import Path
import time

from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from .releases import installed_release_tag, is_update_available
from .deployment_settings import FIELD_MAP, READONLY_REASONS

STATIC = Path(__file__).resolve().parent / "static"
CAPABILITIES = ("host_exec", "host_root", "package_install",
                "network_changes", "mcp_updates")


async def page(ui, request):
    if not request.state.admin:
        return RedirectResponse("/login", status_code=303)
    shell = (STATIC / "control-center.html").read_text(encoding="utf-8")
    marker = '<link rel="stylesheet" href="/static/control-center.css">'
    if marker not in shell:
        raise RuntimeError("Control Center shell is incomplete")
    shell = shell.replace(marker,
        '<meta name="kali-csrf" content="' +
        html.escape(request.state.csrf, quote=True) + '">\n' + marker, 1)
    return HTMLResponse(shell, headers={
        "Cache-Control": "private, no-store",
        "Content-Security-Policy": ("default-src 'none'; script-src 'self'; "
            "style-src 'self'; connect-src 'self'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
    })


async def snapshot(ui, request):
    if (error := ui._admin(request)):
        return error
    from .broker_client import call

    async def host(op: str, *, timeout: int = 4):
        try:
            return await asyncio.to_thread(call, ui.cfg.broker_socket, op, timeout=timeout)
        except Exception:
            return {"ok": False, "error": "Native Agent temporarily unavailable"}

    # Bound per-request IPC and Core DB reads; never return secret credentials.
    agent, inventory, cors, upgrade = await asyncio.gather(
        host("ping"), host("deployment_settings_get"),
        host("browser_origins_status"), host("update_status_get"))
    release = ui.updates.status() if ui.updates is not None else {}
    installed = installed_release_tag()
    comparison = is_update_available(installed, release.get("latest"))
    allowed, guidance = ui._upgrade_gate()
    if comparison is False:
        guidance = "The latest eligible release is already installed."
    elif comparison is None and allowed:
        guidance = "Check GitHub releases first; installation is not yet verified."
    current = {name: {"enabled": ui.store.get_setting(name), **cfg}
               for name, cfg in ui.cfg.ceilings().items()}
    token_rows = ui.store.list_api_tokens(100)
    now = int(time.time())
    tokens = [{
        "name": row["name"], "id": row["token_id"],
        "status": ("Revocato" if row["revoked"] else
                   "Scaduto" if row["expires"] <= now else "Attivo"),
        "expires": row["expires"], "last_used": row.get("last_used"),
        "allowed_tools": row.get("allowed_tools", "[]"),
    } for row in token_rows]
    oauth = [{"name": row["name"], "id": row["client_id"],
              "status": "Attivo" if row["active"] else "Revocato / scaduto"}
             for row in ui.store.list_clients(100)]
    fields = inventory.get("fields", []) if inventory.get("ok") else []
    configured = cors.get("configured", []) if cors.get("ok") else []
    return JSONResponse({
        "ok": True,
        "core": {"online": True, "version": installed},
        "agent": {"online": bool(agent.get("ok")),
                  "name": agent.get("broker", "Native Host Agent")},
        "updates": {**release, "installed": installed,
                    "available": comparison, "install_allowed": bool(
                        allowed and comparison is True and not release.get("error")),
                    "guidance": guidance,
                    "run": upgrade.get("update", {"state": "unknown",
                                                 "phase": "scheduled"})},
        "deployment": inventory.get("deployment", {}),
        "fields": fields,
        "runtime": current,
        "origins": {"configured": configured,
                    "active": list(ui.cfg.browser_origins),
                    "status": cors.get("deployment", {})},
        "tokens": tokens,
        "oauth": oauth,
        "jobs": ui.store.list_jobs(100),
        "audit": ui.store.list_audit(60),
        "flags": {"admin": True, "host_agent": bool(agent.get("ok"))},
    }, headers={"Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff"})
