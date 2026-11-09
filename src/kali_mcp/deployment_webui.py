"""Admin-only deployment settings: complete inventory, safe scoped edits.

All actual mutations go through the root Native Agent and fixed systemd worker.
The WebUI never reads /etc/kali-mcp, handles superuser password verification
on the Host Agent, or allows OAuth clients to write deployment settings.
"""
from __future__ import annotations

import asyncio
import html
import json
import os

from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from .deployment_settings import FIELD_MAP


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _input(key: str, label: str, value: str) -> str:
    return ('<label>' + _esc(label) + '<textarea name="' + _esc(key) +
            '" rows="2" maxlength="3072" spellcheck="false">' +
            _esc(value) + '</textarea></label>')


def render_page(request, inventory: dict) -> HTMLResponse:
    fields = inventory.get("fields", [])
    values = {item["name"]: str(item.get("value", "")) for item in fields}
    csrf = _esc(request.state.csrf)

    def value(key):
        return values.get(key, FIELD_MAP[key].default)

    selected = value("KALI_MCP_ALLOW_ALL_TARGETS")
    scope = f"""<section><h2>Authorized Scope</h2>
      <p>Decide which IPs and CIDRs the typed Kali tools may target. Blacklist
      always wins over allowlist and Allow all, including hostname resolution.</p>
      <form method="post" action="/settings/deployment" class="deployment-form">
        <input type="hidden" name="csrf" value="{csrf}">
        <input type="hidden" name="section" value="scope">
        <label>Target mode
          <select name="KALI_MCP_ALLOW_ALL_TARGETS">
            <option value="false" {'selected' if selected == 'false' else ''}>Allowlist only (default)</option>
            <option value="true" {'selected' if selected == 'true' else ''}>Allow all except blacklist</option>
          </select></label>
        {_input("KALI_MCP_ALLOWED_CIDRS", "Allowed IPs / CIDRs (comma-separated)", value("KALI_MCP_ALLOWED_CIDRS"))}
        {_input("KALI_MCP_DENIED_CIDRS", "Blacklisted IPs / CIDRs (always denied)", value("KALI_MCP_DENIED_CIDRS"))}
        <p class="warning">Allow all requires at least one blacklisted CIDR and
        an explicit confirmation. Protect excluded management networks such as
        192.168.137.0/24, if relevant. Only scan targets you are authorized to test.
        General host shells are a separate capability and may bypass adapter scope.</p>
        <label>Confirmation when Allow all is selected
          <input name="confirm" autocomplete="off" placeholder="Type ALLOW ALL"></label>
        <label>Superuser password
          <input name="password" type="password" required autocomplete="current-password"></label>
        <button type="submit">Apply Authorized Scope</button>
      </form></section>"""

    groups: dict[str, list[str]] = {}
    readonly = []
    for field in fields:
        key = str(field.get("name", ""))
        desc = _esc(field.get("description", ""))
        raw = str(field.get("value", ""))
        if field.get("editable") and field.get("group") != "Scope":
            if field.get("type") == "bool":
                selector = ('<select name="value">'
                            '<option value="false"' +
                            (' selected' if raw == "false" else '') +
                            '>false</option><option value="true"' +
                            (' selected' if raw == "true" else '') +
                            '>true</option></select>')
            else:
                selector = ('<input name="value" maxlength="255" value="' +
                            _esc(raw) + '"' +
                            ('' if field.get("type") == "dns_server" else ' required') +
                            ' spellcheck="false">')
            confirmation = ('<label>Confirmation<input name="confirm" '
                            'placeholder="ENABLE ROOT"></label>'
                            if key in {"KALI_MCP_ALLOW_HOST_ROOT",
                                       "KALI_MCP_ALLOW_MCP_ROOT"} else "")
            form = (f'<form method="post" action="/settings/deployment" class="deploy-row">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<input type="hidden" name="section" value="variable">'
                    f'<input type="hidden" name="key" value="{_esc(key)}">'
                    f'<label><strong>{_esc(key)}</strong><span class="muted">{desc}</span>'
                    f'{selector}</label>{confirmation}'
                    '<label>Superuser password<input name="password" type="password" '
                    'required autocomplete="current-password"></label>'
                    '<button type="submit">Apply</button></form>')
            groups.setdefault(str(field.get("group")), []).append(form)
        elif not field.get("editable"):
            readonly.append('<tr><td><code>' + _esc(key) +
                            '</code></td><td><code>' + _esc(raw) +
                            '</code></td><td>' + desc + '</td></tr>')
    sections = ''.join(
        '<section><h2>' + _esc(group) + '</h2>' + ''.join(forms) + '</section>'
        for group, forms in sorted(groups.items()))
    deployment = inventory.get("deployment", {})
    notice = ("A change was scheduled; check the actual deployment state below. "
              if request.query_params.get("apply") == "scheduled" else
              "Already configured. " if request.query_params.get("apply") == "unchanged"
              else "")
    body = f"""<!doctype html><html lang="en"><head>
      <meta charset="utf-8"><meta name="viewport" content="width=device-width">
      <title>Kali MCP — Deployment &amp; Security</title>
      <link rel="stylesheet" href="/static/app.css"></head><body>
      <header><h1>Kali MCP <small>Deployment &amp; Security</small></h1>
        <nav><a href="/">Return to dashboard</a></nav></header>
      <main class="deployment-page">
      <section><h2>Deployment status</h2>
        <p role="status">{_esc(notice)}
        <strong>{_esc(deployment.get("state", "not changed"))}</strong>
        {_esc(deployment.get("detail", ""))}</p>
        <p class="muted">Changes require the current WebUI session, a valid CSRF
        token and a second superuser password verification on the Native Host
        Agent. The installer settings are updated atomically and checked
        against the running services; errors trigger rollback.</p></section>
      {scope}
      {sections}
      <section><h2>Installer-managed and read-only settings</h2>
        <p class="muted">All detected Kali MCP variables are visible here.
        Secret values are hidden. Browser CORS origins are managed from the
        dashboard; system paths and identity mappings require the installer,
        not arbitrary text changes.</p>
        <div class="table-scroll"><table><thead><tr><th>Variable</th>
        <th>Value</th><th>Why read-only?</th></tr></thead>
        <tbody>{''.join(readonly)}</tbody></table></div>
      </section></main></body></html>"""
    return HTMLResponse(body, headers={
        "Cache-Control": "no-store", "Referrer-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy":
            "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'",
    })


async def view(ui, request):
    if not request.state.admin:
        return RedirectResponse("/login", status_code=303)
    if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() != "true":
        return ui._browser_notice("Unavailable", "Native Host Agent is required.", 503)
    try:
        from .broker_client import call
        result = await asyncio.to_thread(
            call, ui.cfg.broker_socket, "deployment_settings_get", timeout=5)
        return render_page(request, result)
    except RuntimeError as exc:
        return ui._browser_notice(
            "Deployment settings unavailable", str(exc)[:170], 503)


async def save(ui, request):
    if (failure := ui._admin(request)):
        return failure
    form = await request.form()
    if (failure := ui._csrf(request, str(form.get("csrf") or ""))):
        return failure
    if os.getenv("KALI_MCP_HOST_AGENT", "false").lower() != "true":
        return ui._form_failure(request, "Native Host Agent required", 403)
    section = str(form.get("section") or "")
    if section == "scope":
        keys = ("KALI_MCP_ALLOWED_CIDRS", "KALI_MCP_DENIED_CIDRS",
                "KALI_MCP_ALLOW_ALL_TARGETS")
        changes = {key: str(form.get(key) or "") for key in keys}
    elif section == "variable":
        key = str(form.get("key") or "")
        if key not in FIELD_MAP:
            return ui._form_failure(request, "This setting is installer-managed", 400)
        changes = {key: str(form.get("value") or "")}
    elif section == "batch":
        raw = str(form.get("changes") or "")
        if len(raw) > 9000:
            return ui._form_failure(request, "Too many settings in one request", 400)
        try:
            changes = json.loads(raw)
        except ValueError:
            return ui._form_failure(request, "Invalid settings payload", 400)
        if (not isinstance(changes, dict) or not (1 <= len(changes) <= 3)
                or any(not isinstance(k, str) or not isinstance(v, str)
                       for k, v in changes.items())
                or any(k not in FIELD_MAP for k in changes)
                or any(k in {"KALI_MCP_ALLOWED_CIDRS",
                             "KALI_MCP_DENIED_CIDRS",
                             "KALI_MCP_ALLOW_ALL_TARGETS"} for k in changes)):
            return ui._form_failure(request,
                "Batch can change 1–3 ordinary settings; use Authorized Scope for CIDRs", 400)
    else:
        return ui._form_failure(request, "Invalid deployment settings section", 400)
    password = str(form.get("password") or "")
    if not password or len(password) > 256:
        return ui._form_failure(request, "Superuser password confirmation required", 403)
    try:
        from .broker_client import call
        answer = await asyncio.to_thread(call, ui.cfg.broker_socket,
            "deployment_settings_update", {
                "changes": changes,
                "superuser_name": request.state.admin_username,
                "superuser_password": password,
                "confirm": str(form.get("confirm") or ""),
            }, timeout=25)
        ui.store.audit("webui:" + request.state.admin_username,
                        "deployment.update.schedule", "allow",
                        ",".join(sorted(changes))[:150])
        # The SPA needs an explicit *scheduled* result. A 303 followed by a
        # successful GET used to look like a completed settings change even
        # while the detached installer had not yet applied anything.
        if "application/json" in request.headers.get("accept", "").lower():
            scheduled = bool(answer.get("scheduled"))
            unchanged = bool(answer.get("unchanged"))
            return JSONResponse({"ok": True, "scheduled": scheduled,
                                 "unchanged": unchanged,
                                 "keys": sorted(changes)},
                                status_code=202 if scheduled else 200,
                                headers={"Cache-Control": "no-store"})
        return RedirectResponse("/settings/deployment?apply=" +
            ("unchanged" if answer.get("unchanged") else "scheduled"),
            status_code=303, headers={"Cache-Control": "no-store"})
    except (RuntimeError, ValueError) as exc:
        ui.store.audit("webui", "deployment.update", "deny", type(exc).__name__)
        return ui._form_failure(request,
            "Deployment not changed: " + str(exc)[:180], 403)
