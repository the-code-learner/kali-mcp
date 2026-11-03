"""Self-hosted OAuth authorization server with PKCE S256, DCR and hashed tokens.

The administrator must authenticate in the browser before approving a client.
Cloudflare Access bypasses should cover only the OAuth/MCP paths documented in
docs/CLOUDFLARE.md; all remote administrative paths remain behind Access.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets
import time
from urllib.parse import urlparse, urlencode
from uuid import uuid4

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from .config import Config
from .store import Store, digest

PKCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
SCOPE = "mcp:tools"
TOKEN_AGE = 900
REFRESH_AGE = 30 * 86400


def _err(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers={"Cache-Control": "no-store"})


def redirect_ok(uri: str) -> bool:
    try:
        parsed = urlparse(uri)
        if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
            return False
        if parsed.scheme == "https":
            return True
        return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    except ValueError:
        return False


class OAuth:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store

    def protected_resource(self, request: Request) -> JSONResponse:
        return JSONResponse({
            "resource": self.cfg.resource,
            "authorization_servers": [self.cfg.base_url],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
        }, headers={"Cache-Control": "public, max-age=300"})

    def metadata(self, request: Request) -> JSONResponse:
        base = self.cfg.base_url
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token",
            "registration_endpoint": base + "/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": [SCOPE],
        }, headers={"Cache-Control": "public, max-age=300"})

    async def register(self, request: Request) -> JSONResponse:
        try:
            raw = await request.body()
            if len(raw) > 8192:
                return _err("invalid_client_metadata", 413)
            payload = json.loads(raw)
            uris = payload["redirect_uris"]
            if not isinstance(uris, list) or not (1 <= len(uris) <= 10) or not all(isinstance(x, str) and len(x) <= 2048 and redirect_ok(x) for x in uris):
                return _err("invalid_redirect_uri")
            if payload.get("token_endpoint_auth_method", "none") != "none":
                return _err("unsupported_token_auth_method")
            name = str(payload.get("client_name") or "MCP client")[:120]
            with self.store.transaction():
                total = self.store.db.execute("SELECT count(*) AS n FROM oauth_clients").fetchone()["n"]
                if total >= 200:
                    return _err("registration_limit_reached", 429)
                client_id = uuid4().hex
                self.store.db.execute(
                    "INSERT INTO oauth_clients VALUES (?,?,?,?)",
                    (client_id, name, json.dumps(uris), str(int(time.time()))))
                self.store._audit("oauth", "client.register", "allow", client_id)
            return JSONResponse({"client_id": client_id, "client_name": name,
                "redirect_uris": uris, "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"]}, status_code=201, headers={"Cache-Control": "no-store"})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return _err("invalid_client_metadata")

    def _validate_authorize(self, values) -> tuple[str, str, str, str, str, str]:
        client_id = str(values.get("client_id") or "")
        redirect_uri = str(values.get("redirect_uri") or "")
        challenge = str(values.get("code_challenge") or "")
        state = str(values.get("state") or "")
        resource = str(values.get("resource") or "")
        scope = str(values.get("scope") or SCOPE)
        if values.get("response_type") != "code" or values.get("code_challenge_method") != "S256":
            raise ValueError("Only authorization code + PKCE S256 are supported")
        if not PKCE_PATTERN.fullmatch(challenge) or not state or len(state) > 512:
            raise ValueError("Invalid PKCE challenge or state")
        if resource != self.cfg.resource or scope != SCOPE:
            raise ValueError("Invalid resource or scope")
        with self.store.lock:
            row = self.store.db.execute("SELECT * FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()
        if not row or redirect_uri not in json.loads(row["redirect_uris"]):
            raise ValueError("Unregistered client or redirect URI")
        return client_id, redirect_uri, challenge, state, resource, scope

    async def authorize_get(self, request: Request):
        try:
            self._validate_authorize(request.query_params)
        except ValueError as exc:
            return HTMLResponse(html.escape(str(exc)), status_code=400)
        if not request.state.admin:
            next_url = request.url.path + "?" + request.url.query
            return RedirectResponse("/login?" + urlencode({"next": next_url}), status_code=303)
        params = request.query_params
        fields = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(str(params.get(k) or ""), quote=True)}">'
                         for k in ("client_id", "redirect_uri", "response_type", "code_challenge",
                                   "code_challenge_method", "state", "scope", "resource"))
        return HTMLResponse(f"""<!doctype html><meta charset="utf-8"><title>Authorize Kali MCP</title>
            <meta name="referrer" content="no-referrer">
            <style>body{{font:16px system-ui;max-width:38rem;margin:5rem auto;padding:1rem;line-height:1.6;background:#121723;color:#f3f5f8}}button{{padding:1rem}}</style>
            <h1>Authorize MCP client</h1><p>Client: <b>{html.escape(params["client_id"])}</b></p>
            <p>This client will have access to the MCP tool surface, subject to current administrator toggles and YAML ceilings.
            Root and host execution remain separate administrator-controlled settings.</p>
            <form action="/authorize" method="post">{fields}
            <input type="hidden" name="csrf" value="{html.escape(request.state.csrf,quote=True)}">
            <button type="submit">Authorize client</button></form>""",
            headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"})

    async def authorize_post(self, request: Request):
        if not request.state.admin:
            return _err("login_required", 401)
        form = await request.form()
        if not request.state.csrf or not secrets.compare_digest(str(form.get("csrf") or ""), request.state.csrf):
            return _err("invalid_csrf", 403)
        try:
            client_id, redirect_uri, challenge, state, resource, scope = self._validate_authorize(form)
        except ValueError as exc:
            return _err(str(exc))
        code = secrets.token_urlsafe(48)
        with self.store.transaction():
            self.store.db.execute("INSERT INTO oauth_codes VALUES (?,?,?,?,?,?,?)",
                (digest(code), client_id, redirect_uri, challenge, resource, scope, int(time.time()) + 120))
            self.store._audit("webui", "client.authorize", "allow", client_id)
        return RedirectResponse(redirect_uri + ("&" if "?" in redirect_uri else "?") +
            urlencode({"code": code, "state": state}), status_code=303,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    async def token(self, request: Request) -> JSONResponse:
        try:
            form = await request.form()
            grant = str(form.get("grant_type", ""))
            client_id = str(form.get("client_id", ""))
            resource = str(form.get("resource", ""))
            if resource != self.cfg.resource:
                return _err("invalid_target")
            now = int(time.time())
            if grant == "authorization_code":
                code = str(form.get("code", ""))
                verifier = str(form.get("code_verifier", ""))
                uri = str(form.get("redirect_uri", ""))
                if not PKCE_PATTERN.fullmatch(verifier):
                    return _err("invalid_grant")
                with self.store.transaction():
                    row = self.store.db.execute("SELECT * FROM oauth_codes WHERE hash=?", (digest(code),)).fetchone()
                    if not row or row["expires"] < now or row["client_id"] != client_id or row["redirect_uri"] != uri or row["resource"] != resource:
                        return _err("invalid_grant")
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                    if not secrets.compare_digest(challenge, row["challenge"]):
                        return _err("invalid_grant")
                    self.store.db.execute("DELETE FROM oauth_codes WHERE hash=?", (digest(code),))
                    family = uuid4().hex
                    scope = row["scope"]
            elif grant == "refresh_token":
                refresh = str(form.get("refresh_token", ""))
                with self.store.transaction():
                    row = self.store.db.execute("SELECT * FROM oauth_tokens WHERE hash=? AND kind='refresh'", (digest(refresh),)).fetchone()
                    if not row or row["revoked"] or row["expires"] < now or row["client_id"] != client_id or row["resource"] != resource:
                        return _err("invalid_grant")
                    # Rotation and family revocation: a replay attempts to reuse a revoked refresh token.
                    self.store.db.execute("UPDATE oauth_tokens SET revoked=1 WHERE hash=?", (digest(refresh),))
                    family, scope = row["family"], row["scope"]
            else:
                return _err("unsupported_grant_type")
            access = secrets.token_urlsafe(48)
            refresh = secrets.token_urlsafe(48)
            with self.store.transaction():
                self.store.db.execute("INSERT INTO oauth_tokens VALUES (?,?,?,?,?,?,0,?)",
                    (digest(access), client_id, "access", scope, resource, now + TOKEN_AGE, family))
                self.store.db.execute("INSERT INTO oauth_tokens VALUES (?,?,?,?,?,?,0,?)",
                    (digest(refresh), client_id, "refresh", scope, resource, now + REFRESH_AGE, family))
            return JSONResponse({"access_token": access, "token_type": "Bearer",
                "expires_in": TOKEN_AGE, "refresh_token": refresh, "scope": scope},
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        except Exception:
            return _err("invalid_request")

    def verify_bearer(self, token: str) -> str | None:
        if not token or len(token) > 256:
            return None
        with self.store.lock:
            row = self.store.db.execute(
                "SELECT client_id FROM oauth_tokens WHERE hash=? AND kind='access' AND resource=? AND scope=? AND revoked=0 AND expires>?",
                (digest(token), self.cfg.resource, SCOPE, int(time.time()))).fetchone()
        return str(row["client_id"]) if row else None
