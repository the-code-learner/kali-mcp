"""Exercise real HTTP OAuth consent and a Bearer-protected MCP tools/list.

CI-only integration helper. Running it creates a disposable OAuth client and
administrative session. Do not run it repeatedly against a production instance.
"""
from __future__ import annotations

import base64
import hashlib
from http.cookiejar import CookieJar
import json
import os
import re
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPCookieProcessor, Request


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    base = os.getenv("KALI_MCP_SMOKE_URL", "http://127.0.0.1:8787")
    password = os.environ["KALI_MCP_TEST_ADMIN_PASSWORD"]
    opener = build_opener(HTTPCookieProcessor(CookieJar()), NoRedirect())

    def get(path, headers=None):
        try:
            return opener.open(Request(base + path, headers=headers or {}), timeout=15)
        except HTTPError as exc:
            return exc

    def post(path, values, *, json_body=False, headers=None):
        if json_body:
            data = json.dumps(values).encode("utf-8")
            content_type = "application/json"
        else:
            data = urlencode(values).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"
        req = Request(base + path, data=data, method="POST",
            headers={"Content-Type": content_type, **(headers or {})})
        try:
            return opener.open(req, timeout=25)
        except HTTPError as exc:
            return exc

    metadata = json.load(get("/.well-known/oauth-authorization-server"))
    resource = metadata["issuer"] + "/mcp"
    registered = post("/register", {
        "client_name": "Kali MCP smoke test",
        "redirect_uris": ["http://127.0.0.1:19999/callback"],
    }, json_body=True)
    assert registered.status == 201, registered.read()
    client_id = json.load(registered)["client_id"]
    verifier = "s" * 55
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode("ascii")
    params = {
        "client_id": client_id,
        "redirect_uri": "http://127.0.0.1:19999/callback",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "smoke-state-123",
        "scope": "mcp:tools",
        "resource": resource,
    }
    authorization = get("/authorize?" + urlencode(params))
    assert authorization.status == 303, authorization.read()
    login = post("/login", {
        "password": password, "next": "/authorize?" + urlencode(params),
    })
    assert login.status == 303, login.read()
    consent = get("/authorize?" + urlencode(params))
    assert consent.status == 200, consent.read()
    html = consent.read().decode("utf-8")
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match, "Missing administrator consent CSRF"
    approved = post("/authorize", {**params, "csrf": match.group(1)})
    assert approved.status == 303, approved.read()
    query = parse_qs(urlsplit(approved.headers["location"]).query)
    assert query["state"] == ["smoke-state-123"]
    exchanged = post("/token", {
        "grant_type": "authorization_code",
        "code": query["code"][0],
        "client_id": client_id,
        "redirect_uri": params["redirect_uri"],
        "code_verifier": verifier,
        "resource": resource,
    })
    assert exchanged.status == 200, exchanged.read()
    token = json.load(exchanged)["access_token"]
    req = Request(base + "/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    }).encode(), method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer " + token,
        "MCP-Protocol-Version": "2025-06-18",
    })
    try:
        answer = opener.open(req, timeout=30)
    except HTTPError as exc:
        raise AssertionError("MCP HTTP call failed: " + str(exc.status) + " " + exc.read().decode()[:400]) from exc
    payload = json.load(answer)
    names = [item["name"] for item in payload.get("result", {}).get("tools", [])]
    assert "system_status" in names and "scripts_execute" in names, names
    print("HTTP OAuth/PKCE + authenticated tools/list succeeded; tool count:", len(names))


if __name__ == "__main__":
    main()
