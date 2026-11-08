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
        "username": os.getenv("KALI_MCP_TEST_SUPERUSER_NAME", "admin"),
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
    # A private tool must receive the actual OAuth client identity.
    # Otherwise two clients might share a fallback "unknown" job namespace.
    tool_request = Request(base + "/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "jobs_list", "arguments": {"limit": 1}},
    }).encode(), method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer " + token,
        "MCP-Protocol-Version": "2025-06-18",
    })
    try:
        tool_answer = opener.open(tool_request, timeout=30)
    except HTTPError as exc:
        raise AssertionError("OAuth-scoped jobs_list failed: " + str(exc.status) + " " + exc.read().decode()[:400]) from exc
    private_result = json.load(tool_answer)
    assert "error" not in private_result, private_result
    assert not private_result.get("result", {}).get("isError"), private_result
    print("HTTP OAuth/PKCE + tools/list + scoped jobs_list passed; count:", len(names))
    # Legacy Docker smoke intentionally pins an older published release. Only
    # hybrid beta candidate smoke opts into the new API-token endpoints.
    if os.getenv("KALI_MCP_SMOKE_TEST_API_TOKENS", "").lower() == "true":
        # Verify real ASGI MCP SDK flow for API credentials on the SAME /mcp.
        page = get("/")
        assert page.status == 200, page.read()
        csrf_match = re.search(r'name="csrf" value="([^"]+)"', page.read().decode())
        assert csrf_match, "Missing WebUI CSRF"
        browser_origin = os.getenv("KALI_MCP_SMOKE_BROWSER_ORIGIN", "")
        if browser_origin:
            preflight = Request(base + "/mcp", method="OPTIONS", headers={
                "Origin": browser_origin, "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type"})
            try:
                cors_response = opener.open(preflight, timeout=15)
            except HTTPError as exc:
                raise AssertionError("MCP preflight rejected: " + str(exc.status)) from exc
            assert cors_response.status == 204
            assert cors_response.headers.get("Access-Control-Allow-Origin") == browser_origin

        api_created = post("/api/v1/api-tokens/create", {
            "csrf": csrf_match.group(1),
            "password": password,
            "name": "CI smoke llama.cpp",
            "days": "1",
            "allowed_tools": "system_status",
        })
        assert api_created.status == 200, api_created.read()
        api_html = api_created.read().decode("utf-8")
        secret_match = re.search(r"kmp_[0-9a-f]{32}\.[A-Za-z0-9_-]{64}", api_html)
        assert secret_match, "API token not visible in one-time response"
        api_secret = secret_match.group(0)
        token_match = re.search(r"Credential ID: <code>([0-9a-f]{32})</code>", api_html)
        assert token_match
        api_id = token_match.group(1)

        def mcp_call(method, headers, name=None):
            if method == "initialize":
                params = {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "beta5-ci", "version": "1.0"}}
            else:
                params = {"name": name, "arguments": {}} if method == "tools/call" else {}
            request = Request(base + "/mcp", data=json.dumps({
                "jsonrpc": "2.0", "id": 25, "method": method, "params": params,
            }).encode(), method="POST", headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-06-18",
                **headers})
            try:
                return opener.open(request, timeout=30)
            except HTTPError as exc:
                return exc

        api_initialize = mcp_call("initialize", {"Authorization": "Bearer " + api_secret})
        # MCP initialize needs protocol/capability metadata, provided below by mcp_call.
        assert api_initialize.status == 200, api_initialize.read()
        assert "serverInfo" in json.load(api_initialize)["result"]
        accepted_tool = mcp_call("tools/call", {"Authorization": "Bearer " + api_secret}, "system_status")
        assert accepted_tool.status == 200, accepted_tool.read()
        assert not json.load(accepted_tool).get("error")
        api_list = mcp_call("tools/list", {"Authorization": "Bearer " + api_secret})
        assert api_list.status == 200, api_list.read()
        assert "system_status" in [t["name"] for t in json.load(api_list)["result"]["tools"]]
        custom_list = mcp_call("tools/list", {"X-Kali-MCP-API-Key": api_secret})
        assert custom_list.status == 200, custom_list.read()
        assert "system_status" in [t["name"] for t in json.load(custom_list)["result"]["tools"]]
        blocked = mcp_call("tools/call", {"Authorization": "Bearer " + api_secret}, "terminal_open")
        assert blocked.status == 403, blocked.read()
        revoked = post("/api/v1/api-tokens/revoke", {
            "csrf": csrf_match.group(1), "password": password, "token_id": api_id})
        assert revoked.status == 303, revoked.read()
        invalidated = mcp_call("tools/list", {"Authorization": "Bearer " + api_secret})
        assert invalidated.status == 401, invalidated.read()
        print("HTTP OAuth/PKCE + API Bearer/custom-header + revocation passed; tools:", len(names))


if __name__ == "__main__":
    main()
