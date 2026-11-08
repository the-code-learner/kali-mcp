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
    auth_tokens = json.load(exchanged)
    token = auth_tokens["access_token"]
    refresh_token = auth_tokens["refresh_token"]
    # Cloudflare/browser HTTPS requests usually omit :443 from the Host
    # header. The SDK must accept a bare Host as well as a Host:port value.
    bare_host = os.getenv("KALI_MCP_SMOKE_HOST", urlsplit(base).hostname or "localhost")
    oauth_host = (bare_host if os.getenv("KALI_MCP_SMOKE_TEST_API_TOKENS", "").lower() == "true"
                  else (urlsplit(base).netloc or bare_host))
    req = Request(base + "/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    }).encode(), method="POST", headers={
        "Host": oauth_host, "Content-Type": "application/json",
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
        "Host": oauth_host, "Content-Type": "application/json",
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
        # Refresh the OAuth PKCE authorization before independently testing
        # API keys on the same endpoint; refresh replay must revoke its family.
        rotated = post("/token", {"grant_type": "refresh_token",
            "refresh_token": refresh_token, "client_id": client_id,
            "resource": resource})
        assert rotated.status == 200, rotated.read()
        refreshed_access = json.load(rotated)["access_token"]
        refreshed_request = Request(base + "/mcp", data=json.dumps({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {},
        }).encode(), method="POST", headers={
            "Host": bare_host, "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer " + refreshed_access,
            "MCP-Protocol-Version": "2025-06-18",
        })
        assert opener.open(refreshed_request, timeout=30).status == 200
        replayed = post("/token", {"grant_type": "refresh_token",
            "refresh_token": refresh_token, "client_id": client_id,
            "resource": resource})
        assert replayed.status == 400, replayed.read()
        # Verify real ASGI MCP SDK flow for API credentials on the SAME /mcp.
        page = get("/")
        assert page.status == 200, page.read()
        dashboard = page.read().decode()
        assert "Kali MCP" in dashboard and "Control Center" in dashboard
        # The production Control Center uses a non-executable meta CSRF token
        # rather than embedding hundreds of sensitive forms in its HTML shell.
        csrf_match = re.search(r'<meta name="kali-csrf" content="([^"]+)"', dashboard)
        assert csrf_match, "Missing Control Center CSRF"
        snapshot = get("/api/v1/ui/snapshot")
        assert snapshot.status == 200, snapshot.read()
        live_data = json.load(snapshot)
        assert live_data["ok"] and "jobs" in live_data and "runtime" in live_data
        assert "updates" in live_data and "run" in live_data["updates"]
        browser_origin = os.getenv("KALI_MCP_SMOKE_BROWSER_ORIGIN", "")
        if browser_origin:
            preflight = Request(base + "/mcp", method="OPTIONS", headers={
                "Host": bare_host, "Origin": browser_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers":
                    "authorization,content-type,mcp-protocol-version"})
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
            "allowed_tools": "system_status,files_upload,files_upload_chunk,files_upload_finish,files_download,files_list,files_delete,jobs_export",
        })
        assert api_created.status == 200, api_created.read()
        api_html = api_created.read().decode("utf-8")
        secret_match = re.search(r"kmp_[0-9a-f]{32}\.[A-Za-z0-9_-]{64}", api_html)
        assert secret_match, "API token not visible in one-time response"
        api_secret = secret_match.group(0)
        token_match = re.search(r"Credential ID: <code>([0-9a-f]{32})</code>", api_html)
        assert token_match
        api_id = token_match.group(1)

        def mcp_call(method, headers, name=None, arguments=None):
            if method == "initialize":
                params = {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "beta5-ci", "version": "1.0"}}
            else:
                params = {"name": name, "arguments": arguments or {}} if method == "tools/call" else {}
            request = Request(base + "/mcp", data=json.dumps({
                "jsonrpc": "2.0", "id": 25, "method": method, "params": params,
            }).encode(), method="POST", headers={
                "Host": bare_host,
                **({"Origin": browser_origin} if browser_origin else {}),
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
        # Real MCP JSON-RPC file tools, not only vault unit tests.
        def file_tool(name, arguments):
            resp = mcp_call("tools/call",
                            {"Authorization": "Bearer " + api_secret},
                            name, arguments)
            assert resp.status == 200, (name, resp.read()[:400])
            document = json.load(resp)
            assert not document.get("error"), (name, document)
            assert not document["result"].get("isError"), (name, document)
            result = document["result"]
            if isinstance(result.get("structuredContent"), dict):
                body = result["structuredContent"]
            else:
                body = json.loads(result["content"][0]["text"])
            assert body["ok"] is True, (name, body)
            return body

        small = b"CI MCP small transfer, binary: " + bytes([0, 0xff, 0x80])
        created = file_tool("files_upload", {
            "name": "ci-small.bin", "mode": "base64",
            "data_base64": base64.b64encode(small).decode()})
        retrieved = file_tool("files_download", {
            "file_id": created["file_id"], "mode": "base64"})
        assert base64.b64decode(retrieved["data_base64"]) == small
        assert retrieved["done"] is True

        # Use Base64 chunking for a file that cannot fit in a single MCP POST.
        source = b"CI-CHUNKED" * 18000
        opened = file_tool("files_upload", {
            "name": "ci-chunked.bin", "mode": "base64", "size_bytes": len(source)})
        offset = 0
        while offset < len(source):
            part = source[offset:offset + opened["chunk_bytes"]]
            answer = file_tool("files_upload_chunk", {
                "file_id": opened["file_id"], "offset": offset,
                "data_base64": base64.b64encode(part).decode()})
            offset = answer["written"]
        completed = file_tool("files_upload_finish", {"file_id": opened["file_id"]})
        assert completed["sha256"] == hashlib.sha256(source).hexdigest()
        downloaded_parts = []
        offset = 0
        while True:
            part = file_tool("files_download", {
                "file_id": opened["file_id"], "mode": "base64", "offset": offset})
            downloaded_parts.append(base64.b64decode(part["data_base64"]))
            offset = part["next_offset"]
            if part["done"]:
                break
        assert b"".join(downloaded_parts) == source

        # OpenLink: grant only a short-lived signed PUT/GET, no host file access.
        contents = b"\x00binary openlink transfer on Core\xff"
        upload = file_tool("files_upload", {
            "name": "ci-openlink.bin", "mode": "openlink", "size_bytes": len(contents)})
        put_req = Request(base + urlsplit(upload["upload_url"]).path, method="PUT",
            data=contents, headers={
                "Host": bare_host, "Content-Type": "application/octet-stream",
                **({"Origin": browser_origin} if browser_origin else {})})
        pushed = opener.open(put_req, timeout=20)
        assert pushed.status == 201 and json.load(pushed)["bytes"] == len(contents)
        signed = file_tool("files_download", {
            "file_id": upload["file_id"], "mode": "openlink"})
        download_url = base + urlsplit(signed["url"]).path
        get_headers = {"Host": bare_host, **({"Origin": browser_origin} if browser_origin else {})}
        pulled = opener.open(Request(download_url, headers=get_headers), timeout=20)
        assert pulled.status == 200 and pulled.read() == contents
        try:
            opener.open(Request(download_url, headers=get_headers), timeout=20)
        except HTTPError as exc:
            assert exc.status == 404
        else:
            raise AssertionError("Signed OpenLink download reused successfully")
        assert file_tool("files_delete", {"file_id": upload["file_id"]})["ok"] is True
        print("MCP file transfers: Base64 inline/chunked, OpenLink PUT/GET and one-use tokens passed")

        blocked = mcp_call("tools/call", {"Authorization": "Bearer " + api_secret}, "terminal_open")
        assert blocked.status == 403, blocked.read()
        invalid_bearer = mcp_call("tools/list", {"Authorization": "Bearer " + api_secret + "bad"})
        assert invalid_bearer.status == 401, invalid_bearer.read()
        if browser_origin:
            denied_origin = mcp_call("tools/list", {
                "Authorization": "Bearer " + api_secret,
                "Origin": "https://untrusted.example.test"})
            assert denied_origin.status == 403, denied_origin.read()
        bad_host = mcp_call("tools/list", {
            "Authorization": "Bearer " + api_secret, "Host": "evil.example.test"})
        assert bad_host.status in (400, 421), bad_host.read()
        revoked = post("/api/v1/api-tokens/revoke", {
            "csrf": csrf_match.group(1), "password": password, "token_id": api_id})
        assert revoked.status == 303, revoked.read()
        invalidated = mcp_call("tools/list", {"Authorization": "Bearer " + api_secret})
        assert invalidated.status == 401, invalidated.read()
        print("HTTP OAuth/PKCE + API Bearer/custom-header + revocation passed; tools:", len(names))


if __name__ == "__main__":
    main()
