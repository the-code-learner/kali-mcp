"""Public HTTPS host without :443 must survive the real MCP SDK gate."""
from __future__ import annotations

import asyncio
import pytest
from starlette.requests import Request

from kali_mcp.browser_origins import parse_browser_origins, validate_browser_origin


@pytest.mark.parametrize("raw", [
    "https://llm.example.test/path",
    "https://llm.example.test/",
    "https://llm.example.test?foo=bar",
    "https://*.example.test",
    "http://example.test",
    "null",
    "*",
    "https://user@example.test",
    "https://llm.example.test:99999",
    "https://llm.example.test:000443",
    "https://LLM.example.test",
    "https://bad host.example",
])
def test_reject_ambiguous_or_insecure_origins(raw):
    with pytest.raises(ValueError):
        validate_browser_origin(raw)


def test_exact_https_origin_and_bounded_list():
    assert parse_browser_origins("") == ()
    assert parse_browser_origins(
        "https://llm.example.test,https://llm.example.test:8443"
    ) == ("https://llm.example.test", "https://llm.example.test:8443")
    assert validate_browser_origin("http://localhost:9080") == "http://localhost:9080"
    for invalid in (
        "https://llm.example.test,https://llm.example.test",
        ",".join("https://sub%d.example.test" % n for n in range(13)),
    ):
        with pytest.raises(ValueError):
            parse_browser_origins(invalid)


def test_sdk_actual_host_and_origin_validation_for_public_https(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))
    from kali_mcp import runtime
    from mcp.server.transport_security import (
        TransportSecurityMiddleware, TransportSecuritySettings)

    allowed_hosts = runtime.sdk_allowed_hosts("https://kali-mcp.warebench.com")
    assert "kali-mcp.warebench.com" in allowed_hosts
    assert "kali-mcp.warebench.com:*" in allowed_hosts
    assert "*" not in allowed_hosts
    settings = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=["https://llm.davidecasalin.it"],
    )
    middleware = TransportSecurityMiddleware(settings)

    def verify(host, origin="https://llm.davidecasalin.it"):
        scope = {
            "type": "http", "method": "POST", "scheme": "https",
            "path": "/mcp", "raw_path": b"/mcp", "query_string": b"",
            "http_version": "1.1", "root_path": "",
            "server": ("kali-mcp.warebench.com", 443),
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"host", host.encode("ascii")),
                (b"origin", origin.encode("ascii")),
                (b"content-type", b"application/json"),
            ],
        }
        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}
        return asyncio.run(middleware.validate_request(
            Request(scope, receive), is_post=True))

    # Reproduces the beta.7 421: the SDK accepted :443 but rejected a bare
    # public Host, despite the outer CORS OPTIONS preflight passing.
    assert verify("kali-mcp.warebench.com") is None
    assert verify("kali-mcp.warebench.com:443") is None
    assert verify("kali-mcp.warebench.com:9443") is None
    assert verify("evil.example.test").status_code == 421
    assert verify("kali-mcp.warebench.com", "https://evil.example").status_code == 403
