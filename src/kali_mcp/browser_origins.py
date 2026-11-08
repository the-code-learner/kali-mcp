"""Exact, bounded browser-Origin allowlist for the MCP HTTP endpoint only.

This module is shared by the Core, the root-owned Host Agent and the wizard.
It never accepts a wildcard or opaque/null Origin.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_BROWSER_ORIGINS = 12
_MAX_ORIGIN_LEN = 255
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def validate_browser_origin(origin: str) -> str:
    if not isinstance(origin, str) or not origin or len(origin) > _MAX_ORIGIN_LEN:
        raise ValueError("Browser origin is required (max 255 characters)")
    if origin != origin.strip() or any(ord(ch) < 33 or ord(ch) > 126 for ch in origin):
        raise ValueError("Browser origins must be plain ASCII HTTPS origins without whitespace")
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid browser origin hostname or port") from exc
    if (parsed.scheme not in {"https", "http"} or not host or
            parsed.username is not None or parsed.password is not None or
            parsed.path or parsed.query or parsed.fragment or
            parsed.netloc != parsed.netloc.lower() or
            not origin.startswith(parsed.scheme + "://")):
        raise ValueError("Browser origin must be an exact scheme://host[:port], without a path")
    # No mixed Unicode/IDNA homographs, globbed DNS labels, zone IDs or userinfo.
    if host not in _LOOPBACK:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if (len(host) > 253 or not all(_DOMAIN_LABEL.fullmatch(part)
                                            for part in host.split("."))):
                raise ValueError("Browser origin hostname is not a valid DNS name")
    if parsed.scheme == "http" and host not in _LOOPBACK:
        raise ValueError("Browser origins must use HTTPS (except localhost)")
    if ":" in host:
        if not parsed.netloc.startswith("[" + host + "]"):
            raise ValueError("IPv6 browser origin requires brackets")
    else:
        expected = host + (":" + str(port) if port is not None else "")
        if parsed.netloc != expected:
            raise ValueError("Browser origin host or port is not canonical")
    return origin


def parse_browser_origins(value: str) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise ValueError("Browser origins must be a comma-separated string")
    if not value.strip():
        return ()
    items = [part.strip() for part in value.split(",")]
    if (len(items) > MAX_BROWSER_ORIGINS or len(set(items)) != len(items) or
            any(not part for part in items)):
        raise ValueError("At most 12 distinct, nonempty browser origins are allowed")
    return tuple(validate_browser_origin(part) for part in items)
