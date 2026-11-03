"""Read-only MCP invocation telemetry without storing sensitive arguments.

Captures method and tool name from bounded JSON-RPC bodies and attributes
calls to the OAuth client attached by the SecurityGate. It never logs script
source, command strings, uploaded files, passwords or tokens.
"""
from __future__ import annotations

import json

from .store import Store


class ToolCallObserver:
    def __init__(self, app, store: Store):
        self.app, self.store = app, store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        actor = str(scope.get("state", {}).get("oauth_client_id") or "unknown")
        buffered = bytearray()
        audited = False

        async def safe_receive():
            nonlocal audited
            message = await receive()
            if message.get("type") == "http.request" and not audited:
                chunk = message.get("body", b"")
                if len(buffered) + len(chunk) <= 128 * 1024:
                    buffered.extend(chunk)
                else:
                    audited = True
                if not message.get("more_body", False):
                    audited = True
                    try:
                        body = json.loads(buffered)
                        if isinstance(body, dict):
                            method = str(body.get("method") or "")
                            params = body.get("params") if isinstance(body.get("params"), dict) else {}
                            name = str(params.get("name") or "")
                            if method == "tools/call" and name:
                                self.store.audit("mcp:" + actor, "tool.call", "allow", name[:100])
                            elif method in {"initialize", "tools/list", "resources/list"}:
                                self.store.audit("mcp:" + actor, "protocol." + method, "allow")
                    except (ValueError, UnicodeDecodeError):
                        pass
            return message

        return await self.app(scope, safe_receive, send)
