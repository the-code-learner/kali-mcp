"""Strictly local IPC client for the privileged host broker."""
from __future__ import annotations

import json
from pathlib import Path
import socket


class BrokerError(RuntimeError):
    pass


def call(socket_path: str | Path, op: str, payload: dict | None = None, *, timeout: int = 45) -> dict:
    effective = dict(payload or {})
    if op.startswith("terminal_"):
        # Carry the already authenticated request identity into each PTY IPC call.
        # A missing request-scoped identity must fail closed.
        from .server import ACTOR
        actor = ACTOR.get()
        if not actor.startswith("mcp:") or actor == "mcp:unknown":
            raise BrokerError("No authenticated MCP client identity for terminal session")
        effective["actor"] = actor
    data = json.dumps({"v": 1, "op": op, "payload": effective}, separators=(",", ":")).encode()
    if len(data) > 256 * 1024:
        raise BrokerError("Request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(str(socket_path))
            sock.sendall(data + b"\n")
            result = bytearray()
            while not result.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > 1024 * 1024:
                    raise BrokerError("Broker response too large")
            response = json.loads(result)
        except (OSError, ValueError) as exc:
            raise BrokerError(f"Broker unavailable: {type(exc).__name__}") from exc
    if not response.get("ok"):
        raise BrokerError(str(response.get("error", "Broker request denied")))
    return response
