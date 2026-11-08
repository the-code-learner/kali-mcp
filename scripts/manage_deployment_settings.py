#!/usr/bin/env python3
"""Root-only hybrid deployment configuration worker.

Called exclusively by the authenticated Native Host Agent through a fixed
systemd-run command. Edits ONLY schema-approved nonsecret settings and keeps
both root-owned env files in sync. Core and Host Agent must pass health checks
before changes are committed. On failure original bytes are restored.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kali_mcp.cli_config import parse_env
from kali_mcp.deployment_settings import validate_change
from manage_browser_origins import atomic_private, private_status as _unused

CONFIG = Path("/etc/kali-mcp")
ROOT = Path("/opt/kali-mcp/current")
STATUS = Path("/var/lib/kali-mcp/deployment-settings-status.json")
LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=([^\r\n]*)$")


def write_status(state: str, keys: tuple[str, ...], detail: str = "") -> None:
    """Root-owned status report (no submitted values or credentials)."""
    from datetime import datetime, timezone
    import tempfile
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    if STATUS.is_symlink():
        raise RuntimeError("Refusing status symlink")
    payload = json.dumps({"state": state, "keys": list(keys),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail[:200]}, sort_keys=True).encode("utf-8") + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=".deploy-status-", dir=STATUS.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATUS)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def patch_env(raw: bytes, updates: dict[str, str]) -> bytes:
    """Preserve existing env content exactly except explicitly approved keys."""
    lines = raw.decode("utf-8").splitlines()
    if not any(line.startswith("KALI_MCP_PUBLIC_URL=") for line in lines):
        raise RuntimeError("Hybrid config lacks a public URL")
    names: set[str] = set()
    next_lines = []
    for line in lines:
        if not line:
            next_lines.append(line)
            continue
        match = LINE.fullmatch(line)
        if not match:
            raise RuntimeError("Refusing to rewrite malformed environment configuration")
        key, value = match.groups()
        if key in names:
            raise RuntimeError("Refusing duplicate environment key: " + key)
        names.add(key)
        next_lines.append(key + "=" + updates[key] if key in updates else line)
    for key, value in updates.items():
        if key not in names:
            next_lines.append(key + "=" + value)
    return ("\n".join(next_lines) + "\n").encode("utf-8")


def activate(updates: dict[str, str]) -> None:
    """Restart unprivileged Core and Agent after atomically applying settings."""
    subprocess.run([
        "docker", "compose", "--env-file", str(CONFIG / "stack.env"),
        "-f", str(ROOT / "kali-mcp-hybrid.yml"),
        "up", "-d", "--no-deps", "--force-recreate", "--wait",
        "--wait-timeout", "180", "kali-mcp-core",
    ], check=True, timeout=210)
    # Verify the active Core has REALLY loaded requested settings; compose
    # interpolates defaults and a typo in an env key must not be 'success'.
    expected = parse_env(CONFIG / "stack.env")
    observed = subprocess.check_output([
        "docker", "exec", "kali-mcp-core", "/opt/venv/bin/python",
        "-c", "import os,json; print(json.dumps({k:os.getenv(k) for k in "+
        repr(sorted(updates))+"}))",
    ], text=True, timeout=15)
    values = json.loads(observed)
    for key, target in updates.items():
        if values.get(key) != target:
            raise RuntimeError("Core did not apply " + key)
    # The native Agent is loaded from agent.env and owns capability ceilings.
    # Restart only when values in its environment change.
    if updates:
        subprocess.run(["systemctl", "restart", "kali-mcp-agent.service"],
                       check=True, timeout=30)
        subprocess.run(["systemctl", "is-active", "--quiet", "kali-mcp-agent.service"],
                       check=True, timeout=15)
        if not Path("/run/kali-mcp-agent/agent.sock").exists():
            raise RuntimeError("Host Agent socket not restored")


def apply_changes(requested: dict[str, str]) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Only the root Native Host Agent may change hybrid config")
    keys = tuple(sorted(requested))
    with (CONFIG / ".install.lock").open("a") as locked:
        fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stack = CONFIG / "stack.env"
        agent = CONFIG / "agent.env"
        original = (stack.read_bytes(), agent.read_bytes())
        existing = parse_env(stack)
        updates = validate_change(existing, requested)
        after = (patch_env(original[0], updates), patch_env(original[1], updates))
        if after == original:
            write_status("active", keys, "Already configured")
            return
        write_status("applying", keys)
        try:
            atomic_private(stack, after[0])
            atomic_private(agent, after[1])
            activate(updates)
            write_status("active", keys)
            print("Deployment setting applied and both services healthy", flush=True)
        except Exception as exc:
            print("Deployment change failed; restoring original env files", flush=True)
            for path, content in zip((stack, agent), original):
                atomic_private(path, content)
            try:
                activate(updates)
                write_status("rolled_back", keys, type(exc).__name__)
            except Exception as rollback_exc:
                write_status("recovery_failed", keys,
                             type(exc).__name__ + " / recovery: " + type(rollback_exc).__name__)
            raise SystemExit(1) from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--changes", required=True,
                        help="bounded JSON object of schema-approved nonsecret env changes")
    args = parser.parse_args()
    if len(args.changes) > 11000:
        parser.error("Request is too large")
    requested = json.loads(args.changes)
    if not isinstance(requested, dict):
        parser.error("Expected JSON object")
    apply_changes(requested)


if __name__ == "__main__":
    main()
