#!/usr/bin/env python3
"""Root-only, detached browser CORS origin deployment.

Called ONLY by the authenticated Native Host Agent using a fixed script path
and a strictly validated origin list. Never accepts arbitrary file paths or
commands. The Core container has read-only access to code and no /etc mount.
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
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kali_mcp.browser_origins import parse_browser_origins
from kali_mcp.cli_config import parse_env

CONFIG = Path("/etc/kali-mcp")
ROOT = Path("/opt/kali-mcp/current")
STATUS = Path("/var/lib/kali-mcp/browser-origins-status.json")
KEY = "KALI_MCP_BROWSER_ORIGINS"
LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=([^\r\n]*)$")


def atomic_private(path: Path, data: bytes) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Refusing to write an absent or symbolic-link configuration file")
    fd, tmp = tempfile.mkstemp(prefix=".origins-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def private_status(state: str, origins: tuple[str, ...], detail: str = "") -> None:
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    if STATUS.is_symlink():
        raise RuntimeError("Refusing status symlink")
    payload = json.dumps({
        "state": state, "origins": list(origins),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail[:240],
    }, sort_keys=True).encode() + b"\n"
    fd, tmp = tempfile.mkstemp(prefix=".browser-origins-", dir=STATUS.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, STATUS)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def patch_value(existing: bytes, origins: tuple[str, ...]) -> bytes:
    text = existing.decode("utf-8")
    lines = text.splitlines()
    if not any(line.startswith("KALI_MCP_PUBLIC_URL=") for line in lines):
        raise RuntimeError("Existing hybrid configuration is incomplete")
    if any(line and not LINE.fullmatch(line) for line in lines):
        raise RuntimeError("Unexpected existing hybrid configuration entry")
    if sum(line.startswith(KEY + "=") for line in lines) > 1:
        raise RuntimeError("Duplicate browser-origin configuration")
    new_line = KEY + "=" + ",".join(origins)
    edited = [new_line if line.startswith(KEY + "=") else line for line in lines]
    if not any(line.startswith(KEY + "=") for line in lines):
        edited.append(new_line)
    return ("\n".join(edited) + "\n").encode()


def run_compose() -> None:
    # A Core-only recreation. No container privileged mode, Docker socket
    # mount, or host execution/root MCP toggle is involved.
    subprocess.run([
        "docker", "compose", "--env-file", str(CONFIG / "stack.env"),
        "-f", str(ROOT / "kali-mcp-hybrid.yml"),
        "up", "-d", "--no-deps", "--force-recreate", "--wait",
        "--wait-timeout", "180", "kali-mcp-core",
    ], check=True, timeout=210)
    actual = subprocess.check_output([
        "docker", "exec", "kali-mcp-core",
        "/opt/venv/bin/python", "-c",
        "import os; print(os.getenv('KALI_MCP_BROWSER_ORIGINS', ''))",
    ], text=True, timeout=15).strip()
    expected = ",".join(parse_browser_origins(
        parse_env(CONFIG / "stack.env").get(KEY, "")
    ))
    if actual != expected:
        raise RuntimeError("Container did not load the requested browser-origin allowlist")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origins", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Only the root Native Host Agent may deploy browser origins")
    desired = parse_browser_origins(args.origins)

    with (CONFIG / ".install.lock").open("a") as locked:
        fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        paths = (CONFIG / "stack.env", CONFIG / "agent.env")
        previous = [path.read_bytes() for path in paths]
        updated = [patch_value(data, desired) for data in previous]
        private_status("applying", desired)
        if updated == previous:
            private_status("active", desired)
            return
        try:
            for path, data in zip(paths, updated):
                atomic_private(path, data)
            run_compose()
            private_status("active", desired)
            print("Browser-origin allowlist applied; Core container healthy", flush=True)
        except Exception as exc:
            print("Browser-origin deployment failed; restoring previous config", flush=True)
            for path, data in zip(paths, previous):
                atomic_private(path, data)
            try:
                run_compose()
                private_status("rolled_back", desired,
                               type(exc).__name__ + ": " + str(exc)[:140])
            except Exception as recovery_exc:
                private_status("recovery_failed", desired,
                               type(exc).__name__ + "; rollback: " + type(recovery_exc).__name__)
            raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
