#!/usr/bin/env python3
"""Hybrid release gate: Core still sees Native Agent after systemd restarts.

The root systemd service RuntimeDirectory must preserve the directory inode
used by Docker's read-only bind mount. Regression: a previously running Core
kept a stale mount after systemd removed/recreated /run/kali-mcp-agent.
This test is intentionally destructive to the ephemeral CI Agent; never run
it on a real production installation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

SOCKET = Path("/run/kali-mcp-agent/agent.sock")
DIRECTORY = SOCKET.parent


def container_socket() -> dict:
    script = (
        "import json,os,stat,sys;"
        "sys.path.insert(0,'/opt/kali-mcp/current/src');"
        "from kali_mcp.broker_client import call;"
        "p='/run/kali-mcp-agent';s=p+'/agent.sock';"
        "d=os.stat(p);"
        "r=call(s,'ping',timeout=5);"
        "print(json.dumps({'device':d.st_dev,'inode':d.st_ino,"
        "'socket':stat.S_ISSOCK(os.stat(s).st_mode),'reply':r}))"
    )
    output = subprocess.check_output(
        ["docker", "exec", "kali-mcp-core", "/opt/venv/bin/python",
         "-c", script], text=True, timeout=15)
    return json.loads(output)


def assert_socket_works() -> None:
    assert SOCKET.is_socket(), "Native Host Agent socket absent on host"
    host = DIRECTORY.stat()
    result = container_socket()
    assert result["socket"] is True, "Agent socket not visible inside Core"
    assert (result["device"], result["inode"]) == (host.st_dev, host.st_ino), (
        "Core has a stale Docker bind mount of the Agent runtime directory")
    assert result["reply"]["ok"] is True
    assert result["reply"]["broker"] == "systemd-host-agent"


def main() -> None:
    if "--ephemeral-ci" not in sys.argv or os.geteuid() != 0:
        raise SystemExit("Agent restart smoke is permitted only on ephemeral CI as root")
    unit = "kali-mcp-agent.service"
    props = subprocess.check_output(
        ["systemctl", "show", unit, "-p", "RuntimeDirectoryPreserve",
         "--value"], text=True, timeout=10).strip()
    assert props == "yes", (
        "systemd must preserve /run/kali-mcp-agent across stop/restart")
    assert_socket_works()
    initial = DIRECTORY.stat()
    for round_number in (1, 2):
        subprocess.run(["systemctl", "restart", unit], check=True, timeout=35)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                assert_socket_works()
                break
            except (OSError, AssertionError, subprocess.CalledProcessError):
                time.sleep(0.5)
        else:
            assert_socket_works()
        current = DIRECTORY.stat()
        assert (initial.st_dev, initial.st_ino) == (
            current.st_dev, current.st_ino), (
                "Native Agent runtime directory replaced after restart " +
                str(round_number))
    assert subprocess.check_output(
        ["docker", "inspect", "--format", "{{.State.Health.Status}}",
         "kali-mcp-core"], text=True, timeout=15).strip() == "healthy"
    print("Agent Unix IPC remains accessible in running Core after 2 systemd restarts")


if __name__ == "__main__":
    main()
