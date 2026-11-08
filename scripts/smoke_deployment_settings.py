#!/usr/bin/env python3
"""Ephemeral CI integration check for WebUI-configured deny-first target scope.

Root test only. Uses a temporary CI superuser credential and the real private
Host Agent socket, then waits for the scheduled root systemd worker, Core
healthcheck and Agent restart. Not suitable for running on production.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kali_mcp.broker_client import call
from kali_mcp.cli_config import parse_env

CONFIG = Path("/etc/kali-mcp")
STATE = Path("/var/lib/kali-mcp/deployment-settings-status.json")
PASSWORD = Path("/run/kali-mcp-cli-test-password")


def main() -> None:
    if "--ephemeral-ci" not in sys.argv or os.geteuid() != 0:
        raise SystemExit("Scope smoke requires explicit ephemeral CI as root")
    if (not PASSWORD.is_file() or PASSWORD.is_symlink() or
            PASSWORD.stat().st_mode & 0o077):
        raise SystemExit("Private ephemeral CI superuser password not provisioned")
    credential = PASSWORD.read_text(encoding="utf-8").strip()
    desired = {"KALI_MCP_ALLOW_ALL_TARGETS": "true",
               "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
               "KALI_MCP_DENIED_CIDRS": "192.168.137.0/24"}
    result = call("/run/kali-mcp-agent/agent.sock", "deployment_settings_update", {
        "changes": desired, "superuser_name": "admin",
        "superuser_password": credential, "confirm": "ALLOW ALL",
    }, timeout=30)
    assert result.get("scheduled") is True, result
    deadline = time.monotonic() + 190
    while time.monotonic() < deadline:
        try:
            stack = parse_env(CONFIG / "stack.env")
            agent = parse_env(CONFIG / "agent.env")
            state = json.loads(STATE.read_text(encoding="utf-8"))
            active = subprocess.run(["systemctl", "is-active", "--quiet",
                                     "kali-mcp-agent.service"]).returncode == 0
            docker = subprocess.run(["docker", "inspect", "--format",
                "{{.State.Health.Status}}", "kali-mcp-core"],
                capture_output=True, text=True, timeout=10)
            if (all(stack.get(k) == v and agent.get(k) == v
                    for k, v in desired.items()) and active and
                    docker.stdout.strip() == "healthy" and
                    state.get("state") == "active"):
                command = ["docker", "exec", "kali-mcp-core", "/opt/venv/bin/python",
                           "-c", "import os,json;print(json.dumps({k:os.getenv(k) for k in " +
                           repr(sorted(desired)) + "}))"]
                actual = json.loads(subprocess.check_output(command, text=True, timeout=15))
                assert actual == desired, (actual, desired)
                inventory = call("/run/kali-mcp-agent/agent.sock",
                                 "deployment_settings_get", timeout=20)
                rows = {row["name"]: row for row in inventory["fields"]}
                assert rows["KALI_MCP_DENIED_CIDRS"]["value"] == desired["KALI_MCP_DENIED_CIDRS"]
                assert rows["KALI_MCP_ALLOW_ALL_TARGETS"]["value"] == "true"
                assert "KALI_MCP_SUPERUSER_FILE" in rows
                print("Deployment scope: allow-all + CIDR blacklist persisted in Core and Agent")
                return
            if state.get("state") in {"rolled_back", "recovery_failed"}:
                raise AssertionError("Scope deployment failed: " +
                                     str(state.get("detail", "unknown")))
        except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired):
            pass
        time.sleep(3)
    raise AssertionError("Timed out applying scope to both Core and Native Agent")


if __name__ == "__main__":
    main()
