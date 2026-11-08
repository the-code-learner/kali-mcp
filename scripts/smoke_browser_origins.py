"""CI-only real Host Agent browser-origin update smoke.

Runs on an ephemeral hybrid GitHub Actions appliance after installation.
Never invoke against production. All credentials are taken from environment.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kali_mcp.broker_client import call
from kali_mcp.cli_config import parse_env

STATUS = Path("/var/lib/kali-mcp/browser-origins-status.json")
CONFIG = Path("/etc/kali-mcp")
NEW = "https://second.example.test"
EXPECTED = "https://llm.example.test," + NEW


def main() -> None:
    if os.getenv("KALI_MCP_SMOKE_BROWSER_ORIGINS") != "true":
        raise SystemExit("This script requires the explicit ephemeral CI smoke flag")
    if os.geteuid() != 0:
        raise SystemExit("Run as root in the isolated CI test appliance")
    password = os.environ["KALI_MCP_TEST_ADMIN_PASSWORD"]
    result = call("/run/kali-mcp-agent/agent.sock", "browser_origins_update", {
        "action": "add", "origin": NEW, "superuser_name": "admin",
        "superuser_password": password,
    }, timeout=30)
    assert result.get("scheduled") is True, "Browser-origin update not scheduled"

    end = time.monotonic() + 165
    while time.monotonic() < end:
        try:
            stack = parse_env(CONFIG / "stack.env")
            agent = parse_env(CONFIG / "agent.env")
            state = json.loads(STATUS.read_text(encoding="utf-8"))
            health = subprocess.run([
                "docker", "inspect", "--format", "{{.State.Health.Status}}",
                "kali-mcp-core",
            ], capture_output=True, text=True, timeout=8)
            if (stack.get("KALI_MCP_BROWSER_ORIGINS") == EXPECTED and
                    agent.get("KALI_MCP_BROWSER_ORIGINS") == EXPECTED and
                    state.get("state") == "active" and
                    health.stdout.strip() == "healthy"):
                check = subprocess.run([
                    "docker", "exec", "kali-mcp-core", "/opt/venv/bin/python",
                    "-c", "import os; print(os.getenv('KALI_MCP_BROWSER_ORIGINS',''))",
                ], capture_output=True, text=True, timeout=8)
                assert check.stdout.strip() == EXPECTED
                assert (CONFIG / "config.ready").is_file()
                print("Host Agent CORS update: Core-only recreate healthy; both origins persisted")
                return
            if state.get("state") in {"rolled_back", "recovery_failed"}:
                raise AssertionError("Browser origin deployment failed: " +
                                     str(state.get("detail", "unknown"))[:100])
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        time.sleep(3)
    raise AssertionError("Browser origin deployment did not reach healthy active state")


if __name__ == "__main__":
    main()
