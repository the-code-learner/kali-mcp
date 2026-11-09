#!/usr/bin/env python3
"""Carry an operator's existing per-Core DNS override into the hybrid installer.

Only used during an upgrade. Reads the running Core's Docker HostConfig.Dns,
not the host resolver and not a hard-coded public IP. No Docker/network writes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from kali_mcp.deployment_settings import normalize_dns_server
from scripts.wizard import parse_env, write_private


def migrate(config: Path, *, dns: str | None = None) -> bool:
    stack, agent = config / "stack.env", config / "agent.env"
    if not stack.is_file() or not agent.is_file():
        raise ValueError("Hybrid configuration files missing")
    current = parse_env(stack)
    if current.get("KALI_MCP_DNS_SERVER"):
        return False
    if dns is None:
        result = subprocess.run([
            "docker", "inspect", "--format", "{{json .HostConfig.Dns}}",
            "kali-mcp-core",
        ], capture_output=True, text=True, timeout=10)
        if result.returncode:
            return False
        try:
            configured = json.loads(result.stdout)
        except (TypeError, ValueError):
            return False
        if not isinstance(configured, list) or len(configured) != 1:
            return False
        dns = configured[0]
    try:
        valid = normalize_dns_server(dns)
    except (ValueError, TypeError):
        return False
    if not valid:
        return False

    for file in (stack, agent):
        lines = file.read_text(encoding="utf-8").splitlines()
        edited = []
        found = False
        for line in lines:
            if line.startswith("KALI_MCP_DNS_SERVER="):
                if found:
                    raise ValueError("Duplicate Core DNS configuration")
                edited.append("KALI_MCP_DNS_SERVER=" + valid)
                found = True
            else:
                edited.append(line)
        if not found:
            edited.append("KALI_MCP_DNS_SERVER=" + valid)
        write_private(file, "\n".join(edited) + "\n")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", default="/etc/kali-mcp")
    args = parser.parse_args()
    if migrate(Path(args.config_dir)):
        print("Preserved existing Core-only DNS override for hybrid upgrade")
