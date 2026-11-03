"""Portainer Stack configuration is self-contained and uses Compose interpolation."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
YAML = ROOT / "kali-mcp.yml"


def compose_config(overrides: dict | None = None):
    env = os.environ.copy()
    for k in (
        "KALI_MCP_ADMIN_PASSWORD", "KALI_MCP_RELEASE_CHANNEL",
        "KALI_MCP_PUBLIC_URL", "KALI_MCP_VERSION", "KALI_MCP_ALLOW_HOST_ROOT",
    ):
        env.pop(k, None)
    env.update(overrides or {})
    return subprocess.run(["docker", "compose", "-f", str(YAML), "config"],
                          text=True, capture_output=True, env=env, check=False)


def test_admin_password_must_be_set_in_portainer():
    if not _docker_available():
        pytest.skip("Docker Compose not installed")
    result = compose_config()
    assert result.returncode != 0
    assert "KALI_MCP_ADMIN_PASSWORD" in result.stderr


def test_stack_variables_configure_both_services():
    if not _docker_available():
        pytest.skip("Docker Compose not installed")
    result = compose_config({
        "KALI_MCP_ADMIN_PASSWORD": "CI_EXAMPLE_SECRET_DO_NOT_USE_IN_PRODUCTION",
        "KALI_MCP_RELEASE_CHANNEL": "stable",
        "KALI_MCP_PUBLIC_URL": "https://kali.example.test",
        "KALI_MCP_VERSION": "v0.1.0-beta.2",
        "KALI_MCP_ALLOW_HOST_ROOT": "true",
    })
    assert result.returncode == 0, result.stderr
    data = yaml.safe_load(result.stdout)
    services = data["services"]
    assert services["kali-mcp-bootstrap"]["environment"]["KALI_MCP_VERSION"] == "v0.1.0-beta.2"
    assert services["kali-mcp-bootstrap"]["environment"]["KALI_MCP_RELEASE_CHANNEL"] == "stable"
    core = services["kali-mcp-core"]["environment"]
    broker = services["kali-mcp-broker"]["environment"]
    assert core["KALI_MCP_ADMIN_PASSWORD"] == "CI_EXAMPLE_SECRET_DO_NOT_USE_IN_PRODUCTION"
    assert core["KALI_MCP_PUBLIC_URL"] == broker["KALI_MCP_PUBLIC_URL"] == "https://kali.example.test"
    assert core["KALI_MCP_ALLOW_HOST_ROOT"] == broker["KALI_MCP_ALLOW_HOST_ROOT"] == "true"
    # Entire GitHub archive bootstrap is inside the YAML, not a host-side script.
    embedded = services["kali-mcp-bootstrap"]["command"][-1]
    assert "api.github.com/repos" in embedded
    assert "codeload.github.com" in embedded
    assert "safe_extract" in embedded


def _docker_available():
    try:
        proc = subprocess.run(["docker", "compose", "version"],
            capture_output=True, text=True, timeout=8)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
