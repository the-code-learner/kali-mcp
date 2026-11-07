"""Hybrid Kali systemd Host Agent + SSH wizard + unprivileged Compose tests."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest
import yaml

from kali_mcp.config import Config
from kali_mcp.host_agent import AgentState, NativeAgent, BrokerDenied
from kali_mcp.cli_config import parse_env
from kali_mcp.superuser import read_record, verify
from scripts.wizard import configure, valid_origin


ROOT = Path(__file__).resolve().parents[1]


def test_agent_policy_is_host_owned_and_persistent(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "http://localhost:8787")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_EXEC", "true")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_ROOT", "true")
    config = Config.from_env()
    path = tmp_path / "etc" / "agent-state.json"
    state = AgentState(path)
    assert state.get_setting("host_root") is False
    with pytest.raises(BrokerDenied):
        state.set_setting("host_root", True, config)
    state.set_setting("host_exec", True, config)
    state.set_setting("host_root", True, config)
    assert AgentState(path).get_setting("host_root") is True
    assert path.stat().st_mode & 0o777 == 0o600
    state.set_setting("host_exec", False, config)
    assert not state.get_setting("host_root")


def test_native_agent_root_policy_and_nonroot_command(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "http://localhost:8787")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_EXEC", "true")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_ROOT", "true")
    state = AgentState(tmp_path / "host-policy.json")
    agent = NativeAgent(Config.from_env(), state)
    with pytest.raises(BrokerDenied):
        agent._nsenter(["id"], root=True)
    state.set_setting("host_exec", True, agent.cfg)
    state.set_setting("host_root", True, agent.cfg)
    assert agent._nsenter(["id"], root=True) == ["id"]
    assert agent._nsenter(["id"], root=False) == ["runuser", "-u", agent.host_user, "--", "id"]
    assert agent.dispatch("ping", {})["broker"] == "systemd-host-agent"
    assert agent.dispatch("settings_get", {})["settings"]["host_root"] is True


def test_wizard_noninteractive_is_ssh_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "TEST_32_CHAR_URL_SAFE_PASSWORD_2026")
    monkeypatch.setenv("KALI_MCP_RELEASE_CHANNEL", "beta")
    monkeypatch.setenv("KALI_MCP_ACCESS_MODE", "local")
    monkeypatch.delenv("KALI_MCP_ALLOW_HOST_ROOT", raising=False)
    monkeypatch.delenv("KALI_MCP_ALLOW_HOST_EXEC", raising=False)
    state = configure(tmp_path / "private", 912, interactive=False)
    env = parse_env(tmp_path / "private" / "stack.env")
    host = parse_env(tmp_path / "private" / "agent.env")
    assert env["KALI_MCP_AGENT_GID"] == "912"
    assert "KALI_MCP_ADMIN_PASSWORD" not in env
    account = read_record(tmp_path / "private" / "superuser.json")
    assert account["username"] == "admin"
    assert verify(account, "admin", "TEST_32_CHAR_URL_SAFE_PASSWORD_2026")
    assert env["KALI_MCP_ACCESS_MODE"] == "local"
    assert env["KALI_MCP_ALLOW_HOST_ROOT"] == "false"
    assert "KALI_MCP_ADMIN_PASSWORD" not in host
    assert host["KALI_MCP_BROKER_SOCKET"] == "/run/kali-mcp-agent/agent.sock"
    assert (tmp_path / "private" / "stack.env").stat().st_mode & 0o777 == 0o600
    assert valid_origin("https://mcp.example.org")
    assert not valid_origin("http://mcp.example.org")


def test_nonprivileged_core_compose_and_systemd_unit():
    config = yaml.safe_load((ROOT / "kali-mcp-hybrid.yml").read_text())
    services = config["services"]
    assert list(services) == ["kali-mcp-core"]
    core = services["kali-mcp-core"]
    assert not core.get("privileged")
    assert "pid" not in core
    assert "user" in core and core["user"] == "10001:10001"
    assert core["cap_drop"] == ["ALL"]
    assert all("docker.sock" not in item for item in core["volumes"])
    assert all(":/:" not in item for item in core["volumes"])
    assert "/run/kali-mcp-agent:/run/kali-mcp-agent:ro" in core["volumes"]
    assert "/var/lib/kali-mcp/auth/superuser.json:/run/secrets/kali-mcp-superuser.json:ro" in core["volumes"]
    assert "KALI_MCP_ADMIN_PASSWORD" not in core["environment"]
    assert core["environment"]["KALI_MCP_HOST_AGENT"] == "true"
    unit = (ROOT / "systemd/kali-mcp-agent.service").read_text()
    assert "ExecStart=/opt/kali-mcp/agent-venv/bin/python -m kali_mcp.host_agent" in unit
    assert "User=root" in unit


def test_hybrid_bash_parses():
    result = subprocess.run(["bash", "-n", str(ROOT / "scripts/install-hybrid.sh")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_compose_interpolation_from_installer_env(tmp_path):
    if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode:
        pytest.skip("Docker Compose CLI not installed")
    env = tmp_path / "stack.env"
    env.write_text("KALI_MCP_AGENT_GID=912\nKALI_MCP_RELEASE_CHANNEL=beta\n")
    result = subprocess.run(["docker", "compose", "--env-file", str(env), "-f",
         str(ROOT / "kali-mcp-hybrid.yml"), "config"], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    rendered = yaml.safe_load(result.stdout)
    assert rendered["services"]["kali-mcp-core"]["group_add"] == ["912"]
