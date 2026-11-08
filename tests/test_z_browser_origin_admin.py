"""Root-owned CORS origin configuration: authorization, atomic writes, rollback."""
from __future__ import annotations

import json
import os
import sys

import pytest

from kali_mcp.browser_origins import parse_browser_origins
from kali_mcp.config import Config
from kali_mcp.broker import BrokerDenied
from kali_mcp.host_agent import AgentState, NativeAgent
from scripts import manage_browser_origins as manager


def test_host_agent_origin_changes_require_independent_superuser(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    cfg = Config.from_env()
    state = AgentState(tmp_path / "agent-state.json")
    agent = NativeAgent(cfg, state)

    values = {"KALI_MCP_BROWSER_ORIGINS": "https://existing.example.test"}
    monkeypatch.setattr("kali_mcp.host_agent.parse_env", lambda path: dict(values))
    commands = []
    monkeypatch.setattr(agent, "_run", lambda argv, **kwargs:
                        commands.append(argv) or {"exit_code": 0})
    def no_auth(user, password):
        raise BrokerDenied("Superuser authentication required")
    monkeypatch.setattr(agent, "_verify_superuser", no_auth)

    request = {"action": "add", "origin": "https://llm.example.test",
               "superuser_name": "admin", "superuser_password": "wrong"}
    with pytest.raises(BrokerDenied, match="Superuser"):
        agent.dispatch("browser_origins_update", request)
    assert not commands

    verified = []
    monkeypatch.setattr(agent, "_verify_superuser",
                        lambda user, password: verified.append((user, password)))
    result = agent.dispatch("browser_origins_update", {
        **request, "superuser_password": "test-superuser-password"})
    assert result["scheduled"] is True
    assert result["configured"] == [
        "https://existing.example.test", "https://llm.example.test"]
    assert verified == [("admin", "test-superuser-password")]
    assert len(commands) == 1
    assert commands[0][:3] == ["systemd-run", "--collect", "--on-active=3s"]
    assert commands[0][-2:] == [
        "--origins", "https://existing.example.test,https://llm.example.test"]
    # No Host Exec / Host Root grant was needed or performed.
    assert state.settings()["host_exec"] is False
    assert state.settings()["host_root"] is False

    assert agent.dispatch("browser_origins_update", {
        **request, "superuser_password": "test-superuser-password",
        "action": "remove", "origin": "https://missing.example.test"
    })["unchanged"] is True
    with pytest.raises(BrokerDenied, match="Invalid browser-origin"):
        agent.dispatch("browser_origins_update", {
            **request, "superuser_password": "test-superuser-password",
            "origin": "https://*.example.test"
        })


def test_root_worker_preserves_env_and_rolls_back_on_failure(tmp_path, monkeypatch):
    config = tmp_path / "etc" / "kali-mcp"
    config.mkdir(parents=True)
    root = tmp_path / "current"
    root.mkdir()
    stack = config / "stack.env"
    agent = config / "agent.env"
    original = (
        b"KALI_MCP_PUBLIC_URL=https://kali.example.test\n"
        b"KALI_MCP_RELEASE_CHANNEL=beta\n"
        b"KALI_MCP_BROWSER_ORIGINS=https://original.example.test\n"
        b"KALI_MCP_ALLOW_HOST_ROOT=false\n"
    )
    stack.write_bytes(original)
    agent.write_bytes(original)
    stack.chmod(0o600)
    agent.chmod(0o600)
    monkeypatch.setattr(manager, "CONFIG", config)
    monkeypatch.setattr(manager, "ROOT", root)
    monkeypatch.setattr(manager, "STATUS", tmp_path / "origin-status.json")
    monkeypatch.setattr(manager.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [
        "manage_browser_origins.py", "--origins", "https://llm.example.test"
    ])
    observed = []
    def success():
        observed.append((stack.read_bytes(), agent.read_bytes()))
    monkeypatch.setattr(manager, "run_compose", success)
    manager.main()
    expected = original.replace(
        b"KALI_MCP_BROWSER_ORIGINS=https://original.example.test",
        b"KALI_MCP_BROWSER_ORIGINS=https://llm.example.test")
    assert observed == [(expected, expected)]
    assert json.loads(manager.STATUS.read_text())["state"] == "active"
    assert stack.stat().st_mode & 0o777 == 0o600
    assert agent.stat().st_mode & 0o777 == 0o600

    # Docker fails its healthcheck on the first attempt. Both protected files
    # must be restored before a second Core-only recreate.
    recovery_calls = []
    def fail_once():
        recovery_calls.append((stack.read_bytes(), agent.read_bytes()))
        if len(recovery_calls) == 1:
            raise RuntimeError("Simulated Docker unhealthy")
    monkeypatch.setattr(manager, "run_compose", fail_once)
    monkeypatch.setattr(sys, "argv", [
        "manage_browser_origins.py", "--origins", "https://changed.example.test"])
    with pytest.raises(SystemExit):
        manager.main()
    assert stack.read_bytes() == expected
    assert agent.read_bytes() == expected
    assert json.loads(manager.STATUS.read_text())["state"] == "rolled_back"
    assert recovery_calls[0][0] != expected
    assert recovery_calls[1] == (expected, expected)


def test_worker_rejects_non_root_or_invalid_origins(tmp_path, monkeypatch):
    monkeypatch.setattr(manager.os, "geteuid", lambda: 10001)
    monkeypatch.setattr(sys, "argv", [
        "manage_browser_origins.py", "--origins", "https://llm.example.test"])
    with pytest.raises(SystemExit, match="root"):
        manager.main()
    monkeypatch.setattr(manager.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [
        "manage_browser_origins.py", "--origins", "*"])
    with pytest.raises(ValueError):
        manager.main()
