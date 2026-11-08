"""Privileged deployment updates must be authenticated, atomic and reversible."""
from __future__ import annotations

import json
import pytest

from kali_mcp.config import Config
from kali_mcp.broker import BrokerDenied
from kali_mcp.host_agent import AgentState, NativeAgent
from scripts import manage_deployment_settings as worker


def test_native_agent_password_and_explicit_allow_all_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    cfg = Config.from_env()
    state = AgentState(tmp_path / "state.json")
    agent = NativeAgent(cfg, state)
    current = {"KALI_MCP_PUBLIC_URL": "https://kali.example.test",
               "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
               "KALI_MCP_DENIED_CIDRS": "",
               "KALI_MCP_ALLOW_ALL_TARGETS": "false"}
    monkeypatch.setattr("kali_mcp.host_agent.parse_env", lambda _path: dict(current))
    issued = []
    monkeypatch.setattr(agent, "_run", lambda argv, **kwargs:
                        issued.append(argv) or {"exit_code": 0})

    def reject(*_args):
        raise BrokerDenied("Superuser authentication required")
    monkeypatch.setattr(agent, "_verify_superuser", reject)
    changes = {"KALI_MCP_ALLOW_ALL_TARGETS": "true",
               "KALI_MCP_DENIED_CIDRS": "192.168.137.0/24",
               "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32"}
    request = {"changes": changes, "superuser_name": "admin",
               "superuser_password": "incorrect", "confirm": "ALLOW ALL"}
    with pytest.raises(BrokerDenied, match="Superuser"):
        agent.dispatch("deployment_settings_update", request)
    assert not issued

    seen = []
    monkeypatch.setattr(agent, "_verify_superuser",
                        lambda user, password: seen.append((user, password)))
    with pytest.raises(BrokerDenied, match="Type ALLOW ALL"):
        agent.dispatch("deployment_settings_update",
                       {**request, "confirm": ""})
    assert not issued

    result = agent.dispatch("deployment_settings_update", request)
    assert result["scheduled"]
    assert result["keys"] == sorted(changes)
    assert seen[-1] == ("admin", "incorrect")
    assert issued[0][:3] == ["systemd-run", "--collect", "--on-active=3s"]
    assert issued[0][-2] == "--changes"
    assert json.loads(issued[0][-1]) == {
        "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
        "KALI_MCP_DENIED_CIDRS": "192.168.137.0/24",
        "KALI_MCP_ALLOW_ALL_TARGETS": "true",
    }
    assert state.settings()["host_exec"] is False
    assert state.settings()["host_root"] is False

    with pytest.raises(BrokerDenied, match="Invalid deployment change"):
        agent.dispatch("deployment_settings_update", {**request,
            "changes": {"KALI_MCP_AGENT_GROUP": "root"}})
    snapshot = agent.dispatch("deployment_settings_get", {})
    keys = {item["name"] for item in snapshot["fields"]}
    assert "KALI_MCP_ALLOW_ALL_TARGETS" in keys


def test_worker_updates_both_env_files_and_rolls_back_failed_activation(
        tmp_path, monkeypatch):
    folder = tmp_path / "etc" / "kali-mcp"
    folder.mkdir(parents=True)
    (folder / ".install.lock").touch()
    stack, agent = folder / "stack.env", folder / "agent.env"
    old = (b"KALI_MCP_PUBLIC_URL=https://kali.example.test\n"
           b"KALI_MCP_ALLOWED_CIDRS=127.0.0.1/32\n"
           b"KALI_MCP_ADMIN_PASSWORD=DoNotReplaceThisSecret\n"
           b"KALI_MCP_DENIED_CIDRS=\n")
    for path in (stack, agent):
        path.write_bytes(old)
        path.chmod(0o600)
    monkeypatch.setattr(worker, "CONFIG", folder)
    monkeypatch.setattr(worker, "ROOT", tmp_path)
    monkeypatch.setattr(worker, "STATUS", tmp_path / "status.json")
    monkeypatch.setattr(worker.os, "geteuid", lambda: 0)

    activated = []
    def good(updates):
        activated.append((stack.read_bytes(), agent.read_bytes(), updates.copy()))
    monkeypatch.setattr(worker, "activate", good)
    updates = {"KALI_MCP_ALLOW_ALL_TARGETS": "true",
               "KALI_MCP_DENIED_CIDRS": "192.168.137.0/24"}
    worker.apply_changes(updates)
    assert worker.STATUS.exists()
    assert json.loads(worker.STATUS.read_text())["state"] == "active"
    assert len(activated) == 1
    assert stack.read_bytes() == agent.read_bytes()
    assert b"KALI_MCP_ADMIN_PASSWORD=DoNotReplaceThisSecret" in stack.read_bytes()
    assert b"KALI_MCP_ALLOW_ALL_TARGETS=true" in stack.read_bytes()
    assert stack.stat().st_mode & 0o777 == 0o600
    assert agent.stat().st_mode & 0o777 == 0o600

    before = stack.read_bytes()
    recovery = []
    def fail_once(updates):
        recovery.append((stack.read_bytes(), agent.read_bytes()))
        if len(recovery) == 1:
            raise RuntimeError("Simulated Docker unhealthy")
    monkeypatch.setattr(worker, "activate", fail_once)
    with pytest.raises(SystemExit):
        worker.apply_changes({"KALI_MCP_DENIED_CIDRS": "192.168.0.0/16"})
    assert stack.read_bytes() == agent.read_bytes() == before
    assert recovery[0][0] != before
    assert recovery[1] == (before, before)
    assert json.loads(worker.STATUS.read_text())["state"] == "rolled_back"
    with pytest.raises(ValueError):
        worker.apply_changes({"KALI_MCP_SUPERUSER_FILE": "/tmp/evil"})
    assert stack.read_bytes() == before


def test_worker_refuses_non_root_and_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(worker.os, "geteuid", lambda: 10001)
    with pytest.raises(RuntimeError, match="root"):
        worker.apply_changes({"KALI_MCP_ALLOW_ALL_TARGETS": "false"})
