"""Migration and DoS-boundary tests for the systemd hybrid security release."""
from __future__ import annotations

from pathlib import Path

import pytest

from kali_mcp.config import Config
from kali_mcp.store import Store
from kali_mcp.jobs import Jobs
from kali_mcp.host_agent import AgentState, NativeAgent, BrokerDenied
from kali_mcp.superuser import read_record, verify
from kali_mcp.cli_config import parse_env
from scripts.wizard import configure


def test_legacy_password_migrated_without_losing_settings(tmp_path, monkeypatch):
    config = tmp_path / "etc"
    config.mkdir()
    (config / "stack.env").write_text(
        "KALI_MCP_ADMIN_PASSWORD=LEGACY_PASS_ABOVE_SIXTEEN_2026\n"
        "KALI_MCP_RELEASE_CHANNEL=beta\n"
        "KALI_MCP_PUBLIC_URL=http://localhost:8787\n")
    monkeypatch.delenv("KALI_MCP_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("KALI_MCP_ACCESS_MODE", "local")
    configure(config, 987, interactive=False)
    values = parse_env(config / "stack.env")
    assert values["KALI_MCP_RELEASE_CHANNEL"] == "beta"
    assert "KALI_MCP_ADMIN_PASSWORD" not in values
    assert "LEGACY_PASS_ABOVE_SIXTEEN_2026" not in (config / "stack.env").read_text()
    assert verify(read_record(config / "superuser.json"),
                  "admin", "LEGACY_PASS_ABOVE_SIXTEEN_2026")
    assert (config / "superuser.json").stat().st_mode & 0o777 == 0o600


def test_client_job_quotas_prevent_unbounded_submissions(tmp_path, monkeypatch):
    cfg = Config.from_env()
    store = Store(tmp_path / "jobs.db")
    jobs = Jobs(cfg, store)
    jobs.max_pending = 3
    jobs.max_per_actor = 2
    monkeypatch.setattr(jobs.pool, "submit", lambda *args, **kwargs: None)
    try:
        jobs.submit(actor="mcp:alpha", tool_id="nmap", mode="sandbox",
                    operation="execute", payload={"script": "pass"})
        jobs.submit(actor="mcp:alpha", tool_id="nmap", mode="sandbox",
                    operation="execute", payload={"script": "pass"})
        with pytest.raises(ValueError, match="Client job quota"):
            jobs.submit(actor="mcp:alpha", tool_id="nmap", mode="sandbox",
                        operation="execute", payload={"script": "pass"})
        jobs.submit(actor="mcp:beta", tool_id="nmap", mode="sandbox",
                    operation="execute", payload={"script": "pass"})
        with pytest.raises(ValueError, match="Job queue full"):
            jobs.submit(actor="mcp:gamma", tool_id="nmap", mode="sandbox",
                        operation="execute", payload={"script": "pass"})
    finally:
        jobs.shutdown()
        store.close()


def test_per_actor_terminal_limit_before_creating_shell(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_EXEC", "true")
    cfg = Config.from_env()
    state = AgentState(tmp_path / "policy.json")
    state.set_setting("host_exec", True, cfg)
    agent = NativeAgent(cfg, state)
    agent.sessions["a"] = {"actor": "mcp:a", "root": False}
    agent.sessions["b"] = {"actor": "mcp:a", "root": False}
    with pytest.raises(BrokerDenied, match="quota"):
        agent._terminal("terminal_open", {"actor": "mcp:a", "root": False})
