"""Policy-gated native systemd upgrade scheduling and CLI config tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from kali_mcp.config import Config
from kali_mcp.host_agent import AgentState, NativeAgent, BrokerDenied
from kali_mcp.cli_config import parse_env, set_value


def test_upgrade_requires_host_owned_policy_and_exact_release(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "http://localhost:8787")
    monkeypatch.setenv("KALI_MCP_RELEASE_CHANNEL", "beta")
    monkeypatch.setenv("KALI_MCP_ALLOW_MCP_UPDATES", "true")
    policy = AgentState(tmp_path / "agent-policy.json")
    native = NativeAgent(Config.from_env(), policy)
    with pytest.raises(BrokerDenied):
        native.dispatch("updates_install", {"tag": "v0.1.0-beta.3"})
    policy.set_setting("mcp_updates", True, native.cfg)
    monkeypatch.setattr("kali_mcp.host_agent.query_releases", lambda repo: [
        {"tag_name": "v0.1.0-beta.2", "draft": False, "prerelease": True},
        {"tag_name": "v0.1.0-beta.3", "draft": False, "prerelease": True},
    ])
    calls = []
    monkeypatch.setattr(native, "_run", lambda argv, **kwargs:
        calls.append(argv) or {"ok": True, "exit_code": 0})
    result = native.dispatch("updates_install", {"tag": "v0.1.0-beta.3"})
    assert result["scheduled"] is True
    assert calls[0][0] == "systemd-run"
    assert "--setenv=KALI_MCP_VERSION=v0.1.0-beta.3" in calls[0]
    assert calls[0][-2:] == ["/opt/kali-mcp/current/scripts/install-hybrid.sh", "--upgrade"]
    with pytest.raises(BrokerDenied):
        native.dispatch("updates_install", {"tag": "v0.1.0-beta.2"})
    with pytest.raises(BrokerDenied):
        native.dispatch("updates_install", {"tag": "v0.1.0-beta.3;touch /tmp/hacked"})


def test_installer_env_origin_update_preserves_admin_secret(tmp_path):
    path = tmp_path / "stack.env"
    path.write_text("KALI_MCP_ADMIN_PASSWORD=NEVER_DISPLAY_THIS_SECRET\n"
                    "KALI_MCP_PUBLIC_URL=http://localhost:8787\n")
    path.chmod(0o600)
    set_value(path, "KALI_MCP_PUBLIC_URL", "https://mcp.example.com")
    values = parse_env(path)
    assert values["KALI_MCP_ADMIN_PASSWORD"] == "NEVER_DISPLAY_THIS_SECRET"
    assert values["KALI_MCP_PUBLIC_URL"] == "https://mcp.example.com"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        set_value(path, "BAD_NAME", "yes")
    with pytest.raises(ValueError):
        set_value(path, "KALI_MCP_PUBLIC_URL", "https://good\nEXECUTE=evil")


def test_native_upgrade_denied_by_deployment_ceiling(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ALLOW_MCP_UPDATES", "false")
    cfg = Config.from_env()
    policy = AgentState(tmp_path / "agent-policy.json")
    with pytest.raises(BrokerDenied, match="KALI_MCP_ALLOW_MCP_UPDATES"):
        policy.set_setting("mcp_updates", True, cfg)



def test_disabling_root_revokes_only_root_sessions(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_EXEC", "true")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_ROOT", "true")
    cfg = Config.from_env()
    state = AgentState(tmp_path / "policy.json")
    agent = NativeAgent(cfg, state)
    agent.dispatch("settings_set", {"feature": "host_exec", "enabled": True})
    agent.dispatch("settings_set", {"feature": "host_root", "enabled": True})
    agent.sessions["root-pty"] = {"root": True}
    agent.sessions["normal-pty"] = {"root": False}
    closed = []

    def close(key, session):
        closed.append(key)
        del agent.sessions[key]

    monkeypatch.setattr(agent, "_close_session", close)
    agent.dispatch("settings_set", {"feature": "host_root", "enabled": False})
    assert closed == ["root-pty"]
    assert "normal-pty" in agent.sessions
    agent.dispatch("settings_set", {"feature": "host_exec", "enabled": False})
    assert closed == ["root-pty", "normal-pty"]
    assert agent.store.get_setting("host_root") is False


def test_webui_disabling_host_exec_resets_root(configured):
    cfg, store = configured
    from kali_mcp.policy import Policy
    p = Policy(cfg, store)
    p.set_webui("host_exec", True)
    p.set_webui("host_root", True)
    p.set_webui("host_exec", False)
    assert store.get_setting("host_root") is False
