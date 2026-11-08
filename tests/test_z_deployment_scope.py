"""Allow-all + blacklist precedence, locked-down deployment setting schema."""
from __future__ import annotations

import socket
import pytest

from kali_mcp.config import Config
from kali_mcp.deployment_settings import (
    parse_cidrs, validate_scope, validate_change, public_inventory
)
from kali_mcp.policy import Policy, PolicyDenied
from kali_mcp.store import Store


def test_default_only_loopback_and_blacklist_precedence(tmp_path, monkeypatch):
    monkeypatch.delenv("KALI_MCP_ALLOWED_CIDRS", raising=False)
    monkeypatch.delenv("KALI_MCP_DENIED_CIDRS", raising=False)
    monkeypatch.delenv("KALI_MCP_ALLOW_ALL_TARGETS", raising=False)
    cfg = Config.from_env()
    store = Store(tmp_path / "default.db")
    policy = Policy(cfg, store)
    assert cfg.allowed_cidrs == ("127.0.0.1/32",)
    assert cfg.denied_cidrs == ()
    assert not cfg.allow_all_targets
    assert policy.check_target("127.0.0.1") == "127.0.0.1"
    with pytest.raises(PolicyDenied, match="outside authorized"):
        policy.check_target("192.168.0.1")
    store.close()

    monkeypatch.setenv("KALI_MCP_ALLOWED_CIDRS", "192.168.0.0/16")
    monkeypatch.setenv("KALI_MCP_DENIED_CIDRS", "192.168.137.0/24")
    cfg = Config.from_env()
    store = Store(tmp_path / "allowlist.db")
    policy = Policy(cfg, store)
    assert policy.check_target("192.168.0.1") == "192.168.0.1"
    with pytest.raises(PolicyDenied, match="explicitly denied"):
        policy.check_target("192.168.137.42")
    store.close()

    monkeypatch.setenv("KALI_MCP_ALLOW_ALL_TARGETS", "true")
    cfg = Config.from_env()
    store = Store(tmp_path / "allowall.db")
    policy = Policy(cfg, store)
    assert cfg.allow_all_targets
    assert policy.check_target("203.0.113.40") == "203.0.113.40"
    assert policy.check_target("192.168.0.1") == "192.168.0.1"
    with pytest.raises(PolicyDenied, match="explicitly denied"):
        policy.check_target("192.168.137.42")
    store.close()


def test_mixed_hostname_resolution_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ALLOWED_CIDRS", "10.20.0.0/16")
    monkeypatch.setenv("KALI_MCP_DENIED_CIDRS", "192.168.137.0/24")
    monkeypatch.setenv("KALI_MCP_ALLOW_ALL_TARGETS", "true")
    cfg = Config.from_env()
    store = Store(tmp_path / "dns.db")
    policy = Policy(cfg, store)

    def resolve(host, *_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.4.5", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.137.55", 0)),
        ]
    monkeypatch.setattr("kali_mcp.policy.socket.getaddrinfo", resolve)
    with pytest.raises(PolicyDenied, match="explicitly denied"):
        policy.check_target("target.example.test")
    store.close()


def test_invalid_cidrs_and_guardrails_rejected():
    assert parse_cidrs("192.168.0.2,2001:db8::/32") == (
        "192.168.0.2/32", "2001:db8::/32")
    for raw in ("garbage", "192.168.0.999/24", "0.0.0.0/-1",
                "192.168.1.0/24,192.168.1.1/24", ",".join(
                    f"10.{n//256}.{n%256}.0/24" for n in range(65))):
        with pytest.raises(ValueError):
            parse_cidrs(raw)
    with pytest.raises(ValueError, match="blacklisted"):
        validate_scope("true", "127.0.0.1/32", "")
    with pytest.raises(ValueError):
        validate_scope("on", "127.0.0.1/32", "192.168.137.0/24")
    current = {"KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
               "KALI_MCP_ALLOW_HOST_EXEC": "false"}
    with pytest.raises(ValueError, match="cannot be changed"):
        validate_change(current, {"KALI_MCP_SUPERUSER_FILE": "/tmp/compromised"})
    with pytest.raises(ValueError):
        validate_change(current, {"KALI_MCP_ALLOWED_CIDRS": "0.0.0.0/0\nEVIL=yes"})
    with pytest.raises(ValueError, match="Allow all"):
        validate_change(current, {"KALI_MCP_ALLOWED_CIDRS": "0.0.0.0/0"})
    with pytest.raises(ValueError, match="Host Exec"):
        validate_change(current, {"KALI_MCP_ALLOW_HOST_ROOT": "true"})
    with pytest.raises(ValueError):
        validate_change(current, {"KALI_MCP_PORT": "0"})


def test_inventory_shows_all_variables_but_never_secrets():
    stack = {
        "KALI_MCP_PUBLIC_URL": "https://kali.example.test",
        "KALI_MCP_ALLOWED_CIDRS": "127.0.0.1/32",
        "KALI_MCP_ADMIN_PASSWORD": "NEVER_SHOW_THIS_PASSWORD",
        "KALI_MCP_BROWSER_ORIGINS": "https://llm.example.test",
        "KALI_MCP_EXTRA_SECRET": "NEVER_SHOW_EXTRA_SECRET",
    }
    agent = {"KALI_MCP_AGENT_GROUP": "kalimcp"}
    rows = {row["name"]: row for row in public_inventory(stack, agent)}
    assert rows["KALI_MCP_ALLOWED_CIDRS"]["editable"]
    assert rows["KALI_MCP_DENIED_CIDRS"]["value"] == ""
    assert rows["KALI_MCP_ALLOW_ALL_TARGETS"]["value"] == "false"
    assert not rows["KALI_MCP_BROWSER_ORIGINS"]["editable"]
    assert not rows["KALI_MCP_AGENT_GROUP"]["editable"]
    assert rows["KALI_MCP_ADMIN_PASSWORD"]["value"] == "(hidden)"
    assert rows["KALI_MCP_EXTRA_SECRET"]["value"] == "(hidden)"
    assert "NEVER_SHOW" not in repr(rows)
