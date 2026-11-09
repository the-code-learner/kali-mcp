"""beta.14 -> beta.15 DNS migration keeps an explicit Core-only override."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.preserve_core_dns import migrate
from scripts.wizard import parse_env


@pytest.fixture
def config(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "stack.env").write_text("KALI_MCP_PUBLIC_URL=https://example.test\nKALI_MCP_DNS_SERVER=\n")
    (cfg / "agent.env").write_text("KALI_MCP_PUBLIC_URL=https://example.test\n")
    return cfg


def test_dns_migration_preserves_container_override_in_both_files(config):
    assert migrate(config, dns="192.168.137.1")
    for file in ("stack.env", "agent.env"):
        assert parse_env(config / file)["KALI_MCP_DNS_SERVER"] == "192.168.137.1"
        assert (config / file).stat().st_mode & 0o777 == 0o600
    assert migrate(config, dns="8.8.8.8") is False
    assert parse_env(config / "stack.env")["KALI_MCP_DNS_SERVER"] == "192.168.137.1"


def test_migration_does_not_choose_a_dns_if_not_explicit(config):
    assert migrate(config, dns="") is False
    assert migrate(config, dns="127.0.0.11") is False
    assert parse_env(config / "stack.env")["KALI_MCP_DNS_SERVER"] == ""


def test_migration_discovers_real_hostconfig_instead_of_host_resolv(config, monkeypatch):
    def inspect(args, **kwargs):
        assert args[0:2] == ["docker", "inspect"]
        assert args[-1] == "kali-mcp-core"
        return SimpleNamespace(returncode=0, stdout='["192.168.137.1"]')
    monkeypatch.setattr("scripts.preserve_core_dns.subprocess.run", inspect)
    assert migrate(config) is True
    assert parse_env(config / "stack.env")["KALI_MCP_DNS_SERVER"] == "192.168.137.1"


def test_migration_does_not_guess_among_many_dns_servers(config, monkeypatch):
    def inspect(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout='["192.168.137.1", "8.8.8.8"]')
    monkeypatch.setattr("scripts.preserve_core_dns.subprocess.run", inspect)
    assert migrate(config) is False
