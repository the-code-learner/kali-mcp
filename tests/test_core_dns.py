"""Regression coverage for opt-in Docker Core DNS without global daemon changes."""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest
import yaml

from kali_mcp.deployment_settings import normalize_dns_server, normalized_field, validate_change
from kali_mcp.cli_config import parse_env
from scripts.wizard import configure, is_complete

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("address", [
    "192.168.137.1", "10.0.0.53", "1.1.1.1", "2001:4860:4860::8888",
])
def test_dns_accepts_network_upstream_ips(address):
    assert normalize_dns_server(address) == address
    assert normalized_field("KALI_MCP_DNS_SERVER", address) == address
    assert validate_change({}, {"KALI_MCP_DNS_SERVER": address}) == {
        "KALI_MCP_DNS_SERVER": address
    }


@pytest.mark.parametrize("address", [
    "127.0.0.1", "::1", "",  # empty handled by separate test
    "0.0.0.0", "224.0.0.1", "fe80::1",
    "api.github.com", "192.168.137.1:53", "192.168.137.1/24",
    "192.168.137.1 $(id)", "\$(echo bad)", " 192.168.137.1",
])
def test_dns_rejects_unsafe_or_unusable_values(address):
    if address == "":
        assert normalize_dns_server("") == ""
        return
    with pytest.raises(ValueError):
        normalize_dns_server(address)


def test_wizard_retains_opt_in_dns_and_does_not_set_public_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "TEST_32_CHAR_URL_SAFE_PASSWORD_2026")
    monkeypatch.setenv("KALI_MCP_RELEASE_CHANNEL", "beta")
    monkeypatch.setenv("KALI_MCP_ACCESS_MODE", "local")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_ROOT", "false")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_EXEC", "false")
    monkeypatch.setenv("KALI_MCP_DNS_SERVER", "192.168.137.1")
    path = tmp_path / "dns-config"
    configure(path, 912, interactive=False)
    assert parse_env(path / "stack.env")["KALI_MCP_DNS_SERVER"] == "192.168.137.1"
    assert parse_env(path / "agent.env")["KALI_MCP_DNS_SERVER"] == "192.168.137.1"
    assert is_complete(path)

    # An existing site stays configured when a later wizard run omits the env.
    monkeypatch.delenv("KALI_MCP_DNS_SERVER")
    configure(path, 912, interactive=False)
    assert parse_env(path / "stack.env")["KALI_MCP_DNS_SERVER"] == "192.168.137.1"


def test_wizard_default_dns_is_not_forced(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "TEST_32_CHAR_URL_SAFE_PASSWORD_2026")
    monkeypatch.setenv("KALI_MCP_RELEASE_CHANNEL", "beta")
    monkeypatch.setenv("KALI_MCP_ACCESS_MODE", "local")
    monkeypatch.delenv("KALI_MCP_DNS_SERVER", raising=False)
    monkeypatch.delenv("KALI_MCP_ALLOW_HOST_EXEC", raising=False)
    monkeypatch.delenv("KALI_MCP_ALLOW_HOST_ROOT", raising=False)
    path = tmp_path / "default"
    configure(path, 912, interactive=False)
    assert parse_env(path / "stack.env")["KALI_MCP_DNS_SERVER"] == ""
    assert is_complete(path)


def test_dns_compose_overlay_is_only_optional_and_core_scoped():
    base = yaml.safe_load((ROOT / "kali-mcp-hybrid.yml").read_text())
    overlay = yaml.safe_load((ROOT / "kali-mcp-hybrid-dns.yml").read_text())
    assert "dns" not in base["services"]["kali-mcp-core"]
    assert list(overlay["services"]) == ["kali-mcp-core"]
    assert "dns" in overlay["services"]["kali-mcp-core"]
    assert overlay["services"]["kali-mcp-core"]["dns"] == [
        "${KALI_MCP_DNS_SERVER:?Configure a validated upstream DNS IP}"
    ]
    script = ROOT / "scripts/compose-hybrid.sh"
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0


def test_dns_override_renders_with_compose_only_when_selected(tmp_path):
    if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode:
        pytest.skip("Compose CLI not present")
    env = tmp_path / "stack.env"
    env.write_text("KALI_MCP_AGENT_GID=912\nKALI_MCP_DNS_SERVER=192.168.137.1\n")
    args = ["docker", "compose", "--env-file", str(env),
            "-f", str(ROOT / "kali-mcp-hybrid.yml"),
            "-f", str(ROOT / "kali-mcp-hybrid-dns.yml"), "config"]
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    rendered = yaml.safe_load(result.stdout)
    assert rendered["services"]["kali-mcp-core"]["dns"] == ["192.168.137.1"]
