"""Deployment ceilings and runtime config. No secrets are returned to clients."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlparse

from .browser_origins import parse_browser_origins


def flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, "true" if default else "false").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    base_url: str
    data_dir: Path
    broker_socket: Path
    admin_password: str
    allow_host_exec: bool
    allow_host_root: bool
    allow_package_install: bool
    allow_network_changes: bool
    allow_mcp_updates: bool
    allow_mcp_host_exec: bool
    allow_mcp_root: bool
    allowed_cidrs: tuple[str, ...]
    update_channel: str
    repo: str
    check_interval: int
    max_job_seconds: int
    browser_origins: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "Config":
        url = os.getenv("KALI_MCP_PUBLIC_URL", "http://localhost:8787").rstrip("/")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("KALI_MCP_PUBLIC_URL must be a canonical http(s) origin with no path, credentials or query")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Remote KALI_MCP_PUBLIC_URL must use HTTPS")
        channel = os.getenv("KALI_MCP_RELEASE_CHANNEL", "stable").strip()
        if channel not in {"stable", "beta"}:
            raise ValueError("KALI_MCP_RELEASE_CHANNEL must be stable or beta")
        interval = int(os.getenv("KALI_MCP_UPDATE_CHECK_SECONDS", "21600"))
        if interval < 900:
            raise ValueError("Update interval must be >= 900 seconds")
        browser_origins = parse_browser_origins(os.getenv("KALI_MCP_BROWSER_ORIGINS", ""))
        return cls(
            base_url=url,
            data_dir=Path(os.getenv("KALI_MCP_DATA_DIR", "/data")),
            broker_socket=Path(os.getenv("KALI_MCP_BROKER_SOCKET", "/run/kali-mcp/broker.sock")),
            admin_password=os.getenv("KALI_MCP_ADMIN_PASSWORD", ""),
            allow_host_exec=flag("KALI_MCP_ALLOW_HOST_EXEC"),
            allow_host_root=flag("KALI_MCP_ALLOW_HOST_ROOT"),
            allow_package_install=flag("KALI_MCP_ALLOW_PACKAGE_INSTALL"),
            allow_network_changes=flag("KALI_MCP_ALLOW_NETWORK_CHANGES"),
            allow_mcp_updates=flag("KALI_MCP_ALLOW_MCP_UPDATES"),
            allow_mcp_host_exec=flag("KALI_MCP_ALLOW_MCP_HOST_EXEC"),
            allow_mcp_root=flag("KALI_MCP_ALLOW_MCP_ROOT"),
            allowed_cidrs=tuple(s.strip() for s in os.getenv("KALI_MCP_ALLOWED_CIDRS", "127.0.0.1/32").split(",") if s.strip()),
            update_channel=channel,
            repo=os.getenv("KALI_MCP_REPO", "the-code-learner/kali-mcp"),
            check_interval=interval,
            max_job_seconds=max(5, min(3600, int(os.getenv("KALI_MCP_MAX_JOB_SECONDS", "300")))),
            browser_origins=browser_origins,
        )

    @property
    def resource(self) -> str:
        return self.base_url + "/mcp"

    def ceilings(self) -> dict[str, dict]:
        return {
            "host_exec": {"allowed": self.allow_host_exec, "yaml": "KALI_MCP_ALLOW_HOST_EXEC"},
            "host_root": {"allowed": self.allow_host_root, "yaml": "KALI_MCP_ALLOW_HOST_ROOT"},
            "package_install": {"allowed": self.allow_package_install, "yaml": "KALI_MCP_ALLOW_PACKAGE_INSTALL"},
            "network_changes": {"allowed": self.allow_network_changes, "yaml": "KALI_MCP_ALLOW_NETWORK_CHANGES"},
            "mcp_host_exec": {"allowed": self.allow_mcp_host_exec, "yaml": "KALI_MCP_ALLOW_MCP_HOST_EXEC"},
            "mcp_root": {"allowed": self.allow_mcp_root, "yaml": "KALI_MCP_ALLOW_MCP_ROOT"},
            "mcp_updates": {"allowed": self.allow_mcp_updates, "yaml": "KALI_MCP_ALLOW_MCP_UPDATES"},
        }
