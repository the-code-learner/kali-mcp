"""Centralized administrator ceilings and authorization scope validation."""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterable

from .config import Config
from .store import Store


class PolicyDenied(PermissionError):
    pass


class Policy:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store

    def require(self, feature: str, *, actor: str = "mcp") -> None:
        ceilings = self.cfg.ceilings()
        if feature not in ceilings:
            raise PolicyDenied("Unknown capability")
        if not ceilings[feature]["allowed"]:
            self.store.audit(actor, feature, "deny", "YAML ceiling: " + ceilings[feature]["yaml"])
            raise PolicyDenied(f"Disabled by deployment setting {ceilings[feature]['yaml']}")
        if feature.startswith("mcp_"):
            return
        if not self.store.get_setting(feature):
            self.store.audit(actor, feature, "deny", "WebUI toggle off")
            raise PolicyDenied(f"{feature} disabled in WebUI")

    def check_execution(self, mode: str, *, root: bool, actor: str) -> None:
        if mode not in {"sandbox", "host"}:
            raise PolicyDenied("Execution mode must be sandbox or host")
        if mode == "host":
            self.require("host_exec", actor=actor)
            if actor != "webui":
                self.require("mcp_host_exec", actor=actor)
        if root:
            if mode != "host":
                raise PolicyDenied("Root requires host execution")
            self.require("host_root", actor=actor)
            if actor != "webui":
                self.require("mcp_root", actor=actor)

    def set_webui(self, feature: str, value: bool) -> None:
        if feature not in {"host_exec", "host_root", "package_install", "network_changes", "mcp_updates"}:
            raise PolicyDenied("Unknown toggle")
        if value and not self.cfg.ceilings()[feature]["allowed"]:
            raise PolicyDenied(f"Change {self.cfg.ceilings()[feature]['yaml']} in kali-mcp.yml first")
        if feature == "host_root" and value and not self.store.get_setting("host_exec"):
            raise PolicyDenied("Enable host execution first")
        self.store.set_setting(feature, value, "webui")
        if feature == "host_exec" and not value:
            # Never leave a stale enabled root toggle after host execution is off.
            self.store.set_setting("host_root", False, "webui")

    def check_target(self, target: str) -> str:
        """Resolve a single host, reject any address outside authorized networks.

        Tool adapters should execute with the returned numeric address, never
        re-resolve the hostname after checking it (DNS rebinding defense).
        """
        if any(c in target for c in " /\\,:;") or len(target) > 253 or not target:
            raise PolicyDenied("Expected a single IP or hostname")
        try:
            addresses = [ipaddress.ip_address(target)]
        except ValueError:
            try:
                records = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise PolicyDenied("Could not resolve target") from exc
            addresses = list({ipaddress.ip_address(row[4][0]) for row in records})
        if not addresses:
            raise PolicyDenied("No target address")
        allowed = [ipaddress.ip_network(x, strict=False) for x in self.cfg.allowed_cidrs]
        if not all(any(address in network for network in allowed) for address in addresses):
            raise PolicyDenied("Target is outside authorized scope")
        return str(sorted(addresses, key=lambda x: (x.version, int(x)))[0])


def validate_argv(argv: Iterable[str]) -> list[str]:
    result = list(argv)
    if not result or len(result) > 64:
        raise PolicyDenied("Missing or excessive arguments")
    if any(not isinstance(x, str) or not x or "\0" in x or len(x) > 2048 for x in result):
        raise PolicyDenied("Invalid argument")
    return result
