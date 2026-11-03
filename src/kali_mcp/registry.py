"""Stable dynamic tool registry; adding a manifest never adds an MCP function."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shutil

from .policy import Policy, PolicyDenied


@dataclass(frozen=True)
class Tool:
    id: str
    description: str
    executable: str
    package: str
    category: str
    actions: tuple[str, ...]


# Known installer recipes are controlled by the project, not arbitrary MCP input.
BUILTINS: tuple[Tool, ...] = (
    Tool("nmap", "Network discovery and service inventory", "nmap", "nmap", "network", ("version", "quick", "services")),
    Tool("dig", "DNS lookup", "dig", "dnsutils", "dns", ("version", "lookup")),
    Tool("curl", "HTTP response metadata", "curl", "curl", "web", ("version", "headers")),
    Tool("openssl", "TLS tooling and certificate information", "openssl", "openssl", "tls", ("version",)),
    Tool("tshark", "Read packet capture file metadata", "tshark", "tshark", "capture", ("version",)),
    Tool("tcpdump", "Capture tooling and diagnostics", "tcpdump", "tcpdump", "capture", ("version",)),
    Tool("nikto", "Web server analysis", "nikto", "nikto", "web", ("version",)),
    Tool("wireshark", "Packet analysis (GUI)", "wireshark", "wireshark", "capture", ("version",)),
    Tool("aircrack-ng", "Wireless assessment toolkit", "aircrack-ng", "aircrack-ng", "wireless", ("version",)),
    Tool("kismet", "Wireless visibility and detection", "kismet", "kismet", "wireless", ("version",)),
)

KNOWN = {t.id: t for t in BUILTINS}
PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,79}$")


def discover(query: str = "") -> list[dict]:
    return [
        {"id": t.id, "description": t.description, "category": t.category,
         "package": t.package, "installed_in_container": bool(shutil.which(t.executable)), "actions": t.actions}
        for t in BUILTINS if query.lower() in (t.id + " " + t.description + " " + t.category).lower()
    ]


def tool_command(tool_id: str, action: str, params: dict, policy: Policy) -> list[str]:
    """Typed, bounded commands; no generic command/flags passthrough."""
    if tool_id not in KNOWN:
        raise PolicyDenied("Unknown tool: use an approved manifest or host shell if permitted")
    tool = KNOWN[tool_id]
    if action not in tool.actions:
        raise PolicyDenied("Unsupported action")
    if action == "version":
        if tool_id == "openssl":
            return ["openssl", "version"]
        if tool_id in {"nmap", "curl", "tshark", "tcpdump", "aircrack-ng"}:
            return [tool.executable, "--version"]
        return [tool.executable, "-v"]
    if tool_id == "nmap":
        target = policy.check_target(str(params.get("target", "")))
        if action == "quick":
            return ["nmap", "-sT", "-Pn", "-T2", "--top-ports", "100", target]
        if action == "services":
            ports = params.get("ports", [22, 80, 443])
            if not isinstance(ports, list) or not (1 <= len(ports) <= 128) or any(not isinstance(p, int) or p < 1 or p > 65535 for p in ports):
                raise PolicyDenied("ports must be 1-128 valid TCP port numbers")
            return ["nmap", "-sT", "-Pn", "-sV", "-T2", "-p", ",".join(str(p) for p in sorted(set(ports))), target]
    if tool_id == "dig" and action == "lookup":
        name = str(params.get("name", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", name):
            raise PolicyDenied("Invalid DNS hostname")
        return ["dig", "+time=2", "+tries=1", name]
    if tool_id == "curl" and action == "headers":
        # Limiting this to authorized targets prevents generic HTTP SSRF.
        host = policy.check_target(str(params.get("host", "")))
        scheme = str(params.get("scheme", "https"))
        if scheme not in {"http", "https"}:
            raise PolicyDenied("Invalid HTTP scheme")
        return ["curl", "--head", "--max-time", "15", "--proto", "=http,https", f"{scheme}://{host}/"]
    raise PolicyDenied("Action not yet implemented")


def installer_argv(tool_id: str) -> list[str]:
    tool = KNOWN.get(tool_id)
    if tool is None or not PACKAGE_NAME.fullmatch(tool.package):
        raise PolicyDenied("Only built-in reviewed packages may be installed")
    return ["apt-get", "install", "-y", "--no-install-recommends", tool.package]
