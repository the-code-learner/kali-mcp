"""Strict schema for administrator-owned hybrid deployment configuration.

Only well-defined, bounded, nonsecret settings are mutable via the dashboard.
All other installer-owned/environment settings are visible with secrets masked.
Scope decision order: explicit deny > allow-all > explicit allow list > deny.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlparse


MAX_CIDRS = 64
NETWORK_LABEL = "IP/CIDR (IPv4 or IPv6)"
_SECRET_PATTERN = re.compile(r"(PASSWORD|SECRET|TOKEN|PRIVATE_KEY|CREDENTIAL|API_KEY|AUTH_KEY)", re.I)
_KEY_PATTERN = re.compile(r"^KALI_MCP_[A-Z0-9_]+$")


@dataclass(frozen=True)
class Field:
    name: str
    group: str
    kind: str
    default: str
    description: str
    restart: str = "core"


EDITABLE_FIELDS = (
    Field("KALI_MCP_ALLOWED_CIDRS", "Scope", "cidrs", "127.0.0.1/32",
          "Allowed IP networks or individual hosts when Allow all is off"),
    Field("KALI_MCP_DENIED_CIDRS", "Scope", "cidrs", "",
          "Always blocked; takes priority over every allowed network and Allow all"),
    Field("KALI_MCP_ALLOW_ALL_TARGETS", "Scope", "bool", "false",
          "Allow all IP targets except those explicitly blacklisted"),
    Field("KALI_MCP_ALLOW_HOST_EXEC", "Permissions", "bool", "false",
          "Host Agent maximum permission to execute host commands", "both"),
    Field("KALI_MCP_ALLOW_HOST_ROOT", "Permissions", "bool", "false",
          "Host Agent maximum permission to execute as root", "both"),
    Field("KALI_MCP_ALLOW_MCP_HOST_EXEC", "Permissions", "bool", "false",
          "Allow MCP clients to use enabled host-execution capability", "both"),
    Field("KALI_MCP_ALLOW_MCP_ROOT", "Permissions", "bool", "false",
          "Allow MCP clients to use enabled host-root capability", "both"),
    Field("KALI_MCP_ALLOW_PACKAGE_INSTALL", "Permissions", "bool", "false",
          "Host Agent maximum permission to install reviewed packages", "both"),
    Field("KALI_MCP_ALLOW_NETWORK_CHANGES", "Permissions", "bool", "false",
          "Host Agent maximum permission to change network settings", "both"),
    Field("KALI_MCP_ALLOW_MCP_UPDATES", "Permissions", "bool", "false",
          "Allow authenticated MCP update operations", "both"),
    Field("KALI_MCP_API_HEADER_ENABLED", "Authentication", "bool", "true",
          "Enable API Bearer authentication alongside OAuth"),
    Field("KALI_MCP_RELEASE_CHANNEL", "Updates", "channel", "beta",
          "GitHub update channel for eligible releases", "both"),
    Field("KALI_MCP_UPDATE_CHECK_SECONDS", "Updates", "update_seconds", "21600",
          "Interval between release checks; minimum 15 minutes"),
    Field("KALI_MCP_MAX_JOB_SECONDS", "Jobs", "job_seconds", "300",
          "Maximum execution time for one job (5–3600 seconds)", "both"),
    Field("KALI_MCP_PORT", "Networking", "port", "8787",
          "Published host port for Core (changing can disrupt tunnels)"),
    Field("KALI_MCP_BIND_ADDRESS", "Networking", "bind", "127.0.0.1",
          "Host binding interface; 0.0.0.0 exposes the authenticated WebUI"),
    Field("KALI_MCP_PUBLIC_URL", "Networking", "origin", "http://localhost:8787",
          "Canonical WebUI/MCP public origin (changing may require new login)", "both"),
)
FIELD_MAP = {item.name: item for item in EDITABLE_FIELDS}

# The root worker does not accept arbitrary credentials, paths, systemd units
# or unknown environment keys. These remain visible but separately managed.
READONLY_REASONS = {
    "KALI_MCP_BROWSER_ORIGINS": "Managed in the dedicated Browser Origins / CORS panel",
    "KALI_MCP_SUPERUSER_FILE": "Managed by the installer and superuser credential workflow",
    "KALI_MCP_AGENT_GID": "Systemd socket-group identity; managed by installer",
    "KALI_MCP_AGENT_GROUP": "Systemd socket-group identity; managed by installer",
    "KALI_MCP_HOST_USER": "Local unprivileged host account; managed by installer",
    "KALI_MCP_BROKER_SOCKET": "Private Host Agent socket path; managed by installer",
    "KALI_MCP_HOST_AGENT": "Hybrid topology enforced by installer",
    "KALI_MCP_REQUIRE_SUPERUSER": "Mandatory security policy, cannot be disabled",
    "KALI_MCP_ACCESS_MODE": "Installer-controlled deployment mode",
    "KALI_MCP_REPO": "Pinned upstream repository; cannot be redirected through WebUI",
    "KALI_MCP_DATA_DIR": "Container persistent storage mount; managed by installer",
    "KALI_MCP_ADMIN_PASSWORD": "Legacy credential; never displayed or changed as plain text",
}


def parse_cidrs(value: str) -> tuple[str, ...]:
    """Canonical, unique CIDRs, never silent partial acceptance."""
    if not isinstance(value, str) or len(value) > 3072:
        raise ValueError("CIDR list is too long")
    if not value.strip():
        return ()
    parts = [part.strip() for part in value.split(",")]
    if any(not part or len(part) > 64 for part in parts) or len(parts) > MAX_CIDRS:
        raise ValueError("Use at most 64 comma-separated IP addresses or CIDRs")
    networks = []
    for part in parts:
        try:
            network = ipaddress.ip_network(part, strict=False)
        except ValueError as exc:
            raise ValueError("Invalid CIDR or IP address: " + part[:64]) from exc
        networks.append(str(network))
    if len(set(networks)) != len(networks):
        raise ValueError("Duplicate CIDR entries are not permitted")
    return tuple(networks)


def parse_bool(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError("Boolean settings must be exactly true or false")
    return value == "true"


def validate_scope(allow_all: str, allowed: str, denied: str) -> dict:
    enabled = parse_bool(allow_all)
    allow = parse_cidrs(allowed)
    deny = parse_cidrs(denied)
    if enabled and not deny:
        raise ValueError("Allow all requires at least one explicit blacklisted CIDR")
    return {"allow_all": enabled, "allowed": allow, "denied": deny}


def normalized_field(name: str, value: str) -> str:
    field = FIELD_MAP.get(name)
    if field is None:
        raise ValueError("Setting cannot be changed from the WebUI")
    if not isinstance(value, str) or len(value) > 3072 or "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("Invalid setting value")
    if field.kind == "cidrs":
        return ",".join(parse_cidrs(value))
    if field.kind == "bool":
        parse_bool(value)
        return value
    if field.kind == "channel":
        if value not in {"stable", "beta"}:
            raise ValueError("Release channel must be stable or beta")
        return value
    if field.kind in {"update_seconds", "job_seconds", "port"}:
        if not re.fullmatch(r"[0-9]{1,7}", value):
            raise ValueError("Expected a positive integer")
        number = int(value)
        bounds = {"update_seconds": (900, 86400),
                  "job_seconds": (5, 3600), "port": (1024, 65535)}
        low, high = bounds[field.kind]
        if not low <= number <= high:
            raise ValueError(f"Value must be between {low} and {high}")
        return str(number)
    if field.kind == "bind":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Bind address must be a numeric IPv4/IPv6 address") from exc
        return str(address)
    if field.kind == "origin":
        parsed = urlparse(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
                parsed.username or parsed.password or parsed.query or
                parsed.fragment or parsed.path not in {"", "/"}):
            raise ValueError("Public URL must be a canonical http(s) origin")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Remote public URL must use HTTPS")
        if value != value.strip() or len(value) > 255:
            raise ValueError("Invalid public URL")
        return value.rstrip("/")
    raise ValueError("Unsupported setting type")


def validate_change(current: dict[str, str], changes: dict[str, str]) -> dict[str, str]:
    """Validate a patch as a whole, including adjacent ceiling relationships."""
    if not isinstance(changes, dict) or not changes or len(changes) > 3:
        raise ValueError("Expected a bounded deployment change")
    normalized = {key: normalized_field(key, value) for key, value in changes.items()}
    next_values = {**current, **normalized}
    validate_scope(next_values.get("KALI_MCP_ALLOW_ALL_TARGETS", "false"),
                   next_values.get("KALI_MCP_ALLOWED_CIDRS", "127.0.0.1/32"),
                   next_values.get("KALI_MCP_DENIED_CIDRS", ""))
    scope_keys = {"KALI_MCP_ALLOWED_CIDRS", "KALI_MCP_DENIED_CIDRS",
                  "KALI_MCP_ALLOW_ALL_TARGETS"}
    if scope_keys.intersection(changes) and not scope_keys.issuperset(changes):
        raise ValueError("Scope settings cannot be mixed with deployment ceilings")
    if (next_values.get("KALI_MCP_ALLOW_HOST_ROOT", "false") == "true" and
            next_values.get("KALI_MCP_ALLOW_HOST_EXEC", "false") != "true"):
        raise ValueError("Root ceiling requires Host Exec ceiling")
    if (next_values.get("KALI_MCP_ALLOW_MCP_ROOT", "false") == "true" and
            next_values.get("KALI_MCP_ALLOW_MCP_HOST_EXEC", "false") != "true"):
        raise ValueError("MCP Root ceiling requires MCP Host Exec ceiling")
    return normalized


def public_inventory(stack: dict[str, str], agent: dict[str, str]) -> list[dict]:
    """All known keys are shown, but never reveal secret values or arbitrary paths."""
    keys = sorted(set(stack) | set(agent) | set(FIELD_MAP) | set(READONLY_REASONS))
    result = []
    for key in keys:
        if not _KEY_PATTERN.fullmatch(key):
            continue
        field = FIELD_MAP.get(key)
        secret = _SECRET_PATTERN.search(key) is not None
        stored = stack.get(key, agent.get(key))
        value = (stored if stored is not None else field.default if field else "(installer managed)")
        result.append({
            "name": key, "value": "(hidden)" if secret else value,
            "editable": field is not None and not secret,
            "group": field.group if field else "Installer / internal",
            "type": field.kind if field else "readonly",
            "description": field.description if field else READONLY_REASONS.get(
                key, "Not editable from WebUI: installer-managed or unknown setting"),
            "source": "stack.env" if key in stack else
                      "agent.env" if key in agent else "default",
        })
    return result
