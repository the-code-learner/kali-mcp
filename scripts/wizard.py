"""SSH-friendly setup wizard for Kali MCP hybrid installations.

No curses dependency; line-oriented prompts work over ordinary SSH terminals.
Only writes files under the provided --config-dir (installer invokes as root).
"""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlparse

ENV = re.compile(r"^([A-Z][A-Z0-9_]*)=([^\r\n]*)$")
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./:+,@=-]{1,512}$")
CAPABILITIES = ("HOST_EXEC", "HOST_ROOT", "PACKAGE_INSTALL", "NETWORK_CHANGES")
INTRO = """
╔══════════════════════════════════════════════════════════════╗
║  KALI MCP · Hybrid Installation Wizard                       ║
║  Kali Linux · Docker non-privileged · systemd Host Agent       ║
╚══════════════════════════════════════════════════════════════╝

This installer keeps the WebUI/MCP in an unprivileged Docker container.
The native systemd Agent can execute host commands, including root ONLY
when the host policy and the administrator allow it.
"""


def parse_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = ENV.fullmatch(line)
        if match:
            data[match.group(1)] = match.group(2).strip('"')
    return data


def valid_origin(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return (parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in
                {"localhost", "127.0.0.1", "::1"})) and bool(parsed.hostname) and not any(
            (parsed.username, parsed.password, parsed.query, parsed.fragment, parsed.params,
             parsed.path not in {"", "/"}))
    except ValueError:
        return False


def ask(question: str, default: str, *, choices: set[str] | None = None) -> str:
    while True:
        reply = input(f"{question} [{default}]: ").strip() or default
        if choices is None or reply in choices:
            return reply
        print("Allowed:", ", ".join(sorted(choices)))


def yesno(question: str, default: bool = False) -> bool:
    initial = "y" if default else "n"
    return ask(question + " (y/n)", initial, choices={"y", "n"}) == "y"


def password(existing: str | None, *, interactive: bool) -> str:
    if existing:
        if not interactive or yesno("Keep existing administrator password", True):
            return existing
    if not interactive:
        candidate = os.getenv("KALI_MCP_ADMIN_PASSWORD") or secrets.token_urlsafe(32)
        if not SAFE_VALUE.fullmatch(candidate) or len(candidate) < 16:
            raise ValueError("Administrator password must be 16+ printable URL-safe characters")
        return candidate
    if yesno("Generate a secure 43-character administrator password", True):
        candidate = secrets.token_urlsafe(32)
        print("\nSave this password now; it will NOT be shown again:")
        print(candidate + "\n")
        return candidate
    while True:
        candidate = getpass.getpass("Administrator password (16+ URL-safe characters): ")
        again = getpass.getpass("Confirm administrator password: ")
        if candidate != again or len(candidate) < 16 or not SAFE_VALUE.fullmatch(candidate):
            print("Passwords must match, contain 16+ characters and avoid spaces/$/quotes.")
            continue
        return candidate


def write_private(path: Path, data: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(f"{key}={value}\n" for key, value in data.items())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(path, 0o600)
    except BaseException:
        raise


def configure(path: Path, gid: int, *, interactive: bool) -> dict[str, str]:
    old = parse_env(path / "stack.env")
    print(INTRO)
    if interactive:
        channel = ask("GitHub update channel", old.get("KALI_MCP_RELEASE_CHANNEL", "beta"),
                      choices={"stable", "beta"})
        access = ask("Remote access: local / tailscale / cloudflare",
                     old.get("KALI_MCP_ACCESS_MODE", "local"),
                     choices={"local", "tailscale", "cloudflare"})
    else:
        channel = os.getenv("KALI_MCP_RELEASE_CHANNEL", old.get("KALI_MCP_RELEASE_CHANNEL", "beta"))
        access = os.getenv("KALI_MCP_ACCESS_MODE", old.get("KALI_MCP_ACCESS_MODE", "local"))
        if channel not in {"beta", "stable"} or access not in {"local", "tailscale", "cloudflare"}:
            raise ValueError("Unsupported channel/access mode")

    default_origin = old.get("KALI_MCP_PUBLIC_URL", "http://localhost:8787")
    if access == "cloudflare":
        print("Cloudflare: configure HTTPS and Access rules before connecting a hosted MCP client.")
        origin = (ask("Canonical HTTPS origin (no /mcp)", default_origin)
                  if interactive else os.getenv("KALI_MCP_PUBLIC_URL", default_origin))
        if not origin.startswith("https://"):
            raise ValueError("Cloudflare mode requires an HTTPS origin")
    elif access == "tailscale":
        print("Tailscale Serve is PRIVATE to your tailnet; hosted cloud clients cannot use it directly.")
        print("The access wizard can connect Tailscale and discover your HTTPS *.ts.net URL later.")
        origin = (ask("Tailscale HTTPS origin, or localhost until linked", default_origin)
                  if interactive else os.getenv("KALI_MCP_PUBLIC_URL", default_origin))
    else:
        origin = "http://localhost:8787"
    if not valid_origin(origin):
        raise ValueError("Invalid canonical HTTPS origin")

    previous_allow = old.get("KALI_MCP_ALLOW_HOST_EXEC", "false") == "true"
    host_exec = (yesno("Permit enabling unprivileged Kali HOST commands in WebUI", previous_allow)
                 if interactive else os.getenv("KALI_MCP_ALLOW_HOST_EXEC", "false") == "true")
    previous_root = old.get("KALI_MCP_ALLOW_HOST_ROOT", "false") == "true"
    root = (yesno("Permit a future ROOT toggle in the WebUI (HIGH RISK)", previous_root)
            if interactive and host_exec else
            os.getenv("KALI_MCP_ALLOW_HOST_ROOT", "false") == "true" and host_exec
            if not interactive else False)
    if root and interactive:
        if not yesno("Root access can fully control or destroy this Kali system. Continue", False):
            root = False

    pw = password(old.get("KALI_MCP_ADMIN_PASSWORD"), interactive=interactive)
    shared = {
        "KALI_MCP_PUBLIC_URL": origin,
        "KALI_MCP_RELEASE_CHANNEL": channel,
        "KALI_MCP_ALLOWED_CIDRS": old.get("KALI_MCP_ALLOWED_CIDRS", "127.0.0.1/32"),
        "KALI_MCP_ALLOW_HOST_EXEC": str(host_exec).lower(),
        "KALI_MCP_ALLOW_HOST_ROOT": str(root).lower(),
        "KALI_MCP_ALLOW_MCP_HOST_EXEC": str(host_exec).lower(),
        "KALI_MCP_ALLOW_MCP_ROOT": str(root).lower(),
        "KALI_MCP_ALLOW_PACKAGE_INSTALL": old.get("KALI_MCP_ALLOW_PACKAGE_INSTALL", "false"),
        "KALI_MCP_ALLOW_NETWORK_CHANGES": old.get("KALI_MCP_ALLOW_NETWORK_CHANGES", "false"),
        "KALI_MCP_ALLOW_MCP_UPDATES": old.get("KALI_MCP_ALLOW_MCP_UPDATES", "false"),
        "KALI_MCP_UPDATE_CHECK_SECONDS": "21600",
        "KALI_MCP_MAX_JOB_SECONDS": "300",
        "KALI_MCP_PORT": "8787",
        "KALI_MCP_ACCESS_MODE": access,
        "KALI_MCP_AGENT_GID": str(gid),
    }
    for name, value in shared.items():
        if not SAFE_VALUE.fullmatch(value):
            raise ValueError("Invalid configuration value for " + name)
    write_private(path / "stack.env", {**shared, "KALI_MCP_ADMIN_PASSWORD": pw})
    host = {k: value for k, value in shared.items()
            if k.startswith("KALI_MCP_") and k not in {"KALI_MCP_ACCESS_MODE", "KALI_MCP_PORT", "KALI_MCP_AGENT_GID"}}
    host["KALI_MCP_BROKER_SOCKET"] = "/run/kali-mcp-agent/agent.sock"
    host["KALI_MCP_AGENT_GROUP"] = "kalimcp"
    host["KALI_MCP_HOST_USER"] = "kali"
    write_private(path / "agent.env", host)
    print("\nConfiguration saved to /etc/kali-mcp (mode 0600).")
    print("Channel:", channel, "| Remote access:", access, "| OAuth base URL:", origin)
    print("Root ceiling:", root, "| Root active by default: false")
    return shared


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH-friendly Kali MCP setup wizard")
    parser.add_argument("--config-dir", default="/etc/kali-mcp")
    parser.add_argument("--agent-gid", type=int, required=True)
    parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args()
    configure(Path(args.config_dir), args.agent_gid, interactive=not args.non_interactive)


if __name__ == "__main__":
    main()
