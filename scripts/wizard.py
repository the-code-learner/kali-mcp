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
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from kali_mcp.superuser import make_record, read_record, save_record, verify, valid_username, validate_password
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


def setup_superuser(path: Path, old: dict[str, str], *, interactive: bool) -> str:
    """Create/retain the single local superuser for WebUI and CLI.

    Never write the plaintext password to Compose or systemd environments.
    """
    credential_file = path / "superuser.json"
    if credential_file.is_file():
        record = read_record(credential_file)
        username = record["username"]
        if not interactive:
            return username
        print("\nExisting Kali MCP superuser:", username)
        prior = getpass.getpass("Confirm existing superuser password: ")
        if not verify(record, username, prior):
            raise ValueError("Superuser reconfiguration denied")
        if yesno("Keep current superuser credentials", True):
            return username
        suggested = username
    else:
        suggested = "admin"

    username = (ask("Create superuser username", suggested)
                if interactive else os.getenv("KALI_MCP_SUPERUSER_NAME", suggested))
    if not valid_username(username):
        raise ValueError("Invalid superuser name (3-32 lowercase letters/digits/._-)")
    if interactive:
        if yesno("Generate a strong superuser password", True):
            pw = secrets.token_urlsafe(36)
            print("\nSave your superuser password securely; displayed ONCE:")
            print(pw + "\n")
        else:
            pw = getpass.getpass("Superuser password (16+ characters): ")
            confirm = getpass.getpass("Repeat superuser password: ")
            if pw != confirm:
                raise ValueError("Passwords do not match")
    else:
        # Existing beta installs used an admin password inside stack.env.
        # Migrate that credential to a slow hash, then remove plaintext.
        pw = os.getenv("KALI_MCP_ADMIN_PASSWORD") or old.get("KALI_MCP_ADMIN_PASSWORD", "")
        if not pw:
            raise ValueError("Noninteractive bootstrap requires an initial superuser password")
    validate_password(pw)
    save_record(credential_file, make_record(username, pw))
    return username



def write_private(path: Path, data: dict[str, str] | str) -> None:
    """Durable atomic private-file replacement, never truncate live config."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (data if isinstance(data, str) else
               "".join(f"{key}={value}\n" for key, value in data.items()))
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def is_complete(path: Path) -> bool:
    """A marker is valid only with all expected credentials/environment files."""
    try:
        marker = path / "config.ready"
        if marker.read_text(encoding="utf-8") != "v1\n":
            return False
        stack, agent = parse_env(path / "stack.env"), parse_env(path / "agent.env")
        read_record(path / "superuser.json")
        required = ("KALI_MCP_PUBLIC_URL", "KALI_MCP_RELEASE_CHANNEL",
                    "KALI_MCP_ALLOW_HOST_EXEC", "KALI_MCP_BROKER_SOCKET")
        if any(not stack.get(name) for name in required[:3]):
            return False
        if not agent.get(required[3]) or not agent.get("KALI_MCP_HOST_USER"):
            return False
        if any(agent.get(k) != v for k, v in stack.items()
               if k in agent and k != "KALI_MCP_AGENT_GID"):
            return False
        if not valid_origin(stack["KALI_MCP_PUBLIC_URL"]):
            return False
        if not (agent.get("KALI_MCP_SUPERUSER_FILE") == "/etc/kali-mcp/superuser.json"):
            return False
        for filename in ("config.ready", "stack.env", "agent.env", "superuser.json"):
            item = path / filename
            if not item.is_file() or item.stat().st_mode & 0o077:
                return False
        return True
    except (OSError, ValueError, KeyError):
        return False


def configure(path: Path, gid: int, *, interactive: bool, host_user: str = "kali") -> dict[str, str]:
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
    bind_default = old.get("KALI_MCP_BIND_ADDRESS", "127.0.0.1")
    bind = (ask("HTTP bind IP (127.0.0.1 or 0.0.0.0)", bind_default,
                choices={"127.0.0.1", "0.0.0.0"}) if interactive
            else os.getenv("KALI_MCP_BIND_ADDRESS", bind_default))
    if bind not in {"127.0.0.1", "0.0.0.0"}:
        raise ValueError("Invalid bind address")
    if bind == "0.0.0.0":
        print("WARNING: 0.0.0.0 exposes an HTTP origin on every network interface.")
        print("A password alone does not prevent network credential interception.")
        print("Require a firewall and an HTTPS reverse proxy / Cloudflare Access.")
        if not origin.startswith("https://"):
            raise ValueError("Public binding requires a configured HTTPS canonical origin")
        if interactive and not yesno("I have restricted direct port access by firewall", False):
            raise ValueError("Refusing unprotected wide-area binding")

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

    install_updates = (yesno("Allow administrator WebUI/MCP update installation",
                       old.get("KALI_MCP_ALLOW_MCP_UPDATES", "false") == "true")
                       if interactive else os.getenv("KALI_MCP_ALLOW_MCP_UPDATES",
                       old.get("KALI_MCP_ALLOW_MCP_UPDATES", "false")) == "true")
    old_origins = old.get("KALI_MCP_BROWSER_ORIGINS", "")
    browser_origins = (ask("MCP browser origins, comma-separated (empty=none)", old_origins)
                       if interactive and yesno("Configure additional browser origins", bool(old_origins))
                       else os.getenv("KALI_MCP_BROWSER_ORIGINS", old_origins)
                       if not interactive else old_origins)
    origins = [o.strip() for o in browser_origins.split(",") if o.strip()]
    if len(origins) > 12 or len(set(origins)) != len(origins) or any(
            not valid_origin(o) for o in origins):
        raise ValueError("MCP browser origins must be exact HTTPS/localhost origins")
    username = setup_superuser(path, old, interactive=interactive)
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
        "KALI_MCP_ALLOW_MCP_UPDATES": str(install_updates).lower(),
        "KALI_MCP_UPDATE_CHECK_SECONDS": "21600",
        "KALI_MCP_MAX_JOB_SECONDS": "300",
        "KALI_MCP_PORT": "8787",
        "KALI_MCP_BIND_ADDRESS": bind,
        "KALI_MCP_ACCESS_MODE": access,
        "KALI_MCP_AGENT_GID": str(gid),
        "KALI_MCP_BROWSER_ORIGINS": ",".join(origins),
    }
    for name, value in shared.items():
        if value or name != "KALI_MCP_BROWSER_ORIGINS":
            if not SAFE_VALUE.fullmatch(value):
                raise ValueError("Invalid configuration value for " + name)
    write_private(path / "stack.env", shared)
    host = {k: value for k, value in shared.items()
            if k.startswith("KALI_MCP_") and k not in {"KALI_MCP_ACCESS_MODE", "KALI_MCP_PORT", "KALI_MCP_AGENT_GID"}}
    host["KALI_MCP_BROKER_SOCKET"] = "/run/kali-mcp-agent/agent.sock"
    host["KALI_MCP_AGENT_GROUP"] = "kalimcp"
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{1,31}", host_user):
        raise ValueError("Invalid host user")
    host["KALI_MCP_HOST_USER"] = host_user
    host["KALI_MCP_SUPERUSER_FILE"] = "/etc/kali-mcp/superuser.json"
    write_private(path / "agent.env", host)
    # The completion marker must be the very last publication step.
    write_private(path / "config.ready", "v1\n")
    if not is_complete(path):
        raise RuntimeError("Configuration failed post-commit validation")
    print("\nConfiguration saved with hashed superuser credentials (no plaintext password in Compose).")
    print("WebUI and kali-mcp CLI superuser:", username)
    print("Channel:", channel, "| Remote access:", access, "| OAuth base URL:", origin)
    print("Root ceiling:", root, "| Root active by default: false")
    return shared


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH-friendly Kali MCP setup wizard")
    parser.add_argument("--config-dir", default="/etc/kali-mcp")
    parser.add_argument("--agent-gid", type=int, default=0)
    parser.add_argument("--host-user", default="kali")
    parser.add_argument("--verify", action="store_true",
                        help="Exit 0 only for a committed complete configuration")
    parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args()
    if args.verify:
        raise SystemExit(0 if is_complete(Path(args.config_dir)) else 1)
    if args.agent_gid <= 0:
        parser.error("--agent-gid is required for configuration")
    configure(Path(args.config_dir), args.agent_gid,
              interactive=not args.non_interactive, host_user=args.host_user)


if __name__ == "__main__":
    main()
