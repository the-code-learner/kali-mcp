"""Kali MCP terminal control center; suitable for SSH and serial consoles.

Run as root via sudo kali-mcp to manage local services and high-impact gates.
No dependency on the WebUI being accessible, no direct TCP administrator API.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse

from .broker_client import BrokerError, call
from .config import Config
from .store import Store
from .releases import UpdateChecker
from .superuser import DEFAULT_HOST_FILE, read_record, record_fingerprint, verify

ROOT = Path("/opt/kali-mcp")
ETC = Path("/etc/kali-mcp")
CORE = Path("/var/lib/kali-mcp/core")
COMPOSE = ROOT / "current" / "kali-mcp-hybrid.yml"
SOCKET = Path("/run/kali-mcp-agent/agent.sock")
AUTH_USER: str = ""
AUTH_PASSWORD: str = ""


def authenticate_local_superuser() -> None:
    """Second factor after OS sudo: the same named superuser as the WebUI."""
    global AUTH_USER, AUTH_PASSWORD
    file = Path(os.getenv("KALI_MCP_SUPERUSER_FILE", str(DEFAULT_HOST_FILE)))
    record = read_record(file)
    secret_file = os.getenv("KALI_MCP_CLI_PASSWORD_FILE")
    if secret_file:
        # Optional root-only secret file for CI/unattended LOCAL automation.
        # Never accept a password in argv or environment variable values.
        candidate = Path(secret_file)
        st = candidate.lstat()
        if candidate.is_symlink() or st.st_uid != 0 or st.st_mode & 0o777 != 0o600:
            raise RuntimeError("CLI password file must be root-owned mode 0600")
        candidate_password = candidate.read_text(encoding="utf-8").rstrip("\n")
        requested_user = record["username"]
    else:
        if not sys.stdin.isatty():
            raise RuntimeError("Interactive SSH TTY required for CLI login")
        requested_user = input("Kali MCP superuser username: ").strip()
        candidate_password = getpass.getpass("Kali MCP superuser password: ")
    if not verify(record, requested_user, candidate_password):
        raise RuntimeError("Superuser authentication failed")
    AUTH_USER, AUTH_PASSWORD = requested_user, candidate_password





def run(*argv: str, check: bool = False, capture: bool = False):
    return subprocess.run(list(argv), check=check, text=True, capture_output=capture)


def active(service: str) -> str:
    try:
        return run("systemctl", "is-active", service, capture=True).stdout.strip() or "unknown"
    except OSError:
        return "unavailable"


def broker(op: str, data: dict | None = None) -> dict:
    return call(SOCKET, op, data or {}, timeout=15)


def _restore_core_sqlite_owner() -> None:
    # CLI runs under sudo, while API Core uses uid/gid 10001.
    for suffix in ("", "-wal", "-shm"):
        item = CORE / ("app.db" + suffix)
        if item.exists():
            os.chown(item, 10001, 10001)
            os.chmod(item, 0o660)


def data_store() -> Store:
    state = Store(CORE / "app.db")
    _restore_core_sqlite_owner()
    return state


def print_status() -> None:
    print("\nKALI MCP · LOCAL STATUS")
    print("systemd Host Agent : ", active("kali-mcp-agent.service"))
    print("Docker Engine      : ", active("docker.service"))
    print("Cloudflare Tunnel  : ", active("kali-mcp-cloudflared.service"))
    print("Tailscale          : ", active("tailscaled.service"))
    try:
        print("Host Agent IPC     : ", broker("ping")["broker"])
        result = broker("settings_get")
        print("Host toggles       : ", ", ".join(
            k + "=" + ("on" if v else "off") for k, v in result["settings"].items()))
    except (BrokerError, OSError) as error:
        print("Host Agent IPC     : offline", error)
    if COMPOSE.exists() and (ETC / "stack.env").exists():
        try:
            output = run("docker", "compose", "--env-file", str(ETC / "stack.env"),
                         "-f", str(COMPOSE), "ps", capture=True)
            print("\n" + output.stdout.strip())
        except OSError:
            print("docker compose unavailable")
    settings_file = ETC / "stack.env"
    if settings_file.exists():
        from .cli_config import parse_env
        values = parse_env(settings_file)
        url = values.get("KALI_MCP_PUBLIC_URL", "http://localhost:8787")
        print("WebUI / OAuth URL : ", url)
        print("MCP endpoint      : ", url + "/mcp")
        print("Channel           : ", values.get("KALI_MCP_RELEASE_CHANNEL", "beta"))


def show_jobs(limit: int = 15) -> None:
    store = data_store()
    try:
        jobs = store.list_jobs(limit)
        print(f"{'JOB':12} {'CLIENT':20} {'TOOL':19} {'STATE':12} {'STARTED'}")
        for job in jobs:
            print(f"{job['id'][:12]:12} {job['actor'][:20]:20} {job['tool_id'][:19]:19} "
                  f"{job['state'][:12]:12} {job['at'][:19]}")
    finally:
        store.close()


def show_job(job_id: str) -> None:
    if not (len(job_id) == 32 and all(x in "0123456789abcdef" for x in job_id)):
        raise ValueError("Use the full 32-character job ID")
    store = data_store()
    try:
        info = store.get_job(job_id)
        if not info:
            print("Job not found")
            return
        print(json.dumps(info, indent=2, ensure_ascii=False))
        print("\nTIMELINE")
        for event in store.job_events(job_id):
            print(event["at"], event["kind"], event["data"][:150])
    finally:
        store.close()


def show_clients(limit: int = 30) -> None:
    store = data_store()
    try:
        print("REGISTERED MCP CLIENTS")
        for item in store.list_clients(limit):
            print(item["client_id"], item["name"][:50],
                  "active" if item["active"] else "revoked/expired")
    finally:
        store.close()


def revoke_client(client_id: str) -> None:
    if input("Type REVOKE to invalidate this client's OAuth tokens: ").strip() != "REVOKE":
        print("Cancelled.")
        return
    store = data_store()
    try:
        if not store.revoke_client(client_id, actor="cli:" + AUTH_USER):
            print("No such client")
        else:
            print("MCP OAuth client tokens revoked:", client_id)
    finally:
        store.close()
        _restore_core_sqlite_owner()


def api_tokens_list() -> None:
    store = data_store()
    try:
        print("API TOKEN CLIENTS (no secrets retained)")
        for row in store.list_api_tokens():
            status = "revoked" if row["revoked"] else (
                "expired" if row["expires"] <= int(time.time()) else "active")
            print(row["token_id"], row["name"][:36], status,
                  time.strftime("%Y-%m-%d", time.gmtime(row["expires"])),
                  "last_used=" + (str(row["last_used"]) if row["last_used"] else "never"))
    finally:
        store.close()
        _restore_core_sqlite_owner()


def api_token_create(name: str, days: int = 30, tools: str = "") -> None:
    if not sys.stdout.isatty():
        raise ValueError("Create API tokens in an interactive terminal; never redirect credentials to logs")
    from .cli_config import parse_env
    config = parse_env(ETC / "stack.env")
    resource = config.get("KALI_MCP_PUBLIC_URL", "").rstrip("/") + "/mcp"
    credential = read_record(ETC / "superuser.json")
    store = data_store()
    try:
        token_id, token = store.create_api_token(
            name, resource, record_fingerprint(credential), days=days,
            allowed_tools=[part.strip() for part in tools.split(",") if part.strip()],
            actor="cli:" + AUTH_USER)
        print("Store the token now; it cannot be recovered later.")
        print("Token ID:", token_id)
        print("Bearer:", token)
    finally:
        store.close()
        _restore_core_sqlite_owner()


def api_token_revoke(token_id: str) -> None:
    if input("Type REVOKE to invalidate this API token: ").strip() != "REVOKE":
        print("Cancelled")
        return
    store = data_store()
    try:
        print("Revoked" if store.revoke_api_token(token_id, actor="cli:" + AUTH_USER)
              else "Not found or already revoked")
    finally:
        store.close()
        _restore_core_sqlite_owner()


def api_token_rotate(token_id: str, days: int = 30) -> None:
    if not sys.stdout.isatty():
        raise ValueError("Rotate API tokens in an interactive terminal")
    if input("Type ROTATE to revoke the prior token immediately: ").strip() != "ROTATE":
        print("Cancelled")
        return
    from .cli_config import parse_env
    config = parse_env(ETC / "stack.env")
    resource = config.get("KALI_MCP_PUBLIC_URL", "").rstrip("/") + "/mcp"
    credential = read_record(ETC / "superuser.json")
    store = data_store()
    try:
        new_id, token = store.rotate_api_token(
            token_id, resource, record_fingerprint(credential), days=days,
            actor="cli:" + AUTH_USER)
        print("Prior token revoked. Copy this new secret now (shown ONCE).")
        print("New token ID:", new_id)
        print("Bearer:", token)
    finally:
        store.close()
        _restore_core_sqlite_owner()


def show_audit(limit: int = 15) -> None:
    store = data_store()
    try:
        for item in store.list_audit(limit):
            print(item["at"][:19], item["actor"][:18], item["action"][:28],
                  item["decision"], item["detail"][:90])
    finally:
        store.close()


def set_capability(name: str, enabled: bool) -> None:
    if name not in {"host_exec", "host_root", "package_install", "network_changes", "mcp_updates"}:
        raise ValueError("Unknown capability")
    if enabled and name == "host_root":
        print("\nWARNING: root terminal access allows complete control of Kali,")
        print("including service changes, loss of network access or data destruction.")
        if input("Type ENABLE ROOT to authorize: ").strip() != "ENABLE ROOT":
            print("Root access unchanged.")
            return
    # Agent policy is authoritative and stored in a root-owned host file.
    previous = broker("settings_get")["settings"].get(name, False)
    broker("settings_set", {"feature": name, "enabled": enabled,
                            "superuser_name": AUTH_USER, "superuser_password": AUTH_PASSWORD})
    try:
        store = data_store()
        try:
            store.set_setting(name, enabled, "local-cli")
            if name == "host_exec" and not enabled:
                store.set_setting("host_root", False, "local-cli")
        finally:
            store.close()
            for suffix in ("", "-wal", "-shm"):
                f = CORE / ("app.db" + suffix)
                if f.exists():
                    os.chown(f, 10001, 10001)
                    os.chmod(f, 0o660)
    except Exception:
        broker("settings_set", {"feature": name, "enabled": previous,
                                "superuser_name": AUTH_USER, "superuser_password": AUTH_PASSWORD})
        raise
    print(f"{name}: {'ENABLED' if enabled else 'disabled'}")


def update_status(force: bool = False) -> None:
    from .cli_config import parse_env
    env = parse_env(ETC / "stack.env")
    checker = UpdateChecker("the-code-learner/kali-mcp",
        env.get("KALI_MCP_RELEASE_CHANNEL", "beta"), 21600)
    info = checker.check(force=True)
    current = (ROOT / "current").resolve().name if (ROOT / "current").exists() else "unknown"
    print("Installed:", current)
    print("Channel:  ", info["channel"])
    print("Latest:   ", info["latest"] or "none")
    print("Error:    ", info["error"] or "none")
    print("Install action is handled by the versioned installer with rollback.")


def upgrade(confirm: bool = True, *, reconfigure: bool = False) -> None:
    """Operator-driven upgrade using the versioned installer with rollback."""
    from .cli_config import parse_env
    current = (ROOT / "current")
    if not current.is_symlink():
        raise RuntimeError("No installed source release")
    installed = current.resolve().name
    env_values = parse_env(ETC / "stack.env")
    channel = env_values.get("KALI_MCP_RELEASE_CHANNEL", "beta")
    print(f"Currently installed: {installed}, release channel: {channel}")
    if confirm:
        phrase = "RECONFIGURE" if reconfigure else "UPGRADE"
        if input(f"Type {phrase} to continue: ").strip() != phrase:
            print("Cancelled.")
            return
    env = os.environ.copy()
    env["KALI_MCP_RELEASE_CHANNEL"] = channel
    env["KALI_MCP_VERSION"] = installed if reconfigure else "latest"
    argv = ["bash", str(current / "scripts/install-hybrid.sh")]
    argv += ["--reconfigure"] if reconfigure else ["--upgrade"]
    result = subprocess.run(argv, env=env, check=False)
    if result.returncode:
        raise RuntimeError("Installer returned error status " + str(result.returncode))
    print("Hybrid appliance activation completed.")


def set_public_origin(origin: str) -> None:
    """Update host + Core OAuth origin together and restart both services."""
    from .cli_config import set_value
    parsed = urlparse(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/")
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Expected a canonical https://hostname origin with no path")
    origin = origin.rstrip("/")
    print("OAuth issuer and token audience will change to", origin)
    print("Existing OAuth sessions for the old origin may require reauthorization.")
    if input("Type CHANGE ORIGIN to apply and restart services: ").strip() != "CHANGE ORIGIN":
        print("Unchanged.")
        return
    paths = (ETC / "stack.env", ETC / "agent.env")
    old = {path: path.read_bytes() for path in paths}
    try:
        for path in paths:
            set_value(path, "KALI_MCP_PUBLIC_URL", origin)
        run("systemctl", "restart", "kali-mcp-agent.service", check=True)
        run("docker", "compose", "--env-file", str(ETC / "stack.env"),
            "-f", str(COMPOSE), "up", "-d", "--force-recreate",
            "--wait", "--wait-timeout", "300", check=True)
    except Exception:
        for path, content in old.items():
            path.write_bytes(content)
            path.chmod(0o600)
        run("systemctl", "restart", "kali-mcp-agent.service")
        raise
    print("Public OAuth origin updated. MCP URL:", origin + "/mcp")


def apt_install(package: str) -> None:
    if not shutil.which("apt-get"):
        raise RuntimeError("apt-get unavailable on this system")
    print("Installing reviewed package:", package)
    run("apt-get", "update", check=True)
    run("apt-get", "install", "-y", package, check=True)


def setup_tailscale() -> None:
    print("\nTAILSCALE · PRIVATE TAILNET ACCESS")
    if not shutil.which("tailscale"):
        if input("Install Kali's tailscale apt package? [y/N]: ").strip().lower() != "y":
            return
        apt_install("tailscale")
    run("systemctl", "enable", "--now", "tailscaled.service", check=True)
    print("Join the tailnet. The following command will display a browser login URL.")
    run("tailscale", "up", check=True)
    if input("Expose local WebUI via private Tailscale Serve? [y/N]: ").strip().lower() == "y":
        run("tailscale", "serve", "--bg", "http://127.0.0.1:8787", check=True)
        run("tailscale", "serve", "status")
        details = run("tailscale", "status", "--json", capture=True)
        try:
            dns = json.loads(details.stdout)["Self"]["DNSName"].rstrip(".")
        except (ValueError, KeyError, TypeError):
            dns = ""
        if dns.endswith(".ts.net"):
            print("Private tailnet OAuth URL:", "https://" + dns + "/mcp")
            if input("Set this HTTPS hostname as the MCP OAuth origin? [y/N]: ").strip().lower() == "y":
                set_public_origin("https://" + dns)
        else:
            print("Unable to discover Tailscale DNS hostname; check MagicDNS and HTTPS.")
        print("Tailscale Serve is private: hosted ChatGPT cannot connect from outside the tailnet.")
    print("Hosted ChatGPT/Codex outside your tailnet cannot access Tailscale Serve.")
    print("For public MCP OAuth, configure Cloudflare Tunnel (preferred).")


def setup_cloudflare() -> None:
    print("\nCLOUDFLARE TUNNEL · PUBLIC HTTPS")
    print("Only expose /mcp and necessary OAuth protocol routes.")
    print("Keep the administrative WebUI protected by Cloudflare Access.")
    print("Check docs/CLOUDFLARE.md before enabling a public route.")
    if not shutil.which("cloudflared"):
        print("cloudflared not installed; checking distribution-signed APT packages.")
        if input("Try distribution APT cloudflared package? [y/N]: ").strip().lower() != "y":
            return
        try:
            apt_install("cloudflared")
        except (RuntimeError, subprocess.CalledProcessError, OSError) as error:
            print("APT install failed (possibly GPG/repository/HTTP 403).")
            print("MCP Core and Host Agent remain operational; access wizard can be retried.")
            print("Install a verified official cloudflared package for this architecture,")
            print("checking the publisher signature/checksum before dpkg -i, then return here.")
            print("Reference: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
            return
    binary = shutil.which("cloudflared")
    if not binary:
        print("cloudflared executable not detected after installation; retry later.")
        return
    version = run(binary, "--version", capture=True)
    if version.returncode:
        print("cloudflared binary version check failed; refusing to enable tunnel.")
        return
    print(version.stdout.strip())
    if input("Configured Cloudflare Access for WebUI and restricted OAuth exceptions? [y/N]: ").strip().lower() != "y":
        print("Not starting tunnel without Access policy acknowledgment.")
        return
    secret = getpass.getpass("Cloudflare remotely-managed Tunnel token (hidden): ").strip()
    if len(secret) < 40 or any(c.isspace() for c in secret):
        raise ValueError("Invalid tunnel token")
    directory = Path("/etc/kali-mcp")
    directory.mkdir(exist_ok=True)
    target = directory / "cloudflared.token"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(secret + "\n")
    os.chmod(target, 0o600)
    secret = ""  # never pass token as argv
    unit = Path("/etc/systemd/system/kali-mcp-cloudflared.service")
    unit.write_text(
        "[Unit]\nDescription=Kali MCP Cloudflare Tunnel\nAfter=network-online.target\n"
        "Wants=network-online.target\n[Service]\nType=simple\nUser=root\n"
        f"ExecStart={binary} tunnel --no-autoupdate run --token-file /etc/kali-mcp/cloudflared.token\n"
        "Restart=on-failure\nRestartSec=5\n"
        "[Install]\nWantedBy=multi-user.target\n")
    run("systemctl", "daemon-reload", check=True)
    run("systemctl", "enable", "--now", "kali-mcp-cloudflared.service", check=True)
    print("Tunnel enabled. Configure the public hostname to forward to")
    print("http://127.0.0.1:8787 and set KALI_MCP_PUBLIC_URL to its HTTPS origin.")
    hostname = input("HTTPS hostname for Cloudflare Tunnel (or Enter to keep current): ").strip()
    if hostname:
        set_public_origin(hostname)


def access_menu() -> None:
    while True:
        print("\nREMOTE ACCESS\n  1) Tailscale (private)\n  2) Cloudflare Tunnel (public + Access)")
        print("  3) Show access status\n  0) Back")
        value = input("Choose: ").strip()
        if value == "1":
            setup_tailscale()
        elif value == "2":
            setup_cloudflare()
        elif value == "3":
            print_status()
        elif value == "0":
            return


def refresh_dashboard() -> None:
    print("\033[2J\033[H", end="")
    print_status()
    print("\nRECENT JOBS")
    show_jobs(8)
    print("\n  [j] jobs   [a] audit   [g] agent toggles   [r] remote access")
    print("  [u] update check   [p] upgrade   [w] wizard   [s] services   [t] API tokens   [q] quit")
    print("Refreshes automatically every 5 seconds. Works over SSH.")


def dashboard() -> None:
    import select
    if not sys.stdin.isatty():
        print_status()
        show_jobs()
        return
    while True:
        refresh_dashboard()
        ready, _, _ = select.select([sys.stdin], [], [], 5)
        if not ready:
            continue
        option = input("Action: ").strip().lower()
        if option == "q":
            return
        if option == "j":
            show_jobs(25)
        elif option == "a":
            show_audit(25)
        elif option == "c":
            show_clients(25)
        elif option == "u":
            update_status(True)
        elif option == "p":
            upgrade()
        elif option == "w":
            upgrade(reconfigure=True)
        elif option == "r":
            access_menu()
        elif option == "t":
            api_tokens_list()
            action = input("Create / Revoke / Rotate / Back [c/r/o/b]: ").strip().lower()
            if action == "c":
                api_token_create(input("Client name: ").strip(),
                                 int(input("Expires in days (1-90) [30]: ").strip() or "30"),
                                 input("Allowed MCP tool names, comma-separated (blank=all): "))
            elif action == "r":
                api_token_revoke(input("Token ID: ").strip())
            elif action == "o":
                api_token_rotate(input("Token ID: ").strip())
        elif option == "g":
            caps = broker("settings_get")["settings"]
            print(caps)
            key = input("Capability name (or Enter): ").strip()
            if key:
                desired = input("Enable? [y/N]: ").lower() == "y"
                set_capability(key, desired)
        elif option == "s":
            print_status()
        if option != "q":
            input("\nPress Enter to return to dashboard...")


def main() -> None:
    parser = argparse.ArgumentParser(prog="kali-mcp", description="Native Kali MCP CLI dashboard")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("dashboard")
    sub.add_parser("status")
    sub.add_parser("jobs")
    item = sub.add_parser("job")
    item.add_argument("job_id")
    sub.add_parser("audit")
    sub.add_parser("clients")
    sub.add_parser("api-tokens")
    create = sub.add_parser("api-token-create")
    create.add_argument("name", help="Descriptive client name (not a secret)")
    create.add_argument("--days", type=int, default=30)
    create.add_argument("--tools", default="", help="Comma-separated MCP tool allowlist")
    revoke_api = sub.add_parser("api-token-revoke")
    revoke_api.add_argument("token_id")
    rotate_api = sub.add_parser("api-token-rotate")
    rotate_api.add_argument("token_id")
    rotate_api.add_argument("--days", type=int, default=30)
    revoke = sub.add_parser("client-revoke")
    revoke.add_argument("client_id")
    sub.add_parser("access")
    sub.add_parser("updates")
    sub.add_parser("upgrade")
    sub.add_parser("wizard")
    setting = sub.add_parser("toggle")
    setting.add_argument("capability", choices=sorted({"host_exec","host_root","package_install","network_changes"}))
    setting.add_argument("state", choices=["on", "off"])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Use sudo kali-mcp to access the local host dashboard")
    try:
        authenticate_local_superuser()
        if args.command in (None, "dashboard"):
            dashboard()
        elif args.command == "status":
            print_status()
        elif args.command == "jobs":
            show_jobs(30)
        elif args.command == "job":
            show_job(args.job_id)
        elif args.command == "audit":
            show_audit(40)
        elif args.command == "clients":
            show_clients(40)
        elif args.command == "api-tokens":
            api_tokens_list()
        elif args.command == "api-token-create":
            api_token_create(args.name, args.days, args.tools)
        elif args.command == "api-token-revoke":
            api_token_revoke(args.token_id)
        elif args.command == "api-token-rotate":
            api_token_rotate(args.token_id, args.days)
        elif args.command == "client-revoke":
            revoke_client(args.client_id)
        elif args.command == "access":
            access_menu()
        elif args.command == "updates":
            update_status(True)
        elif args.command == "upgrade":
            upgrade()
        elif args.command == "wizard":
            upgrade(reconfigure=True)
        elif args.command == "toggle":
            set_capability(args.capability, args.state == "on")
    except (BrokerError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print("Error:", error, file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
