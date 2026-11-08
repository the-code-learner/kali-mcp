"""Native Kali Host Agent managed by systemd, never by a privileged container.

The protocol is the existing bounded newline-delimited local broker protocol.
The trusted transport is a Unix socket with root:kalimcp ownership and mode
0660. Processes in the socket group are TRUSTED CONTROL-PLANE PROCESSES,
not untrusted users. Compromising the Core may therefore compromise this
trust boundary; the host-side root toggle is a policy check, not a guarantee
against a compromised Core.
"""
from __future__ import annotations

import grp
import json
import os
from pathlib import Path
import re
import shutil
import socketserver
import subprocess
import tempfile
import time
from collections import deque
from uuid import uuid4

from .releases import query_releases, select_release
from .browser_origins import parse_browser_origins, validate_browser_origin
from .cli_config import parse_env
from .deployment_settings import public_inventory, validate_change, FIELD_MAP
import threading

from .broker import Broker, BrokerDenied, Handler, LocalServer
from .config import Config
from .registry import installer_argv
from .superuser import DEFAULT_HOST_FILE, read_record, verify


CAPABILITIES = frozenset({"host_exec", "host_root", "package_install", "network_changes", "mcp_updates"})
STATE_PATH = Path(os.getenv("KALI_MCP_AGENT_STATE", "/etc/kali-mcp/agent-state.json"))
AGENT_GROUP = os.getenv("KALI_MCP_AGENT_GROUP", "kalimcp")


class AgentState:
    """Small host-owned state file; the Core does not mount or write it."""
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._save({name: False for name in CAPABILITIES})

    def _read(self) -> dict:
        with self.path.open(encoding="utf-8") as stream:
            values = json.load(stream)
        if not isinstance(values, dict):
            raise ValueError("Invalid host agent policy")
        return values

    def _save(self, values: dict) -> None:
        fd, name = tempfile.mkstemp(prefix=".agent-state-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(values, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def get_setting(self, name: str) -> bool:
        if name not in CAPABILITIES:
            return False
        with self.lock:
            return self._read().get(name) is True

    def settings(self) -> dict[str, bool]:
        with self.lock:
            raw = self._read()
            return {name: raw.get(name) is True for name in sorted(CAPABILITIES)}

    def set_setting(self, name: str, value: bool, cfg: Config) -> None:
        if name not in CAPABILITIES or type(value) is not bool:
            raise BrokerDenied("Unsupported host capability")
        if value and not cfg.ceilings()[name]["allowed"]:
            raise BrokerDenied("Blocked by host deployment ceiling: " + cfg.ceilings()[name]["yaml"])
        with self.lock:
            values = self._read()
            if name == "host_root" and value and not values.get("host_exec"):
                raise BrokerDenied("Enable host_exec before host_root")
            if name == "host_exec" and not value:
                values["host_root"] = False
            values[name] = value
            self._save(values)

    def audit(self, *args, **kwargs) -> None:
        # Host events are captured by journald, not the container DB.
        print("agent-audit:", *(str(x)[:160] for x in args), flush=True)


class NativeAgent(Broker):
    def __init__(self, cfg: Config, store: AgentState):
        super().__init__(cfg, store)
        self._auth_gate = threading.BoundedSemaphore(1)
        self._auth_failures = deque()
        self._auth_lock = threading.Lock()

    def _verify_superuser(self, username: str, password: str) -> None:
        now = time.monotonic()
        with self._auth_lock:
            while self._auth_failures and self._auth_failures[0] < now - 60:
                self._auth_failures.popleft()
            if len(self._auth_failures) >= 8:
                raise BrokerDenied("Superuser approval temporarily rate-limited")
        if not self._auth_gate.acquire(blocking=False):
            raise BrokerDenied("Superuser verification busy")
        try:
            auth_path = Path(os.getenv("KALI_MCP_SUPERUSER_FILE", str(DEFAULT_HOST_FILE)))
            if not verify(read_record(auth_path), username, password):
                with self._auth_lock:
                    self._auth_failures.append(time.monotonic())
                raise BrokerDenied("Superuser authentication required")
        finally:
            self._auth_gate.release()

    def _nsenter(self, argv: list[str], *, root: bool) -> list[str]:
        # Native systemd agent is already on Kali; never enter PID/mount namespaces.
        if root:
            self.require("host_root", "allow_host_root")
            return argv
        return ["runuser", "-u", self.host_user, "--"] + argv

    def dispatch(self, op: str, data: dict) -> dict:
        if op == "ping":
            return {"ok": True, "broker": "systemd-host-agent", "version": 1}
        if op == "settings_get":
            return {"ok": True, "settings": self.store.settings(),
                    "ceilings": self.cfg.ceilings()}
        if op == "settings_set":
            key, enabled = data.get("feature"), data.get("enabled")
            if not isinstance(key, str) or type(enabled) is not bool:
                raise BrokerDenied("Invalid capability value")
            # The control socket alone never authorizes a privilege change.
            # Authenticate the superuser independently on the root-owned host.
            username = data.get("superuser_name")
            password = data.get("superuser_password")
            self._verify_superuser(username, password)
            self.store.set_setting(key, enabled, self.cfg)
            if not enabled and key in {"host_exec", "host_root"}:
                # Revocation is immediate for terminals still owned by the Agent.
                # A full root shell can spawn work outside the tracked session;
                # root is not a sandbox or complete process containment.
                with self.lock:
                    for session_id, session in list(self.sessions.items()):
                        if key == "host_exec" or session["root"]:
                            self._close_session(session_id, session)
            self.store.audit("admin", "settings_set", "allow", key)
            return {"ok": True, "settings": self.store.settings()}
        if op == "deployment_settings_get":
            stack = parse_env(Path("/etc/kali-mcp/stack.env"))
            agent = parse_env(Path("/etc/kali-mcp/agent.env"))
            status_path = Path("/var/lib/kali-mcp/deployment-settings-status.json")
            progress = {"state": "not changed"}
            try:
                if status_path.is_file() and not status_path.is_symlink():
                    progress = json.loads(status_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                progress = {"state": "status unavailable"}
            return {"ok": True, "fields": public_inventory(stack, agent),
                    "deployment": progress}
        if op == "deployment_settings_update":
            self._verify_superuser(data.get("superuser_name"),
                                   data.get("superuser_password"))
            requested = data.get("changes")
            if not isinstance(requested, dict) or not requested or len(requested) > 3:
                raise BrokerDenied("Invalid deployment change")
            try:
                current = parse_env(Path("/etc/kali-mcp/stack.env"))
                changes = validate_change(current, requested)
            except (ValueError, OSError) as exc:
                raise BrokerDenied("Invalid deployment change: " + str(exc)[:200]) from exc
            new = {**current, **changes}
            # High-impact changes have additional, explicit user intent.
            if new.get("KALI_MCP_ALLOW_ALL_TARGETS", "false") == "true" and (
                "KALI_MCP_ALLOW_ALL_TARGETS" in changes or
                "KALI_MCP_DENIED_CIDRS" in changes
            ) and data.get("confirm") != "ALLOW ALL":
                raise BrokerDenied("Type ALLOW ALL to confirm this broad target scope")
            if any(key in changes and changes[key] == "true"
                   for key in ("KALI_MCP_ALLOW_HOST_ROOT",
                               "KALI_MCP_ALLOW_MCP_ROOT")) and (
                               data.get("confirm") != "ENABLE ROOT"):
                raise BrokerDenied("Type ENABLE ROOT to confirm this root ceiling")
            if all(current.get(k, FIELD_MAP[k].default) == value
                   for k, value in changes.items()):
                return {"ok": True, "unchanged": True}
            unit = "kali-mcp-deploy-" + uuid4().hex[:12]
            command = ["systemd-run", "--collect", "--on-active=3s",
                       "--unit=" + unit, "/usr/bin/python3",
                       "/opt/kali-mcp/current/scripts/manage_deployment_settings.py",
                       "--changes", json.dumps(changes, separators=(",", ":"))]
            result = self._run(command, timeout=20)
            if result.get("exit_code") != 0:
                raise BrokerDenied("systemd could not schedule the deployment change")
            self.store.audit("admin", "deployment_settings.update", "allow",
                             ",".join(sorted(changes)))
            return {"ok": True, "scheduled": True, "unit": unit,
                    "keys": sorted(changes),
                    "message": "Scheduled, not yet applied; check deployment state"}
        if op == "browser_origins_status":
            configured = parse_browser_origins(
                parse_env(Path("/etc/kali-mcp/stack.env")).get("KALI_MCP_BROWSER_ORIGINS", ""))
            status_path = Path("/var/lib/kali-mcp/browser-origins-status.json")
            progress = {"state": "unknown"}
            try:
                if status_path.is_file() and not status_path.is_symlink():
                    progress = json.loads(status_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                progress = {"state": "unavailable"}
            return {"ok": True, "configured": list(configured), "deployment": progress}
        if op == "browser_origins_update":
            # This is a narrowly scoped administrative configuration operation;
            # it never enables any host/root execution or MCP capability.
            self._verify_superuser(data.get("superuser_name"),
                                   data.get("superuser_password"))
            action = data.get("action")
            if action not in {"add", "remove"}:
                raise BrokerDenied("Invalid browser-origin action")
            try:
                origin = validate_browser_origin(data.get("origin"))
                previous = parse_browser_origins(
                    parse_env(Path("/etc/kali-mcp/stack.env")).get("KALI_MCP_BROWSER_ORIGINS", ""))
                current = list(previous)
                if action == "add" and origin not in current:
                    current.append(origin)
                elif action == "remove" and origin in current:
                    current.remove(origin)
                desired = parse_browser_origins(",".join(current))
            except (ValueError, OSError) as exc:
                raise BrokerDenied("Invalid browser-origin configuration: " + str(exc)[:160]) from exc
            if desired == previous:
                return {"ok": True, "unchanged": True, "configured": list(desired)}
            unit = "kali-mcp-origins-" + uuid4().hex[:12]
            argv = ["systemd-run", "--collect", "--on-active=3s",
                    "--unit=" + unit, "/usr/bin/python3",
                    "/opt/kali-mcp/current/scripts/manage_browser_origins.py",
                    "--origins", ",".join(desired)]
            result = self._run(argv, timeout=20)
            if result.get("exit_code") != 0:
                raise BrokerDenied("Could not schedule the Core configuration change")
            self.store.audit("admin", "browser_origins.update", "allow",
                             action + ":" + origin)
            return {"ok": True, "scheduled": True, "configured": list(desired),
                    "unit": unit}
        if op == "updates_install":
            self.require("mcp_updates", "allow_mcp_updates")
            requested = str(data.get("tag", ""))
            if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[0-9]+)?", requested):
                raise BrokerDenied("Invalid release tag")
            selected = select_release(query_releases(self.cfg.repo), self.cfg.update_channel)
            if not selected or selected.tag != requested:
                raise BrokerDenied("Only the latest eligible GitHub Release can be installed")
            unit = "kali-mcp-update-" + uuid4().hex[:12]
            # A detached transient unit survives the Agent and Core being restarted
            # by their own installer. The command and tag are bounded, never supplied
            # as arbitrary executable text by a client.
            command = ["systemd-run", "--collect", "--unit=" + unit,
                "--setenv=KALI_MCP_VERSION=" + requested,
                "--setenv=KALI_MCP_RELEASE_CHANNEL=" + self.cfg.update_channel,
                "/bin/bash", "/opt/kali-mcp/current/scripts/install-hybrid.sh", "--upgrade"]
            result = self._run(command, timeout=20)
            if result.get("exit_code") != 0:
                raise BrokerDenied("systemd could not schedule the upgrade")
            self.store.audit("admin", "update.schedule", "allow", requested)
            return {"ok": True, "scheduled": True, "unit": unit, "tag": requested}
        if op == "package_install":
            # Installing a reviewed package requires explicit package consent,
            # but not permission to open an unrestricted root terminal.
            self.require("package_install", "allow_package_install")
            argv = installer_argv(str(data.get("tool_id", "")))
            return self._run(argv, timeout=300)
        return super().dispatch(op, data)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Host Agent requires root via systemd")
    config = Config.from_env()
    state = AgentState(STATE_PATH)
    server = NativeAgent(config, state)
    group = grp.getgrnam(AGENT_GROUP).gr_gid
    socket_file = config.broker_socket
    socket_file.parent.mkdir(parents=True, exist_ok=True)
    os.chown(socket_file.parent, 0, group)
    os.chmod(socket_file.parent, 0o750)
    socket_file.unlink(missing_ok=True)
    with LocalServer(str(socket_file), Handler) as app:
        app.broker = server
        os.chown(socket_file, 0, group)
        os.chmod(socket_file, 0o660)
        print("Native Kali Host Agent ready via private Unix socket", flush=True)
        try:
            app.serve_forever(poll_interval=0.25)
        finally:
            for key, session in list(server.sessions.items()):
                server._close_session(key, session)
            socket_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
