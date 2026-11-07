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
import threading

from .broker import Broker, BrokerDenied, Handler, LocalServer
from .config import Config
from .registry import installer_argv


CAPABILITIES = frozenset({"host_exec", "host_root", "package_install", "network_changes"})
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
            self.store.set_setting(key, enabled, self.cfg)
            self.store.audit("admin", "settings_set", "allow", key)
            return {"ok": True, "settings": self.store.settings()}
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
