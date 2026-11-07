"""Privileged broker. Never exposes TCP; reachable only via a shared Unix socket.

WARNING: Docker privileged + host PID + Docker socket + host namespace entry
is effectively host-root authority. The WebUI toggle is a user consent gate,
not a hard isolation boundary against a compromised privileged broker.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pty
import signal
import re
import select
import shutil
import socketserver
import subprocess
import threading
import time

from .config import Config
from .policy import validate_argv
from .registry import installer_argv
from .store import Store


SESSION_TTL = 1800
MAX_RESPONSE = 256 * 1024
SAFE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class BrokerDenied(PermissionError):
    pass


class Broker:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store
        self.sessions: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.max_sessions = 8
        self.max_sessions_per_actor = 2
        self._reaper = threading.Thread(target=self._expire_terminals, daemon=True,
                                        name="kali-mcp-pty-reaper")
        self._reaper.start()
        self.host_user = os.environ.get("KALI_MCP_HOST_USER", "kali")
        if not SAFE_USER.fullmatch(self.host_user):
            raise RuntimeError("Invalid KALI_MCP_HOST_USER")

    def _expire_terminals(self) -> None:
        # Terminate abandoned PTY process groups even if clients disappear
        # without issuing terminal_close.
        while True:
            time.sleep(30)
            with self.lock:
                for session_id, session in list(self.sessions.items()):
                    if time.monotonic() - session.get("last", 0) > SESSION_TTL:
                        self._close_session(session_id, session)

    def require(self, setting: str, flag: str) -> None:
        if not getattr(self.cfg, flag) or not self.store.get_setting(setting):
            raise BrokerDenied(f"{setting} is disabled by deployment or WebUI")

    def _nsenter(self, argv: list[str], *, root: bool) -> list[str]:
        if shutil.which("nsenter") is None:
            raise BrokerDenied("nsenter missing in broker image")
        # Host PID 1 is visible via pid:host; --root/--wd switch filesystem
        # perspective to the host, not the container's filesystem.
        prefix = ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--root", "--wd", "--"]
        if root:
            self.require("host_root", "allow_host_root")
            return prefix + argv
        return prefix + ["runuser", "-u", self.host_user, "--"] + argv

    def _run(self, command: list[str], *, timeout: int = 60, input_bytes: bytes | None = None) -> dict:
        timeout = max(5, min(self.cfg.max_job_seconds, timeout))
        proc = subprocess.Popen(command, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = proc.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        return {"ok": True, "exit_code": 124 if timed_out else proc.returncode,
                "stdout": stdout[:100000].decode("utf-8", "replace"),
                "stderr": stderr[:100000].decode("utf-8", "replace"),
                "timed_out": timed_out,
                "truncated": len(stdout) > 100000 or len(stderr) > 100000}

    def _sandbox(self, script: str, language: str, timeout: int) -> dict:
        if language not in {"python", "bash"}:
            raise BrokerDenied("Sandbox supports Python or Bash")
        if len(script.encode()) > 65536:
            raise BrokerDenied("Script too large")
        try:
            import docker
        except ImportError as exc:
            raise BrokerDenied("Docker SDK unavailable in broker") from exc
        client = docker.from_env(timeout=10)
        # Docker forbids put_archive into read-only containers, even on tmpfs.
        # Pass the bounded script directly as an argv element to preserve
        # a read-only root filesystem. Docker administrators can see this
        # argument with inspect while the ephemeral sandbox exists.
        command = (["python", "-B", "-c", script] if language == "python"
                   else ["bash", "-c", script])
        container = None
        try:
            container = client.containers.create(
                image=os.environ.get("KALI_MCP_SANDBOX_IMAGE", "python:3.12-slim-bookworm"),
                command=command,
                user="65534:65534",
                network_mode="none",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                read_only=True,
                tmpfs={"/tmp": "rw,nosuid,nodev,size=16m,mode=1777"},
                mem_limit="512m", nano_cpus=1_000_000_000,
                pids_limit=64,
                detach=True,
                environment={"PYTHONDONTWRITEBYTECODE": "1"},
                labels={"app": "kali-mcp", "purpose": "sandbox"},
            )
            container.start()
            try:
                result = container.wait(timeout=max(5, min(timeout, self.cfg.max_job_seconds)))
                exit_code = int(result.get("StatusCode", 1))
            except Exception:
                container.kill()
                exit_code = 124
            logs = container.logs(stdout=True, stderr=True)
            return {"ok": True, "exit_code": exit_code,
                    "stdout": logs[:180000].decode("utf-8", "replace"),
                    "stderr": "" if exit_code != 124 else "Execution timeout",
                    "truncated": len(logs) > 180000, "sandbox": True}
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            client.close()

    def _exec(self, data: dict) -> dict:
        mode = data.get("mode", "sandbox")
        timeout = int(data.get("timeout", 60))
        root = data.get("root") is True
        script = data.get("script")
        argv = data.get("argv")
        if script is not None:
            if not isinstance(script, str) or len(script.encode()) > 65536:
                raise BrokerDenied("Invalid script")
            language = data.get("language", "python")
            if language not in ("python", "bash"):
                raise BrokerDenied("Unsupported script language")
            if mode == "sandbox":
                return self._sandbox(script, language, timeout)
            self.require("host_exec", "allow_host_exec")
            command = ["/usr/bin/python3", "-"] if language == "python" else ["/bin/bash", "-s"]
            return self._run(self._nsenter(command, root=root), timeout=timeout, input_bytes=script.encode())
        if argv is None:
            raise BrokerDenied("Missing executable or script")
        argv = validate_argv(argv)
        if mode == "sandbox":
            raise BrokerDenied("Use script execution for a sandbox")
        self.require("host_exec", "allow_host_exec")
        return self._run(self._nsenter(argv, root=root), timeout=timeout)

    def _network(self, data: dict) -> dict:
        action = str(data.get("action", ""))
        if action not in {"scan", "status"}:
            self.require("network_changes", "allow_network_changes")
        interface = str(data.get("interface", ""))
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,24}", interface):
            raise BrokerDenied("Invalid interface")
        if action == "scan":
            argv = ["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "device", "wifi", "list", "ifname", interface]
        elif action == "status":
            argv = ["nmcli", "-t", "device", "show", interface]
        elif action == "disconnect":
            raise BrokerDenied("Network changes are disabled until checkpoint rollback support is validated")
        else:
            raise BrokerDenied("Network action not yet implemented with rollback guard")
        return self._run(self._nsenter(argv, root=action == "disconnect"), timeout=30)

    def _terminal(self, action: str, data: dict) -> dict:
        if action == "terminal_open":
            self.require("host_exec", "allow_host_exec")
            root = data.get("root") is True
            owner = str(data.get("actor") or "")
            if not owner or len(owner) > 128:
                raise BrokerDenied("Missing terminal owner")
            with self.lock:
                if len(self.sessions) >= self.max_sessions:
                    raise BrokerDenied("Terminal session quota reached")
                if sum(1 for item in self.sessions.values() if item.get("actor") == owner) >= self.max_sessions_per_actor:
                    raise BrokerDenied("Client terminal quota reached")
            command = self._nsenter(["/bin/bash", "--noprofile", "--norc", "-i"], root=root)
            master, slave = pty.openpty()
            proc = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                    close_fds=True, start_new_session=True)
            os.close(slave)
            os.set_blocking(master, False)
            session_id = os.urandom(16).hex()
            with self.lock:
                self.sessions[session_id] = {"master": master, "proc": proc, "last": time.monotonic(), "root": root, "actor": owner}
            return {"ok": True, "session_id": session_id, "pid": proc.pid}
        session_id = str(data.get("session_id", ""))
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                raise BrokerDenied("Unknown terminal session")
            if str(data.get("actor") or "") != session["actor"]:
                raise BrokerDenied("Terminal belongs to another client")
            if action != "terminal_close":
                try:
                    self.require("host_exec", "allow_host_exec")
                    if session["root"]:
                        self.require("host_root", "allow_host_root")
                except BrokerDenied:
                    self._close_session(session_id, session)
                    raise
            if time.monotonic() - session["last"] > SESSION_TTL:
                self._close_session(session_id, session)
                raise BrokerDenied("Terminal session expired")
            session["last"] = time.monotonic()
            if action == "terminal_read":
                ready, _, _ = select.select([session["master"]], [], [], 0.02)
                if not ready:
                    return {"ok": True, "output": "", "running": session["proc"].poll() is None}
                try:
                    data_bytes = os.read(session["master"], 32768)
                except OSError:
                    data_bytes = b""
                return {"ok": True, "output": data_bytes.decode("utf-8", "replace"),
                        "running": session["proc"].poll() is None}
            if action == "terminal_write":
                payload = str(data.get("input", ""))
                if len(payload) > 4096:
                    raise BrokerDenied("Terminal input too long")
                os.write(session["master"], payload.encode())
                return {"ok": True}
            if action == "terminal_close":
                self._close_session(session_id, session)
                return {"ok": True}
        raise BrokerDenied("Unknown terminal action")

    def _close_session(self, key: str, session: dict) -> None:
        proc = session["proc"]
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2)
        try:
            os.close(session["master"])
        except OSError:
            pass
        self.sessions.pop(key, None)

    def dispatch(self, op: str, data: dict) -> dict:
        if op == "ping":
            return {"ok": True, "broker": "available"}
        if op == "execute":
            return self._exec(data)
        if op == "discover":
            # Read-only host inventory: no root toggle necessary.
            tool = str(data.get("tool_id") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", tool):
                raise BrokerDenied("Invalid executable")
            return self._run(self._nsenter(["/usr/bin/which", tool], root=False), timeout=10)
        if op == "package_install":
            self.require("package_install", "allow_package_install")
            argv = installer_argv(str(data.get("tool_id") or ""))
            return self._run(self._nsenter(argv, root=True), timeout=300)
        if op == "network":
            return self._network(data)
        if op.startswith("terminal_"):
            return self._terminal(op, data)
        raise BrokerDenied("Unknown operation")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw = self.rfile.readline(256 * 1024 + 1)
            if len(raw) > 256 * 1024 or not raw.endswith(b"\n"):
                raise BrokerDenied("Invalid message framing")
            request = json.loads(raw)
            if request.get("v") != 1 or not isinstance(request.get("payload"), dict):
                raise BrokerDenied("Unsupported broker protocol")
            response = self.server.broker.dispatch(str(request.get("op") or ""), request["payload"])
        except Exception as exc:
            response = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:280]}"}
        encoded = json.dumps(response, separators=(",", ":")).encode()
        if len(encoded) > MAX_RESPONSE:
            encoded = json.dumps({"ok": False, "error": "Broker response limit exceeded"}).encode()
        self.wfile.write(encoded + b"\n")


class LocalServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    cfg = Config.from_env()
    store = Store(cfg.data_dir / "app.db")
    # The privileged broker starts before the non-root Core. SQLite uses
    # the main database plus WAL/SHM sidecars, all of which must be writable
    # by Core uid 10001. Preserve ownership on every broker restart.
    for suffix in ("", "-wal", "-shm"):
        database_file = cfg.data_dir / ("app.db" + suffix)
        if database_file.exists():
            os.chown(database_file, 10001, 10001)
            os.chmod(database_file, 0o660)
    broker = Broker(cfg, store)
    socket_path = cfg.broker_socket
    socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(socket_path.parent, 10001, 10001)
    os.chmod(socket_path.parent, 0o700)
    socket_path.unlink(missing_ok=True)
    with LocalServer(str(socket_path), Handler) as srv:
        srv.broker = broker
        os.chmod(socket_path, 0o600)
        os.chown(socket_path, 10001, 10001)
        print("Kali MCP host broker listening on private Unix socket", flush=True)
        srv.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
