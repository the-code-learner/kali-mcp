"""Stable, intentionally small MCP tool surface backed by a dynamic Kali registry."""
from __future__ import annotations

from contextvars import ContextVar
from functools import lru_cache
import os
from typing import Any

from mcp.server import MCPServer

from .broker_client import BrokerError, call
from .config import Config
from .jobs import Jobs
from .policy import Policy, PolicyDenied
from .registry import KNOWN, discover, installer_argv, tool_command
from .releases import UpdateChecker
from .store import Store


ACTOR: ContextVar[str] = ContextVar("kali_mcp_actor", default="mcp:unknown")
mcp = MCPServer(
    "Kali MCP",
    instructions=(
        "Self-hosted Kali Linux tooling control plane. Only use authorized "
        "assessment scopes. Execution, package installs, network changes and "
        "host root access are controlled by deployment ceilings and WebUI "
        "administrator toggles. Tools return job IDs; use jobs_get to retrieve "
        "results and execution logs. An OAuth login never implies root approval."
    ),
)

cfg = Config.from_env()
store = Store(cfg.data_dir / "app.db")
policy = Policy(cfg, store)
jobs = Jobs(cfg, store)
updates = UpdateChecker(cfg.repo, cfg.update_channel, cfg.check_interval)


def actor() -> str:
    return ACTOR.get()


def safe_call(fn, *args, **kwargs) -> dict:
    try:
        return fn(*args, **kwargs)
    except (ValueError, PolicyDenied, BrokerError, RuntimeError) as exc:
        store.audit(actor(), getattr(fn, "__name__", "unknown"), "deny", str(exc)[:300])
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        store.audit(actor(), getattr(fn, "__name__", "unknown"), "failed", type(exc).__name__)
        return {"ok": False, "error": "Internal operation error"}


@mcp.tool()
def system_status() -> dict:
    """Read-only. Show version, runtime health, platform and broker connectivity."""
    def compute():
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "VERSION"), encoding="utf-8") as handle:
            version = handle.read().strip()
        broker = safe_call(call, cfg.broker_socket, "ping", timeout=2)
        return {"ok": True, "version": version, "broker": broker,
                "release_channel": cfg.update_channel, "auth": "OAuth 2.1 / PKCE"}
    return safe_call(compute)


@mcp.tool()
def capabilities_get() -> dict:
    """Read-only. Explain effective capability settings and blocking YAML variables."""
    return {"ok": True, "capabilities": {
        key: {**details, "enabled": store.get_setting(key) if key in {
            "host_exec", "host_root", "package_install", "network_changes", "mcp_updates"} else details["allowed"]}
        for key, details in cfg.ceilings().items()},
        "allowed_target_cidrs": list(cfg.allowed_cidrs)}


@mcp.tool()
def tools_search(query: str = "") -> dict:
    """Read-only. Discover known Kali tool adapters without expanding the MCP tool list."""
    return {"ok": True, "tools": discover(query[:120]), "host_availability": "query tools_info"}


@mcp.tool()
def tools_info(tool_id: str) -> dict:
    """Read-only. Explain one Kali tool adapter and check its host executable availability."""
    def compute():
        item = KNOWN.get(tool_id)
        if not item:
            return {"ok": False, "error": "Unknown tool ID"}
        status = call(cfg.broker_socket, "discover", {"tool_id": item.executable}, timeout=4)
        return {"ok": True, "tool": vars(item), "installed_on_host": status.get("exit_code") == 0,
                "path": status.get("stdout", "").strip()}
    return safe_call(compute)


@mcp.tool()
def tools_execute(tool_id: str, action: str, parameters: dict[str, Any] | None = None, timeout: int = 90) -> dict:
    """Execute an approved typed Kali adapter on host within authorized scope."""
    def compute():
        policy.check_execution("host", root=False, actor=actor())
        argv = tool_command(tool_id, action, parameters or {}, policy)
        return jobs.submit(actor=actor(), tool_id=tool_id, mode="host",
                           operation="execute", payload={"mode": "host", "argv": argv,
                           "timeout": max(5, min(cfg.max_job_seconds, timeout)), "root": False})
    return safe_call(compute)


@mcp.tool()
def modules_list() -> dict:
    """Read-only. List reviewed tool packages and install recipes."""
    return {"ok": True, "modules": [vars(item) for item in KNOWN.values()]}


@mcp.tool()
def modules_install(tool_id: str) -> dict:
    """WRITE ACTION. Install a reviewed Kali module via apt if explicitly authorized."""
    def compute():
        policy.require("package_install", actor=actor())
        policy.check_execution("host", root=True, actor=actor())
        installer_argv(tool_id)  # fail before dispatching to broker
        return jobs.submit(actor=actor(), tool_id=tool_id, mode="host-root",
                           operation="package_install", payload={"tool_id": tool_id, "timeout": 300})
    return safe_call(compute)


@mcp.tool()
def scripts_execute(script: str, language: str = "python", mode: str = "sandbox",
                    root: bool = False, timeout: int = 60) -> dict:
    """Execute Python/Bash in a disposable network-off sandbox, or on authorized host."""
    def compute():
        if language not in {"python", "bash"}:
            raise ValueError("language must be python or bash")
        if len(script.encode("utf-8")) > 65536:
            raise ValueError("Script exceeds 64KiB")
        policy.check_execution(mode, root=root, actor=actor())
        return jobs.submit(actor=actor(), tool_id="script:" + language, mode=mode,
            operation="execute", payload={"script": script, "language": language,
            "mode": mode, "root": root, "timeout": max(5, min(cfg.max_job_seconds, timeout))})
    return safe_call(compute)


@mcp.tool()
def terminal_open(root: bool = False) -> dict:
    """WRITE ACTION. Open a persistent host Bash PTY when host execution is enabled."""
    def compute():
        policy.check_execution("host", root=root, actor=actor())
        result = call(cfg.broker_socket, "terminal_open", {"root": root}, timeout=10)
        store.audit(actor(), "terminal.open", "allow", "root" if root else "user")
        return result
    return safe_call(compute)


@mcp.tool()
def terminal_write(session_id: str, text: str) -> dict:
    """WRITE ACTION. Send bounded input to an existing terminal session."""
    def compute():
        policy.check_execution("host", root=False, actor=actor())
        result = call(cfg.broker_socket, "terminal_write", {"session_id": session_id, "input": text}, timeout=5)
        store.audit(actor(), "terminal.write", "allow", session_id[:16])
        return result
    return safe_call(compute)


@mcp.tool()
def terminal_read(session_id: str) -> dict:
    """Read-only. Retrieve pending PTY output from a terminal session."""
    return safe_call(call, cfg.broker_socket, "terminal_read", {"session_id": session_id}, timeout=5)


@mcp.tool()
def terminal_close(session_id: str) -> dict:
    """WRITE ACTION. Close a PTY session and terminate its shell."""
    return safe_call(call, cfg.broker_socket, "terminal_close", {"session_id": session_id}, timeout=5)


@mcp.tool()
def jobs_list(limit: int = 40) -> dict:
    """Read-only. List recent execution jobs and state transitions."""
    return {"ok": True, "jobs": store.list_jobs(limit, actor=actor())}


@mcp.tool()
def jobs_get(job_id: str) -> dict:
    """Read-only. Return command results and audit-safe output for a completed job."""
    record = store.get_job(job_id)
    if not record or record["actor"] != actor():
        return {"ok": False, "error": "Unknown job"}
    return jobs.status(job_id)


@mcp.tool()
def jobs_cancel(job_id: str) -> dict:
    """Request cancellation. Returns unavailable until broker process-tree cancellation lands."""
    record = store.get_job(job_id)
    if not record or record["actor"] != actor():
        return {"ok": False, "error": "Unknown job"}
    return jobs.cancel(job_id)


@mcp.tool()
def network_manage(action: str, interface: str = "wlan0") -> dict:
    """Network status / Wi-Fi scan / disconnect. Changes obey admin and YAML gates."""
    def compute():
        if action not in {"status", "scan", "disconnect"}:
            raise ValueError("Unknown or not-yet-implemented network action")
        if action == "disconnect":
            policy.require("network_changes", actor=actor())
        return jobs.submit(actor=actor(), tool_id="network:" + action, mode="host",
            operation="network", payload={"action": action, "interface": interface, "timeout": 30})
    return safe_call(compute)


@mcp.tool()
def updates_status() -> dict:
    """Read-only. Return selected release channel and latest scanned GitHub Release."""
    return {"ok": True, **updates.status()}


@mcp.tool()
def updates_check() -> dict:
    """Read-only. Trigger a release metadata check; never installs automatically."""
    return {"ok": True, **updates.check(force=True)}


@mcp.tool()
def updates_install(tag: str) -> dict:
    """WRITE ACTION. Update installation is withheld until crash-safe supervisor support is validated."""
    try:
        policy.require("mcp_updates", actor=actor())
    except PolicyDenied as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": False, "error": "Release installation not available in this development build; no change was made",
            "requested_tag": tag}


@mcp.tool()
def audit_recent(limit: int = 50) -> dict:
    """Read-only. Return bounded redacted authorization and job audit events."""
    return {"ok": True, "events": store.list_audit(limit, actor=actor())}
