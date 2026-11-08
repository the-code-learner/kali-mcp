"""Private root-owned update state that survives Core and Native Agent restarts.

The update installer is a detached systemd transient unit. Its scheduling
job is NOT proof of successful installation. Expose only bounded phase/status
metadata over authenticated host-agent IPC; no logs or credentials.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time

STATE_PATH = Path("/var/lib/kali-mcp/update-status.json")
STATES = frozenset({"idle", "scheduled", "running", "completed", "failed", "rolled_back"})
PHASES = frozenset({"scheduled", "preflight", "download", "verify", "backup",
                   "configuration", "dependencies", "activation", "healthcheck",
                   "completed", "failed", "rolled_back"})
DEFAULT = {"state": "idle", "phase": "scheduled", "tag": None,
           "unit": None, "updated_at": None, "started_at": None, "detail": ""}


def load(path: Path = STATE_PATH) -> dict:
    if path.is_symlink():
        return {**DEFAULT, "state": "failed", "detail": "Update state unavailable"}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Invalid update state")
        result = {name: raw.get(name, default) for name, default in DEFAULT.items()}
        if result["state"] not in STATES or result["phase"] not in PHASES:
            raise ValueError("Invalid update state code")
        if not isinstance(result["detail"], str):
            result["detail"] = ""
        result["detail"] = result["detail"][:160]
        return result
    except FileNotFoundError:
        return dict(DEFAULT)
    except (OSError, ValueError):
        return {**DEFAULT, "state": "failed", "detail": "Update state unreadable"}


def save(*, state: str, phase: str, tag: str | None, unit: str | None = None,
         detail: str = "", path: Path = STATE_PATH,
         started_at: str | None = None) -> dict:
    if state not in STATES or phase not in PHASES:
        raise ValueError("Invalid update state or phase")
    if path.is_symlink():
        raise RuntimeError("Refusing update status symlink")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = load(path)
    stamp = datetime.now(timezone.utc).isoformat()
    next_state = {"state": state, "phase": phase, "tag": tag,
                  "unit": unit or old.get("unit"),
                  "updated_at": stamp,
                  "started_at": started_at or old.get("started_at") or stamp,
                  "detail": str(detail)[:160]}
    data = (json.dumps(next_state, sort_keys=True) + "\n").encode("utf-8")
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".upgrade-status-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return next_state


def is_inflight(status: dict) -> bool:
    if status.get("state") not in {"scheduled", "running"}:
        return False
    try:
        date = datetime.fromisoformat(str(status.get("updated_at")))
        return 0 <= (datetime.now(timezone.utc) - date).total_seconds() < 2 * 3600
    except (ValueError, TypeError):
        return False
