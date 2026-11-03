"""SQLite-backed settings, OAuth state, audit events and async job histories."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from uuid import uuid4


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=20, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=20000")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (
          id TEXT PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, decision TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY, at TEXT NOT NULL, finished_at TEXT,
          actor TEXT NOT NULL, tool_id TEXT NOT NULL,
          mode TEXT NOT NULL, state TEXT NOT NULL, exit_code INTEGER,
          args_json TEXT NOT NULL, result_json TEXT);
        CREATE INDEX IF NOT EXISTS jobs_at ON jobs(at DESC);
        CREATE TABLE IF NOT EXISTS job_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
          at TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS oauth_clients (
          client_id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS oauth_codes (
          hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
          challenge TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL,
          expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS oauth_tokens (
          hash TEXT PRIMARY KEY, client_id TEXT NOT NULL,
          kind TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
          expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
          family TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS oauth_tokens_family ON oauth_tokens(family);
        CREATE TABLE IF NOT EXISTS admin_sessions (
          hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, expires INTEGER NOT NULL);
        """)
        for key in ("host_root", "host_exec", "package_install", "network_changes", "mcp_updates"):
            self.db.execute("INSERT OR IGNORE INTO settings VALUES (?, 'false')", (key,))

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def get_setting(self, key: str) -> bool:
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return bool(row and row["value"] == "true")

    def set_setting(self, key: str, value: bool, actor: str = "webui") -> None:
        if key not in {"host_root", "host_exec", "package_install", "network_changes", "mcp_updates"}:
            raise ValueError("Unknown setting")
        with self.transaction():
            self.db.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (key, "true" if value else "false"))
            self._audit(actor, "settings." + key, "allow", json.dumps({"value": value}))

    def _audit(self, actor: str, action: str, decision: str, detail: str = "") -> None:
        self.db.execute("INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?)",
                        (uuid4().hex, utc(), actor[:128], action[:128], decision[:48], detail[:1024]))

    def audit(self, actor: str, action: str, decision: str, detail: str = "") -> None:
        with self.lock:
            self._audit(actor, action, decision, detail)

    def list_audit(self, limit: int = 100, *, actor: str | None = None) -> list[dict]:
        with self.lock:
            if actor is not None:
                query = "SELECT * FROM audit WHERE actor=? ORDER BY at DESC LIMIT ?"
                params = (actor, max(1, min(limit, 500)))
            else:
                query = "SELECT * FROM audit ORDER BY at DESC LIMIT ?"
                params = (max(1, min(limit, 500)),)
            return [dict(x) for x in self.db.execute(query, params)]

    def new_job(self, actor: str, tool_id: str, mode: str, args: dict) -> str:
        job_id = uuid4().hex
        # Sensitive script bodies and authentication tokens must not land in SQLite.
        sanitized = {k: ("[REDACTED]" if k in {"password", "token", "script", "command", "content"} else v) for k, v in args.items()}
        with self.lock:
            self.db.execute(
                "INSERT INTO jobs(id,at,actor,tool_id,mode,state,args_json) VALUES (?,?,?,?,?,?,?)",
                (job_id, utc(), actor[:128], tool_id[:128], mode[:32], "queued", json.dumps(sanitized, default=str)[:8192]))
        return job_id

    def job_state(self, job_id: str, state: str, *, result: dict | None = None, exit_code: int | None = None) -> None:
        if state not in {"queued", "running", "completed", "failed", "timed_out", "cancelled", "lost"}:
            raise ValueError("Invalid job state")
        with self.lock:
            self.db.execute(
                "UPDATE jobs SET state=?, finished_at=?, result_json=?, exit_code=? WHERE id=?",
                (state, utc() if state not in ("queued", "running") else None,
                 json.dumps(result, default=str)[:65536] if result is not None else None, exit_code, job_id))
            self.db.execute("INSERT INTO job_events(job_id,at,kind,data) VALUES(?,?,?,?)",
                            (job_id, utc(), "state", state))

    def get_job(self, job_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["args"] = json.loads(result.pop("args_json"))
            result["result"] = json.loads(result.pop("result_json")) if result.get("result_json") else None
            return result

    def list_jobs(self, limit: int = 100, *, actor: str | None = None) -> list[dict]:
        with self.lock:
            fields = "id,at,finished_at,actor,tool_id,mode,state,exit_code"
            if actor is not None:
                query = f"SELECT {fields} FROM jobs WHERE actor=? ORDER BY at DESC LIMIT ?"
                params = (actor, max(1, min(limit, 500)))
            else:
                query = f"SELECT {fields} FROM jobs ORDER BY at DESC LIMIT ?"
                params = (max(1, min(limit, 500)),)
            return [dict(x) for x in self.db.execute(query, params)]

    def events(self, after: int = 0, limit: int = 100) -> list[dict]:
        with self.lock:
            return [dict(x) for x in self.db.execute(
                "SELECT * FROM job_events WHERE id > ? ORDER BY id LIMIT ?", (max(0, after), max(1, min(limit, 500))),)]

    def job_events(self, job_id: str, limit: int = 100) -> list[dict]:
        with self.lock:
            return [dict(x) for x in self.db.execute(
                "SELECT * FROM job_events WHERE job_id=? ORDER BY id LIMIT ?",
                (job_id, max(1, min(limit, 500))))]

    def close(self) -> None:
        with self.lock:
            self.db.close()
