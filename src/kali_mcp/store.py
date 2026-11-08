"""SQLite-backed settings, OAuth state, audit events and async job histories."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import re
import secrets
import time
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
        CREATE TABLE IF NOT EXISTS api_tokens (
          token_id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
          resource TEXT NOT NULL, scope TEXT NOT NULL, allowed_tools TEXT NOT NULL,
          issued_for TEXT NOT NULL, created_at INTEGER NOT NULL, expires INTEGER NOT NULL,
          last_used INTEGER, revoked INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS api_tokens_expires ON api_tokens(expires);
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
        sensitive = {"password", "token", "secret", "api_key", "authorization",
                     "script", "command", "argv", "input", "content", "env",
                     "headers", "key", "cookie", "refresh_token", "client_secret"}
        sanitized = {str(k)[:64]: ("[REDACTED]" if str(k).lower() in sensitive else v)
                     for k, v in args.items()}
        encoded_args = json.dumps(sanitized, default=str)
        if len(encoded_args) > 8192:
            encoded_args = json.dumps({"truncated": True, "keys": list(sanitized)[:32]})
        with self.lock:
            self.db.execute(
                "INSERT INTO jobs(id,at,actor,tool_id,mode,state,args_json) VALUES (?,?,?,?,?,?,?)",
                (job_id, utc(), actor[:128], tool_id[:128], mode[:32], "queued", encoded_args))
        return job_id

    def job_state(self, job_id: str, state: str, *, result: dict | None = None, exit_code: int | None = None) -> None:
        if state not in {"queued", "running", "completed", "failed", "timed_out", "cancelled", "lost"}:
            raise ValueError("Invalid job state")
        encoded_result = None
        if result is not None:
            bounded = dict(result)
            for field in ("stdout", "stderr"):
                value = bounded.get(field)
                if isinstance(value, str) and len(value) > 24000:
                    bounded[field] = value[:24000]
                    bounded["truncated"] = True
            encoded_result = json.dumps(bounded, default=str)
            if len(encoded_result) > 65536:
                encoded_result = json.dumps({"truncated": True,
                    "error": "Result exceeded persistent storage limit"})
        with self.lock:
            self.db.execute(
                "UPDATE jobs SET state=?, finished_at=?, result_json=?, exit_code=? WHERE id=?",
                (state, utc() if state not in ("queued", "running") else None,
                 encoded_result, exit_code, job_id))
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

    def list_clients(self, limit: int = 100) -> list[dict]:
        """Admin-only inventory; never return bearer, refresh or auth-code secrets."""
        with self.lock:
            return [dict(row) for row in self.db.execute("""
                SELECT c.client_id, c.name, c.created_at,
                       EXISTS(SELECT 1 FROM oauth_tokens t
                              WHERE t.client_id=c.client_id AND t.revoked=0
                                AND t.expires>strftime('%s','now')) AS active
                  FROM oauth_clients c ORDER BY c.created_at DESC LIMIT ?
                """, (max(1, min(limit, 200)),))]

    def revoke_client(self, client_id: str, actor: str = "webui") -> bool:
        if not isinstance(client_id, str) or len(client_id) != 32 or any(
                char not in "0123456789abcdef" for char in client_id):
            raise ValueError("Invalid client ID")
        with self.transaction():
            found = self.db.execute("SELECT client_id FROM oauth_clients WHERE client_id=?",
                                    (client_id,)).fetchone()
            if not found:
                return False
            self.db.execute("UPDATE oauth_tokens SET revoked=1 WHERE client_id=?", (client_id,))
            self.db.execute("DELETE FROM oauth_codes WHERE client_id=?", (client_id,))
            self._audit(actor, "client.revoke", "allow", client_id)
        return True

    def create_api_token(self, name: str, resource: str, issued_for: str, *,
                         days: int = 30, allowed_tools: list[str] | None = None,
                         actor: str = "webui") -> tuple[str, str]:
        """Issue a 384-bit API key once. The database stores only SHA-256."""
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or any(
                ord(c) < 32 or ord(c) == 127 for c in name):
            raise ValueError("Token name must contain 1-80 printable characters")
        if not isinstance(days, int) or not 1 <= days <= 90:
            raise ValueError("API token lifetime must be 1-90 days")
        if not isinstance(resource, str) or not resource.endswith("/mcp"):
            raise ValueError("Invalid MCP resource")
        if not isinstance(issued_for, str) or len(issued_for) != 64:
            raise ValueError("Administrator credential fingerprint required")
        tools = allowed_tools or []
        if (not isinstance(tools, list) or len(tools) > 50 or
                any(not isinstance(tool, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", tool) for tool in tools)):
            raise ValueError("Invalid tool allowlist")
        token_id = uuid4().hex
        token = "kmp_" + token_id + "." + secrets.token_urlsafe(48)
        now = int(time.time())
        with self.transaction():
            if self.db.execute("SELECT count(*) FROM api_tokens WHERE revoked=0").fetchone()[0] >= 200:
                raise ValueError("API token limit reached (revoke unused keys)")
            self.db.execute("""
                INSERT INTO api_tokens(token_id,name,token_hash,resource,scope,allowed_tools,
                                       issued_for,created_at,expires)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (token_id, name.strip(), digest(token), resource, "mcp:tools",
                 json.dumps(sorted(set(tools))), issued_for, now, now + days * 86400))
            self._audit(actor, "api_token.create", "allow", token_id)
        return token_id, token

    def verify_api_token(self, token: str, resource: str, issued_for: str) -> dict | None:
        """Return identity/limits for a valid key, with a constant-time digest comparison."""
        match = re.fullmatch(r"kmp_([0-9a-f]{32})\\.([A-Za-z0-9_-]{64})", token or "")
        if not match:
            return None
        now = int(time.time())
        with self.lock:
            row = self.db.execute("SELECT * FROM api_tokens WHERE token_id=?",
                                  (match.group(1),)).fetchone()
            if (row is None or not hmac.compare_digest(row["token_hash"], digest(token))
                    or row["revoked"] or row["expires"] <= now
                    or row["resource"] != resource or row["scope"] != "mcp:tools"
                    or not hmac.compare_digest(row["issued_for"], issued_for)):
                return None
            self.db.execute("UPDATE api_tokens SET last_used=? WHERE token_id=?", (now, row["token_id"]))
            return {"token_id": row["token_id"], "allowed_tools": json.loads(row["allowed_tools"])}

    def list_api_tokens(self, limit: int = 100) -> list[dict]:
        """Admin inventory never exposes hashes or recoverable secrets."""
        with self.lock:
            return [dict(row) for row in self.db.execute("""
                SELECT token_id,name,resource,scope,allowed_tools,created_at,expires,
                       last_used,revoked FROM api_tokens ORDER BY created_at DESC LIMIT ?""",
                (max(1, min(limit, 200)),))]

    def revoke_api_token(self, token_id: str, *, actor: str = "webui") -> bool:
        if not re.fullmatch(r"[0-9a-f]{32}", token_id or ""):
            raise ValueError("Invalid API token ID")
        with self.transaction():
            changed = self.db.execute(
                "UPDATE api_tokens SET revoked=1 WHERE token_id=? AND revoked=0",
                (token_id,)).rowcount
            if changed:
                self._audit(actor, "api_token.revoke", "allow", token_id)
            return bool(changed)

    def close(self) -> None:
        with self.lock:
            self.db.close()
