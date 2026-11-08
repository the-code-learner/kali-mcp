"""Bounded MCP client/server file exchange, confined to a private Core workspace.

No host filesystem paths, Docker mounts or root/host permission toggles are exposed.
OpenLink URLs are short-lived single-use bearer capabilities, not public file shares.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import mimetypes
import os
from pathlib import Path
import re
import secrets
import time
from uuid import uuid4

from .store import Store, digest

MAX_BASE64_FILE = 256 * 1024
MAX_OPENLINK_FILE = 8 * 1024 * 1024
MAX_OWNER_FILES = 16
MAX_OWNER_BYTES = 32 * 1024 * 1024
FILE_LIFETIME = 24 * 3600
LINK_LIFETIME = 10 * 60
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{40,96}$")
MIME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+_-]*/[a-zA-Z0-9][a-zA-Z0-9.+_-]*$")


class TransferError(ValueError):
    pass


def file_name(name: str) -> str:
    if (not isinstance(name, str) or not name or name in {".", ".."} or
            len(name.encode("utf-8")) > 120 or
            "/" in name or "\\" in name or
            any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise TransferError("File name must be a single safe basename (max 120 bytes)")
    return name


def mime_name(value: str) -> str:
    if not isinstance(value, str) or len(value) > 100 or not MIME_RE.fullmatch(value):
        raise TransferError("Invalid MIME type")
    return value


class TransferVault:
    def __init__(self, directory: Path, store: Store, public_url: str):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise RuntimeError("Refusing symbolic-link transfer directory")
        os.chmod(self.directory, 0o700)
        self.store = store
        self.public_url = public_url.rstrip("/")
        with store.lock:
            store.db.executescript("""
            CREATE TABLE IF NOT EXISTS transfer_files (
              file_id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL,
              mime_type TEXT NOT NULL, size INTEGER NOT NULL,
              sha256 TEXT NOT NULL, status TEXT NOT NULL,
              created INTEGER NOT NULL, expires INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS transfer_owner ON transfer_files(owner,expires);
            CREATE TABLE IF NOT EXISTS transfer_tickets (
              ticket_hash TEXT PRIMARY KEY, file_id TEXT NOT NULL,
              verb TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS transfer_tickets_expiry ON transfer_tickets(expires);
            """)

    def _path(self, file_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", file_id):
            raise TransferError("Invalid transfer ID")
        return self.directory / file_id

    def _sweep(self) -> None:
        now = int(time.time())
        with self.store.transaction():
            ids = [row["file_id"] for row in self.store.db.execute(
                "SELECT file_id FROM transfer_files WHERE expires<=?", (now,))]
            self.store.db.execute("DELETE FROM transfer_tickets WHERE expires<=?", (now,))
            self.store.db.execute(
                "DELETE FROM transfer_tickets WHERE file_id IN "
                "(SELECT file_id FROM transfer_files WHERE expires<=?)", (now,))
            self.store.db.execute("DELETE FROM transfer_files WHERE expires<=?", (now,))
        for file_id in ids:
            self._path(file_id).unlink(missing_ok=True)

    def _quota(self, owner: str, size: int) -> None:
        if not owner.startswith(("mcp:oauth:", "mcp:api:")) or len(owner) > 140:
            raise TransferError("Only authenticated MCP clients can transfer files")
        if size < 0 or size > MAX_OPENLINK_FILE:
            raise TransferError("OpenLink files must be at most 8 MiB")
        row = self.store.db.execute(
            "SELECT COUNT(*) AS files, COALESCE(SUM(size),0) AS bytes FROM transfer_files "
            "WHERE owner=? AND expires>?", (owner, int(time.time()))).fetchone()
        if row["files"] >= MAX_OWNER_FILES or row["bytes"] + size > MAX_OWNER_BYTES:
            raise TransferError("File quota reached: 16 files / 32 MiB per MCP client")

    def _new_record(self, owner: str, name: str, mime: str,
                    size: int, status: str, sha256: str = "") -> str:
        identity = uuid4().hex
        now = int(time.time())
        self.store.db.execute(
            "INSERT INTO transfer_files VALUES (?,?,?,?,?,?,?,?,?)",
            (identity, owner, file_name(name), mime_name(mime), size,
             sha256, status, now, now + (LINK_LIFETIME if status == "pending" else FILE_LIFETIME)))
        return identity

    def _ticket(self, file_id: str, verb: str) -> str:
        secret = secrets.token_urlsafe(36)
        self.store.db.execute("INSERT INTO transfer_tickets VALUES (?,?,?,?,0)",
                              (digest(secret), file_id, verb, int(time.time()) + LINK_LIFETIME))
        return self.public_url + "/files/openlink/" + secret

    def put_bytes(self, owner: str, name: str, mime: str, content: bytes) -> dict:
        if not isinstance(content, bytes) or len(content) > MAX_BASE64_FILE:
            raise TransferError("Base64 mode supports at most 256 KiB per file")
        self._sweep()
        with self.store.transaction():
            self._quota(owner, len(content))
            file_id = self._new_record(owner, name, mime, len(content), "ready",
                                       hashlib.sha256(content).hexdigest())
            path = self._path(file_id)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(content)
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        return {"ok": True, "file_id": file_id, "name": name, "mime_type": mime,
                "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                "expires_in": FILE_LIFETIME}

    def put_base64(self, owner: str, name: str, mime: str, value: str) -> dict:
        if not isinstance(value, str) or len(value) > (MAX_BASE64_FILE * 4 // 3 + 16):
            raise TransferError("Base64 upload exceeds 256 KiB")
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise TransferError("Data is not valid Base64") from exc
        return self.put_bytes(owner, name, mime, raw)

    def begin_upload(self, owner: str, name: str, mime: str, size: int) -> dict:
        if type(size) is not int or size < 0:
            raise TransferError("Upload requires an exact nonnegative byte size")
        self._sweep()
        with self.store.transaction():
            self._quota(owner, size)
            file_id = self._new_record(owner, name, mime, size, "pending")
            url = self._ticket(file_id, "PUT")
        return {"ok": True, "file_id": file_id, "mode": "openlink",
                "upload_url": url, "method": "PUT",
                "content_type": "application/octet-stream", "bytes": size,
                "expires_in": LINK_LIFETIME,
                "hint": "PUT exactly this number of raw bytes to the signed URL once."}

    def _consume(self, secret: str, verb: str, status: str) -> dict | None:
        if not TOKEN_RE.fullmatch(secret):
            return None
        now = int(time.time())
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT f.*,t.ticket_hash FROM transfer_tickets t "
                "JOIN transfer_files f ON f.file_id=t.file_id "
                "WHERE t.ticket_hash=? AND t.verb=? AND t.used=0 "
                "AND t.expires>? AND f.expires>? AND f.status=?",
                (digest(secret), verb, now, now, status)).fetchone()
            if row is None:
                return None
            changed = self.store.db.execute(
                "UPDATE transfer_tickets SET used=1 WHERE ticket_hash=? AND used=0",
                (row["ticket_hash"],)).rowcount
            if not changed:
                return None
            if verb == "PUT":
                self.store.db.execute("UPDATE transfer_files SET status='receiving' WHERE file_id=?",
                                      (row["file_id"],))
            return dict(row)

    def consume_download(self, secret: str) -> tuple[Path, str] | None:
        row = self._consume(secret, "GET", "ready")
        if not row:
            return None
        path = self._path(row["file_id"])
        if not path.is_file() or path.is_symlink():
            return None
        return path, row["name"]

    async def receive_upload(self, secret: str, stream, declared_size: int | None) -> dict:
        if declared_size is not None and (declared_size < 0 or declared_size > MAX_OPENLINK_FILE):
            raise TransferError("Upload Content-Length is out of bounds")
        row = self._consume(secret, "PUT", "pending")
        if not row:
            raise TransferError("Upload link is invalid, expired or already used")
        file_id = row["file_id"]
        path = self._path(file_id)
        received = 0
        sha = hashlib.sha256()
        try:
            if declared_size is not None and declared_size != row["size"]:
                raise TransferError("Content-Length does not match prepared upload")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                async for chunk in stream:
                    received += len(chunk)
                    if received > row["size"] or received > MAX_OPENLINK_FILE:
                        raise TransferError("Upload exceeds the declared size")
                    output.write(chunk)
                    sha.update(chunk)
            if received != row["size"]:
                raise TransferError("Upload is incomplete")
            with self.store.transaction():
                self.store.db.execute(
                    "UPDATE transfer_files SET status='ready',sha256=?,expires=? "
                    "WHERE file_id=? AND status='receiving'",
                    (sha.hexdigest(), int(time.time()) + FILE_LIFETIME, file_id))
            return {"ok": True, "file_id": file_id, "bytes": received, "sha256": sha.hexdigest()}
        except BaseException:
            path.unlink(missing_ok=True)
            with self.store.transaction():
                self.store.db.execute("DELETE FROM transfer_tickets WHERE file_id=?", (file_id,))
                self.store.db.execute("DELETE FROM transfer_files WHERE file_id=?", (file_id,))
            raise

    def get_file(self, owner: str, file_id: str, mode: str) -> dict:
        self._sweep()
        if not re.fullmatch(r"[a-f0-9]{32}", file_id):
            raise TransferError("Unknown file ID")
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT * FROM transfer_files WHERE file_id=? AND owner=? "
                "AND status='ready' AND expires>?",
                (file_id, owner, int(time.time()))).fetchone()
            if not row:
                raise TransferError("File not found for this MCP client")
            result = {"ok": True, "file_id": file_id, "name": row["name"],
                      "mime_type": row["mime_type"], "bytes": row["size"],
                      "sha256": row["sha256"], "mode": mode}
            if mode == "openlink":
                result.update({"url": self._ticket(file_id, "GET"),
                               "method": "GET", "expires_in": LINK_LIFETIME,
                               "single_use": True})
                return result
            if mode != "base64":
                raise TransferError("File mode must be 'openlink' or 'base64'")
            if row["size"] > MAX_BASE64_FILE:
                raise TransferError("File exceeds Base64 limit; use OpenLink")
            path = self._path(file_id)
            if not path.is_file() or path.is_symlink():
                raise TransferError("File content is unavailable")
            raw = path.read_bytes()
            if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise TransferError("File integrity validation failed")
            result["data_base64"] = base64.b64encode(raw).decode("ascii")
            return result

    def list_files(self, owner: str) -> dict:
        self._sweep()
        with self.store.lock:
            rows = self.store.db.execute(
                "SELECT file_id,name,mime_type,size,sha256,status,expires FROM transfer_files "
                "WHERE owner=? AND expires>? ORDER BY created DESC LIMIT 16",
                (owner, int(time.time()))).fetchall()
        return {"ok": True, "files": [dict(row) for row in rows]}

    def delete(self, owner: str, file_id: str) -> dict:
        if not re.fullmatch(r"[a-f0-9]{32}", file_id):
            raise TransferError("Unknown file ID")
        with self.store.transaction():
            valid = self.store.db.execute(
                "SELECT file_id FROM transfer_files WHERE file_id=? AND owner=?",
                (file_id, owner)).fetchone()
            if not valid:
                raise TransferError("File not found for this MCP client")
            self.store.db.execute("DELETE FROM transfer_tickets WHERE file_id=?", (file_id,))
            self.store.db.execute("DELETE FROM transfer_files WHERE file_id=?", (file_id,))
        self._path(file_id).unlink(missing_ok=True)
        return {"ok": True, "deleted": file_id}
