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
import shutil
import time
from uuid import uuid4

from .store import Store, digest

# MCP JSON bodies are limited to 256 KiB, so each Base64 part must fit in
# one call with room for the JSON-RPC envelope and tool metadata.
MAX_BASE64_FILE = 128 * 1024  # inline upload/download bytes per RPC
MAX_OPENLINK_FILE = 100_000_000  # 100 decimal MB per complete file
MAX_OWNER_FILES = 16
MAX_OWNER_BYTES = 300_000_000
MAX_GLOBAL_BYTES = 1_000_000_000
MIN_FREE_BYTES = 128 * 1024 * 1024
FILE_LIFETIME = 24 * 3600
LINK_LIFETIME = 10 * 60
MAX_BASE64_SESSION_AGE = 2 * 3600
OPENLINK_STREAM_AGE = 60 * 60  # allow slow streamed upload after link use
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
              created INTEGER NOT NULL, expires INTEGER NOT NULL,
              written INTEGER NOT NULL DEFAULT 0);
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
            raise TransferError("Files must be at most 100 MB")
        # Reserve a minimum amount of disk for the Core DB and event logs,
        # even if the quota counters are still far below their ceilings.
        if shutil.disk_usage(self.directory).free - size < MIN_FREE_BYTES:
            raise TransferError("Not enough disk space for this file transfer")
        row = self.store.db.execute(
            "SELECT COUNT(*) AS files, COALESCE(SUM(size),0) AS bytes FROM transfer_files "
            "WHERE owner=? AND expires>?", (owner, int(time.time()))).fetchone()
        if row["files"] >= MAX_OWNER_FILES or row["bytes"] + size > MAX_OWNER_BYTES:
            raise TransferError("File quota reached: 16 files / 300 MB per MCP client")
        global_reserved = self.store.db.execute(
            "SELECT COALESCE(SUM(size),0) AS bytes FROM transfer_files "
            "WHERE expires>?", (int(time.time()),)).fetchone()["bytes"]
        if global_reserved + size > MAX_GLOBAL_BYTES:
            raise TransferError("Transfer storage quota reached: 1 GB total")

    def _new_record(self, owner: str, name: str, mime: str,
                    size: int, status: str, sha256: str = "") -> str:
        identity = uuid4().hex
        now = int(time.time())
        self.store.db.execute(
            "INSERT INTO transfer_files "
            "(file_id,owner,name,mime_type,size,sha256,status,created,expires,written)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (identity, owner, file_name(name), mime_name(mime), size,
             sha256, status, now,
             now + (LINK_LIFETIME if status in {"pending", "base64-pending"} else FILE_LIFETIME),
             size if status == "ready" else 0))
        return identity

    def _ticket(self, file_id: str, verb: str) -> str:
        secret = secrets.token_urlsafe(36)
        self.store.db.execute("INSERT INTO transfer_tickets VALUES (?,?,?,?,0)",
                              (digest(secret), file_id, verb, int(time.time()) + LINK_LIFETIME))
        return self.public_url + "/files/openlink/" + secret

    def put_bytes(self, owner: str, name: str, mime: str, content: bytes) -> dict:
        if not isinstance(content, bytes) or len(content) > MAX_BASE64_FILE:
            raise TransferError("Inline Base64 supports at most 128 KiB; use chunks for larger files")
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
            raise TransferError("Base64 part exceeds 128 KiB")
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

    def begin_base64(self, owner: str, name: str, mime: str, size: int) -> dict:
        """Reserve a file for ordered small Base64 chunks; 100 MB total."""
        if type(size) is not int or size < 0:
            raise TransferError("Chunked Base64 requires an exact nonnegative byte size")
        self._sweep()
        with self.store.transaction():
            self._quota(owner, size)
            file_id = self._new_record(owner, name, mime, size, "base64-pending")
            path = self._path(file_id)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        return {"ok": True, "file_id": file_id, "mode": "base64",
                "bytes": size, "written": 0, "chunk_bytes": MAX_BASE64_FILE,
                "expires_in": LINK_LIFETIME,
                "hint": "Send chunks sequentially with files_upload_chunk then files_upload_finish."}

    def append_base64(self, owner: str, file_id: str,
                      offset: int, data_base64: str) -> dict:
        """Append one at-most-128-KiB chunk with strict sequential offset."""
        if type(offset) is not int or offset < 0:
            raise TransferError("Base64 chunk offset must be a nonnegative integer")
        if (not isinstance(data_base64, str) or
                len(data_base64) > (MAX_BASE64_FILE * 4 // 3 + 16)):
            raise TransferError("Base64 part exceeds 128 KiB")
        try:
            chunk = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise TransferError("Data is not valid Base64") from exc
        if not chunk or len(chunk) > MAX_BASE64_FILE:
            raise TransferError("Base64 chunk must contain 1–128 KiB")
        self._sweep()
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT * FROM transfer_files WHERE file_id=? AND owner=? "
                "AND status='base64-pending' AND expires>?",
                (file_id, owner, int(time.time()))).fetchone()
            if row is None:
                raise TransferError("Base64 upload not found or expired for this client")
            if offset != row["written"] or offset + len(chunk) > row["size"]:
                raise TransferError("Base64 chunk offset or size mismatch")
            path = self._path(file_id)
            if not path.is_file() or path.is_symlink() or path.stat().st_size != offset:
                raise TransferError("Base64 upload file integrity mismatch")
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            with os.fdopen(fd, "wb") as output:
                output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            # Refresh an idle timeout for long 100 MB MCP transfers while
            # bounding abandoned reservations to two hours overall.
            expires = min(int(time.time()) + LINK_LIFETIME,
                          row["created"] + MAX_BASE64_SESSION_AGE)
            self.store.db.execute(
                "UPDATE transfer_files SET written=written+?,expires=? WHERE file_id=?",
                (len(chunk), expires, file_id))
        return {"ok": True, "file_id": file_id, "written": offset + len(chunk),
                "remaining": row["size"] - offset - len(chunk)}

    def finish_base64(self, owner: str, file_id: str) -> dict:
        """Finalize only complete uploads, hashing the file in bounded chunks."""
        self._sweep()
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT * FROM transfer_files WHERE file_id=? AND owner=? "
                "AND status='base64-pending' AND expires>?",
                (file_id, owner, int(time.time()))).fetchone()
            if row is None:
                raise TransferError("Base64 upload not found or expired for this client")
            if row["written"] != row["size"]:
                raise TransferError("Base64 upload is incomplete")
            path = self._path(file_id)
            if not path.is_file() or path.is_symlink() or path.stat().st_size != row["size"]:
                raise TransferError("Base64 upload file integrity mismatch")
            sha = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    sha.update(chunk)
            self.store.db.execute(
                "UPDATE transfer_files SET status='ready', sha256=?, expires=? "
                "WHERE file_id=? AND status='base64-pending'",
                (sha.hexdigest(), int(time.time()) + FILE_LIFETIME, file_id))
            return {"ok": True, "file_id": file_id, "bytes": row["size"],
                    "sha256": sha.hexdigest(), "expires_in": FILE_LIFETIME}

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
                # The signed URL must be used within 10 minutes, but a large
                # upload may continue for up to an hour after it starts.
                self.store.db.execute(
                    "UPDATE transfer_files SET status='receiving',expires=? WHERE file_id=?",
                    (int(time.time()) + OPENLINK_STREAM_AGE, row["file_id"]))
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

    def get_file(self, owner: str, file_id: str, mode: str,
                 offset: int = 0, max_bytes: int = MAX_BASE64_FILE) -> dict:
        """OpenLink gives a one-use URL; Base64 returns a bounded window.

        Every Base64 response is at most 128 KiB raw (under 175 KiB JSON).
        Clients repeat with next_offset until done, then verify sha256.
        """
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
            if (type(offset) is not int or offset < 0 or offset > row["size"] or
                    type(max_bytes) is not int or not (1 <= max_bytes <= MAX_BASE64_FILE)):
                raise TransferError("Base64 window must be within the file and at most 128 KiB")
            path = self._path(file_id)
            if not path.is_file() or path.is_symlink() or path.stat().st_size != row["size"]:
                raise TransferError("File content is unavailable or modified")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                stream.seek(offset)
                raw = stream.read(min(max_bytes, row["size"] - offset))
            result["data_base64"] = base64.b64encode(raw).decode("ascii")
            result["offset"] = offset
            result["next_offset"] = offset + len(raw)
            result["done"] = result["next_offset"] == row["size"]
            result["chunk_sha256"] = hashlib.sha256(raw).hexdigest()
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
