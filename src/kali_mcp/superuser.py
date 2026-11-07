"""Single local superuser for WebUI, CLI and host-privilege approvals.

Uses scrypt (N=2**17, r=8, p=1) from Python's standard library. The
credential record contains a random salt and a slow password hash, NEVER the
cleartext password. Keep root's canonical record out of the Core's writable
volume; mount a read-only, root-maintained copy into the Core instead.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

USERNAME = re.compile(r"^[a-z][a-z0-9_.-]{2,31}$")
N = 1 << 17
R = 8
P = 1
MAXMEM = 256 * 1024 * 1024
DEFAULT_HOST_FILE = Path("/etc/kali-mcp/superuser.json")


def valid_username(name: str) -> bool:
    return isinstance(name, str) and bool(USERNAME.fullmatch(name))


def validate_password(password: str) -> None:
    if not isinstance(password, str) or not (16 <= len(password) <= 256):
        raise ValueError("Superuser password must be 16-256 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in password):
        raise ValueError("Superuser password contains control characters")


def derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=R, p=P,
                          dklen=32, maxmem=MAXMEM)


def make_record(username: str, password: str) -> dict:
    if not valid_username(username):
        raise ValueError("Superuser username must be 3-32 lowercase characters (a-z, 0-9, _, ., -)")
    validate_password(password)
    salt = secrets.token_bytes(24)
    return {"version": 1, "role": "superuser", "username": username,
            "kdf": "scrypt", "n": N, "r": R, "p": P,
            "salt": salt.hex(), "hash": derive(password, salt).hex()}


def save_record(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".superuser-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(record, output, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_record(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > 4096:
        raise ValueError("Invalid superuser record size")
    record = json.loads(raw)
    if (not isinstance(record, dict) or record.get("version") != 1
            or record.get("role") != "superuser"
            or record.get("kdf") != "scrypt"
            or not valid_username(record.get("username"))
            or (record.get("n"), record.get("r"), record.get("p")) != (N, R, P)):
        raise ValueError("Invalid superuser record format")
    if len(bytes.fromhex(record["salt"])) != 24 or len(bytes.fromhex(record["hash"])) != 32:
        raise ValueError("Invalid superuser credential fields")
    return record


def verify(record: dict, username: str, password: str) -> bool:
    """Single slow hash even when username is unknown, avoiding fast enumeration."""
    if not isinstance(username, str) or not isinstance(password, str) or len(password) > 256:
        return False
    try:
        actual = derive(password, bytes.fromhex(record["salt"]))
        same_user = hmac.compare_digest(username.encode(), record["username"].encode())
        same_secret = hmac.compare_digest(actual, bytes.fromhex(record["hash"]))
        return bool(same_user and same_secret)
    except (KeyError, TypeError, ValueError, MemoryError):
        return False


def record_fingerprint(record: dict) -> str:
    """Changes when password changes; therefore invalidates old web sessions."""
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
