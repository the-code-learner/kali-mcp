"""Read simple installer-generated KEY=VALUE files (not a shell evaluator)."""
from __future__ import annotations

from pathlib import Path
import re

LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=([^\r\n]*)$")


def parse_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = LINE.fullmatch(line)
        if match:
            result[match.group(1)] = match.group(2).strip('"')
    return result


def set_value(path: Path, key: str, value: str) -> None:
    """Atomically set an installer-owned env value without shell evaluation."""
    import os
    import tempfile
    if not re.fullmatch(r"KALI_MCP_[A-Z0-9_]+", key):
        raise ValueError("Invalid config key")
    if not re.fullmatch(r"[A-Za-z0-9_./:+,@=-]{1,512}", value):
        raise ValueError("Invalid config value")
    old = parse_env(path)
    if not old:
        raise FileNotFoundError("No existing hybrid environment config")
    old[key] = value
    fd, temporary = tempfile.mkstemp(prefix=".stack-env-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            for name, val in old.items():
                stream.write(f"{name}={val}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
