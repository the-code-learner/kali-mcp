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
