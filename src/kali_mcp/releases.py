"""GitHub Release checker, with separate stable/beta channels and no automatic installs."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import time
import urllib.request

from packaging.version import Version, InvalidVersion


REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+(?:-beta\.\d+)?$")


def installed_release_tag(version_file: Path | None = None) -> str | None:
    """Read the source release mounted in the running Core, not GitHub's latest.

    The container's read-only release bind mount is replaced when the Core is
    recreated, so this value changes only after activation, not when scheduled.
    """
    source = version_file if version_file is not None else Path(__file__).resolve().parents[2] / "VERSION"
    try:
        version = source.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    tag = "v" + version
    return tag if TAG_PATTERN.fullmatch(tag) else None


def is_update_available(installed: str | None, latest: str | None) -> bool | None:
    """Return None when installation/comparison is unknown, not a false success."""
    if not installed or not latest:
        return None
    if not TAG_PATTERN.fullmatch(installed) or not TAG_PATTERN.fullmatch(latest):
        return None
    try:
        def parsed(tag: str) -> Version:
            return Version(tag[1:].replace("-beta.", "b"))
        return parsed(latest) > parsed(installed)
    except InvalidVersion:
        return None


@dataclass(frozen=True)
class Release:
    tag: str
    version: Version
    prerelease: bool
    published_at: str


def select_release(payload: list[dict], channel: str) -> Release | None:
    if channel not in {"stable", "beta"}:
        raise ValueError("Unknown release channel")
    candidates: list[Release] = []
    for item in payload:
        tag = str(item.get("tag_name", ""))
        if item.get("draft") or not TAG_PATTERN.fullmatch(tag):
            continue
        try:
            version = Version(tag[1:].replace("-beta.", "b"))
        except InvalidVersion:
            continue
        prerelease = bool(item.get("prerelease")) or version.is_prerelease
        if channel == "stable" and prerelease:
            continue
        if channel == "beta" and prerelease and "-beta." not in tag:
            continue
        candidates.append(Release(tag, version, prerelease, str(item.get("published_at") or "")))
    return max(candidates, key=lambda r: r.version) if candidates else None


def query_releases(repo: str, *, timeout: int = 15) -> list[dict]:
    if not REPO_PATTERN.fullmatch(repo):
        raise ValueError("Invalid GitHub repository")
    url = f"https://api.github.com/repos/{repo}/releases?per_page=100"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "Kali-MCP-release-checker",
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise RuntimeError("Release response too large")
    payload = json.loads(data)
    if not isinstance(payload, list):
        raise RuntimeError("Invalid GitHub response")
    return payload


class UpdateChecker:
    def __init__(self, repo: str, channel: str, interval: int):
        self.repo, self.channel, self.interval = repo, channel, interval
        self.last_checked = 0.0
        self.last_error = ""
        self.latest: Release | None = None

    def check(self, *, force: bool = False) -> dict:
        if force or time.monotonic() - self.last_checked >= self.interval:
            try:
                self.latest = select_release(query_releases(self.repo), self.channel)
                self.last_error = ""
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
            self.last_checked = time.monotonic()
        return self.status()

    def status(self) -> dict:
        return {
            "channel": self.channel,
            "latest": self.latest.tag if self.latest else None,
            "prerelease": bool(self.latest and self.latest.prerelease),
            "error": self.last_error,
            "checked": bool(self.last_checked),
            "install_automatic": False,
        }
