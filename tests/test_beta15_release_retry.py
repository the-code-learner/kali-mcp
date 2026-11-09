"""Release discovery retries after temporary Core DNS failures."""
from __future__ import annotations

import pytest

import kali_mcp.releases as releases


def test_error_retries_automatically_and_returns_to_normal_interval(monkeypatch):
    tick = [1000.0]
    monkeypatch.setattr(releases.time, "monotonic", lambda: tick[0])
    calls = [0]

    def flaky(repository):
        calls[0] += 1
        if calls[0] < 4:
            raise OSError("DNS temporarily unavailable")
        return [{"tag_name": "v0.1.0-beta.15", "prerelease": True, "draft": False}]

    monkeypatch.setattr(releases, "query_releases", flaky)
    c = releases.UpdateChecker("the-code-learner/kali-mcp", "beta", 21600)
    assert c.check()["error"]
    assert c.retry_in_seconds() == 30
    tick[0] += 29
    assert c.check()["error"]
    assert calls[0] == 1
    tick[0] += 1
    assert c.check()["error"]
    assert c.retry_in_seconds() == 60
    tick[0] += 60
    assert c.check()["error"]
    assert c.retry_in_seconds() == 120
    tick[0] += 120
    assert c.check()["latest"] == "v0.1.0-beta.15"
    assert c.status()["error"] == ""
    assert c.retry_in_seconds() == 21600
    assert calls[0] == 4
    tick[0] += 30
    assert c.check()["latest"] == "v0.1.0-beta.15"
    assert calls[0] == 4


def test_force_update_overrides_failure_backoff(monkeypatch):
    tick = [2000.0]
    monkeypatch.setattr(releases.time, "monotonic", lambda: tick[0])
    queue = iter([OSError("DNS failed"), []])

    def query(repository):
        value = next(queue)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(releases, "query_releases", query)
    checker = releases.UpdateChecker("the-code-learner/kali-mcp", "stable", 21600)
    assert checker.check(force=True)["error"]
    response = checker.check(force=True)
    assert response["error"] == ""
    assert response["checked"] is True
    assert response["latest"] is None
    assert checker.retry_in_seconds() == 21600


def test_retry_interval_backoff_is_bounded(monkeypatch):
    tick = [3000.0]
    monkeypatch.setattr(releases.time, "monotonic", lambda: tick[0])

    def broken(repository):
        raise TimeoutError("DNS timeout")

    monkeypatch.setattr(releases, "query_releases", broken)
    checker = releases.UpdateChecker("the-code-learner/kali-mcp", "beta", 21600)
    for interval in [30, 60, 120, 240, 300, 300]:
        checker.check(force=True)
        assert checker.retry_in_seconds() == interval
        tick[0] += interval
