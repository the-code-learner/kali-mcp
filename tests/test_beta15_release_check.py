"""Release-check feedback tests: no falsely successful empty or failed results."""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.releases import UpdateChecker, select_release
from kali_mcp.store import Store
from kali_mcp.webui import UI
import kali_mcp.releases as releases


@dataclass
class StubChecker:
    response: dict

    def check(self, *, force: bool = False) -> dict:
        assert force is True
        return dict(self.response)


@pytest.mark.parametrize(
    "snapshot,status,expected_phrase",
    [
        ({"channel": "beta", "latest": "v0.1.0-beta.15",
          "error": "", "checked": True}, 200, "v0.1.0-beta.15"),
        ({"channel": "stable", "latest": None, "error": "",
          "checked": True}, 200, "No eligible releases in the stable channel"),
        ({"channel": "beta", "latest": None, "error": "URLError: DNS resolution failed",
          "checked": True}, 503, "GitHub release check failed"),
    ],
)
def test_webui_update_check_reports_actual_result(tmp_path, monkeypatch,
                                                    snapshot, status, expected_phrase):
    store = Store(tmp_path / "store.db")
    ui = UI(None, store, None, None, StubChecker(snapshot))
    # These tests isolate the check result after the usual authentication and
    # CSRF guards; production guards themselves are covered elsewhere.
    monkeypatch.setattr(ui, "_admin", lambda request: None)
    monkeypatch.setattr(ui, "_csrf", lambda request, csrf: None)
    app = Starlette(routes=[
        Route("/api/v1/updates/check", ui.update_check, methods=["POST"])
    ])
    try:
        with TestClient(app) as client:
            r = client.post("/api/v1/updates/check",
                data={"csrf": "test"},
                headers={"Accept": "application/json"})
            assert r.status_code == status
            body = r.json()
            assert expected_phrase in body["message"]
            assert body["channel"] == snapshot["channel"]
            assert body["ok"] is (status == 200)
            assert r.headers["cache-control"] == "private, no-store"
            audits = store.list_audit(5)
            assert audits[0]["action"] == "updates.check"
            assert audits[0]["decision"] == ("failed" if status == 503 else "allow")
    finally:
        store.close()


def test_release_checker_beta_channel_returns_published_beta(monkeypatch):
    records = [
        {"tag_name": "v0.1.0-beta.14", "prerelease": True, "draft": False},
        {"tag_name": "v0.1.0-beta.15", "prerelease": True, "draft": False},
        {"tag_name": "v0.1.0-beta.99", "prerelease": True, "draft": True},
    ]
    monkeypatch.setattr(releases, "query_releases", lambda repository: records)
    check = UpdateChecker("the-code-learner/kali-mcp", "beta", 3600).check(force=True)
    assert check["latest"] == "v0.1.0-beta.15"
    assert check["error"] == ""
    assert check["checked"]


def test_release_checker_exposes_real_github_failure(monkeypatch):
    def fail(repository):
        raise OSError("No route to GitHub")
    monkeypatch.setattr(releases, "query_releases", fail)
    check = UpdateChecker("the-code-learner/kali-mcp", "beta", 3600).check(force=True)
    assert check["latest"] is None
    assert "OSError" in check["error"]
    assert "No route to GitHub" in check["error"]
    assert check["checked"] is True
