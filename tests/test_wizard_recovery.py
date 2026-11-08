"""Crash-recovery and atomic-write regressions for the hybrid wizard."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts import wizard


PASSWORD = "A_test_only_superuser_password_2026!"


def test_resume_partial_wizard_without_losing_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("KALI_MCP_ACCESS_MODE", "local")
    monkeypatch.setenv("KALI_MCP_RELEASE_CHANNEL", "beta")
    wizard.configure(tmp_path, 1234, interactive=False, host_user="kali")
    assert wizard.is_complete(tmp_path)
    credentials = (tmp_path / "superuser.json").read_bytes()

    # The specific beta.4 crash: stack.env + superuser exist; agent.env absent.
    (tmp_path / "agent.env").unlink()
    assert not wizard.is_complete(tmp_path)
    wizard.configure(tmp_path, 1234, interactive=False, host_user="kali")
    assert wizard.is_complete(tmp_path)
    assert (tmp_path / "superuser.json").read_bytes() == credentials

    # Simulate SIGKILL after the stack write; old success marker must not survive.
    real_writer = wizard.write_private
    def interrupted(path, data):
        real_writer(path, data)
        if path.name == "stack.env":
            raise RuntimeError("simulated power loss")
    monkeypatch.setattr(wizard, "write_private", interrupted)
    with pytest.raises(RuntimeError, match="simulated power loss"):
        wizard.configure(tmp_path, 1234, interactive=False, host_user="kali")
    assert not wizard.is_complete(tmp_path)
    monkeypatch.setattr(wizard, "write_private", real_writer)
    wizard.configure(tmp_path, 1234, interactive=False, host_user="kali")
    assert wizard.is_complete(tmp_path)
    assert (tmp_path / "superuser.json").read_bytes() == credentials

    for name in ("stack.env", "agent.env", "superuser.json", "config.ready"):
        assert (tmp_path / name).stat().st_mode & 0o777 == 0o600


def test_private_file_atomic_write_leaves_no_tempfiles(tmp_path):
    target = tmp_path / "stack.env"
    wizard.write_private(target, {"EXAMPLE": "one"})
    assert target.read_text() == "EXAMPLE=one\n"
    wizard.write_private(target, {"EXAMPLE": "two"})
    assert target.read_text() == "EXAMPLE=two\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["stack.env"]
