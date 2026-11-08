"""Real installer progress is root-owned, persistent and not a scheduling-job guess."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from kali_mcp.config import Config
from kali_mcp.host_agent import AgentState, NativeAgent
from kali_mcp.update_state import load, save, is_inflight
from scripts import upgrade_supervisor as worker


def test_private_update_status_survives_process_restart(tmp_path):
    path = tmp_path / "update-status.json"
    assert load(path)["state"] == "idle"
    first = save(state="scheduled", phase="scheduled", tag="v0.1.0-beta.12",
                 unit="kali-mcp-update-abcdef", path=path)
    assert first["state"] == "scheduled"
    assert is_inflight(load(path))
    assert path.stat().st_mode & 0o777 == 0o600
    started = save(state="running", phase="download", tag="v0.1.0-beta.12",
                   detail="Downloading release", path=path)
    assert started["started_at"] == first["started_at"]
    assert load(path)["phase"] == "download"
    done = save(state="completed", phase="completed", tag="v0.1.0-beta.12",
                detail="Version and health verified", path=path)
    assert done["state"] == "completed"
    assert not is_inflight(load(path))
    assert done["unit"] == "kali-mcp-update-abcdef"
    path.unlink()
    path.symlink_to(tmp_path / "other-file")
    with pytest.raises(RuntimeError, match="symlink"):
        save(state="running", phase="activation", tag="v0.1.0-beta.12", path=path)


def test_agent_schedules_fixed_supervisor_and_rejects_concurrent_updates(
        tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_ALLOW_MCP_UPDATES", "true")
    cfg = Config.from_env()
    state = AgentState(tmp_path / "agent-state.json")
    state.set_setting("mcp_updates", True, cfg)
    agent = NativeAgent(cfg, state)
    monkeypatch.setattr("kali_mcp.host_agent.query_releases", lambda repo: [])
    monkeypatch.setattr("kali_mcp.host_agent.select_release", lambda *_:
                        SimpleNamespace(tag="v0.1.0-beta.12"))
    scheduled = []
    monkeypatch.setattr("kali_mcp.host_agent.save_update_state",
                        lambda **args: scheduled.append(args))
    monkeypatch.setattr("kali_mcp.host_agent.load_update_state",
                        lambda: {"state": "idle"})
    commands = []
    monkeypatch.setattr(agent, "_run", lambda argv, **kwargs:
                        commands.append(argv) or {"exit_code": 0})
    result = agent.dispatch("updates_install", {"tag": "v0.1.0-beta.12"})
    assert result["scheduled"] is True and commands
    assert "upgrade_supervisor.py" in " ".join(commands[0])
    assert commands[0][-2:] == ["--tag", "v0.1.0-beta.12"]
    assert scheduled[0]["state"] == "scheduled"
    assert scheduled[0]["tag"] == "v0.1.0-beta.12"

    monkeypatch.setattr("kali_mcp.host_agent.load_update_state",
                        lambda: {"state": "running",
                                 "phase": "download",
                                 "updated_at": __import__("datetime").datetime.now(
                                     __import__("datetime").timezone.utc).isoformat()})
    with pytest.raises(Exception, match="already scheduled or running"):
        agent.dispatch("updates_install", {"tag": "v0.1.0-beta.12"})
    assert len(commands) == 1
    response = agent.dispatch("update_status_get", {})
    assert response["update"]["state"] == "running"


def test_supervisor_tracks_real_installer_and_reports_success_or_failure(
        tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    current_release = tmp_path / "v0.1.0-beta.11"
    current_release.mkdir()
    current = tmp_path / "current"
    current.symlink_to(current_release, target_is_directory=True)
    installer = tmp_path / "installer.sh"
    installer.write_text("#!/bin/sh\nexit 0\n")
    log = tmp_path / "install.log"
    log.write_text("")
    monkeypatch.setattr(worker, "STATE_DIR", state_dir)
    monkeypatch.setattr(worker, "INSTALLER", installer)
    monkeypatch.setattr(worker, "CURRENT", current)
    monkeypatch.setattr(worker, "INSTALL_LOG", log)
    monkeypatch.setattr(worker, "SUPERVISOR_LOG", tmp_path / "supervisor.log")
    monkeypatch.setattr(worker.os, "geteuid", lambda: 0)
    monkeypatch.setattr(worker.time, "sleep", lambda _duration: None)
    monkeypatch.setattr(worker, "_health", lambda tag: None)
    captured = []
    def status(**kwargs):
        captured.append(dict(kwargs))
        return save(**kwargs, path=tmp_path / "status.json")
    monkeypatch.setattr(worker, "save", status)

    class Fake:
        def __init__(self, command, **kwargs):
            self.calls = 0
            assert "--upgrade" in command
            with log.open("a") as stream:
                stream.write("2026-11-08T20:00:00Z phase=backup\n")
                stream.write("2026-11-08T20:00:01Z phase=healthcheck\n")
        def poll(self):
            self.calls += 1
            return None if self.calls == 1 else 0
        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(worker.subprocess, "Popen", Fake)
    worker.run("v0.1.0-beta.12")
    assert load(tmp_path / "status.json")["state"] == "completed"
    assert "healthcheck" in [x["phase"] for x in captured]
    assert captured[-1]["detail"] == "Release and Core/Agent health verified"

    class Failing(Fake):
        def poll(self):
            return 3
        def wait(self, timeout=None):
            return 3
    monkeypatch.setattr(worker.subprocess, "Popen", Failing)
    with pytest.raises(RuntimeError, match="unsuccessfully"):
        worker.run("v0.1.0-beta.12")
    assert load(tmp_path / "status.json")["state"] == "failed"
    assert captured[-1]["phase"] == "failed"  # Not a fake rollback

    with pytest.raises(ValueError):
        worker.run("../arbitrary-file")
