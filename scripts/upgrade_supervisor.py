#!/usr/bin/env python3
"""Detached upgrade supervisor: persist actual installer phases across restarts.

This script runs as root in its own transient systemd unit. It does not expose
arbitrary commands; the Host Agent has already verified a GitHub release tag.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, "/opt/kali-mcp/current/src")
from kali_mcp.update_state import save

STATE_DIR = Path("/var/lib/kali-mcp")
INSTALLER = Path("/opt/kali-mcp/current/scripts/install-hybrid.sh")
CURRENT = Path("/opt/kali-mcp/current")
INSTALL_LOG = Path("/var/log/kali-mcp/install.log")
SUPERVISOR_LOG = Path("/var/log/kali-mcp/update-supervisor.log")
PHASE_MAP = {
    "preflight": "preflight", "download": "download", "source": "download",
    "backup": "backup", "wizard": "configuration",
    "legacy-config-migration": "configuration", "credentials": "configuration",
    "native-dependencies": "dependencies", "activation": "activation",
    "healthcheck": "healthcheck",
}
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[0-9]+)?\Z")
PHASE_RE = re.compile(r" phase=([a-z-]{3,40})\s*$")
POLL_SECONDS = 1.0


def _health(tag: str) -> None:
    current = CURRENT.resolve(strict=True)
    if current.name != tag:
        raise RuntimeError("Installed release does not match the requested tag")
    observed = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.State.Health.Status}}", "kali-mcp-core"],
        text=True, timeout=15).strip()
    if observed != "healthy":
        raise RuntimeError("Core Docker healthcheck not healthy")
    subprocess.run(["systemctl", "is-active", "--quiet", "kali-mcp-agent.service"],
                   check=True, timeout=15)
    if not Path("/run/kali-mcp-agent/agent.sock").is_socket():
        raise RuntimeError("Native Agent socket missing after upgrade")


def run(tag: str) -> None:
    if os.geteuid() != 0 or not TAG_RE.fullmatch(tag):
        raise ValueError("Unauthorized update supervisor arguments")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE_DIR / ".update-worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another update supervisor is already active") from exc
        previous = CURRENT.resolve(strict=True) if CURRENT.is_symlink() else None
        save(state="running", phase="preflight", tag=tag,
             detail="Starting verified systemd upgrade")
        if not INSTALLER.is_file():
            save(state="failed", phase="failed", tag=tag, detail="Installer is missing")
            raise RuntimeError("Installer is missing")
        env = dict(os.environ)
        env["KALI_MCP_VERSION"] = tag
        # The installer runs a fixed audited Bash script; arguments cannot be
        # provided by the MCP client.
        phase = "preflight"
        try:
            INSTALL_LOG.parent.mkdir(parents=True, exist_ok=True)
            before = INSTALL_LOG.stat().st_size if INSTALL_LOG.exists() else 0
            with SUPERVISOR_LOG.open("a", encoding="utf-8") as transcript:
                os.chmod(transcript.name, 0o600)
                proc = subprocess.Popen(["/bin/bash", str(INSTALLER), "--upgrade"],
                                        env=env, stdin=subprocess.DEVNULL,
                                        stdout=transcript, stderr=subprocess.STDOUT)
                while proc.poll() is None:
                    try:
                        with INSTALL_LOG.open("r", encoding="utf-8", errors="replace") as stream:
                            stream.seek(before)
                            new_text = stream.read(65536)
                            before = stream.tell()
                        for line in new_text.splitlines():
                            match = PHASE_RE.search(line)
                            if match:
                                next_phase = PHASE_MAP.get(match.group(1))
                                if next_phase and phase != next_phase:
                                    phase = next_phase
                                    save(state="running", phase=phase, tag=tag,
                                         detail="Installer phase: " + next_phase)
                    except OSError:
                        pass
                    time.sleep(POLL_SECONDS)
                code = proc.wait(timeout=15)
            if code:
                raise RuntimeError("Installer exited unsuccessfully")
            save(state="running", phase="healthcheck", tag=tag,
                 detail="Verifying installed version and services")
            _health(tag)
            save(state="completed", phase="completed", tag=tag,
                 detail="Release and Core/Agent health verified")
        except BaseException as exc:
            try:
                after = CURRENT.resolve() if CURRENT.is_symlink() else None
                restored = (previous is not None and after == previous and
                            phase in {"activation", "healthcheck"})
            except OSError:
                restored = False
            state = "rolled_back" if restored else "failed"
            save(state=state, phase=state, tag=tag,
                 detail=("Previous release restored" if restored else
                         "Upgrade failed; inspect /var/log/kali-mcp/install.log"))
            raise


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--tag", required=True)
    args = p.parse_args()
    run(args.tag)
