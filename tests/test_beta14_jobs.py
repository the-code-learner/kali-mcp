"""beta.14 regression tests: job lifecycle, broker termination and flexible discovery."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sys
import threading
import time
from uuid import uuid4

import pytest

from kali_mcp.broker import Broker
from kali_mcp.config import Config
from kali_mcp.jobs import Jobs
from kali_mcp.policy import Policy, PolicyDenied
from kali_mcp.registry import discover
from kali_mcp.store import Store
import kali_mcp.jobs as jobs_module


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "http://localhost:8787")
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KALI_MCP_ALLOW_ALL_TARGETS", "true")
    monkeypatch.setenv("KALI_MCP_DENIED_CIDRS", "192.168.137.0/24")
    config = Config.from_env()
    store = Store(tmp_path / "jobs.db")
    yield config, store
    store.close()


def test_permissive_scope_remains_explicit_and_deny_first(state):
    cfg, store = state
    policy = Policy(cfg, store)
    assert policy.check_target("192.168.0.80") == "192.168.0.80"
    with pytest.raises(PolicyDenied):
        policy.check_target("192.168.137.68")


def test_discover_understands_natural_wifi_and_network_queries():
    wifi = {x["id"] for x in discover("wifi wireless scan")}
    network = {x["id"] for x in discover("network discovery scan")}
    assert {"aircrack-ng", "kismet"} <= wifi
    assert "nmap" in network
    assert len(discover("")) >= 10
    assert discover("unrelated_nonexistent_widget_qqq") == []


def test_final_job_state_cannot_be_overwritten(state):
    _, store = state
    job_id = store.new_job("mcp:test", "script:bash", "host", {"script": "secret"})
    store.job_state(job_id, "cancelled", result={"cancelled": True})
    store.job_state(job_id, "completed", result={"exit_code": 0}, exit_code=0)
    snapshot = store.get_job(job_id)
    assert snapshot["state"] == "cancelled"
    assert snapshot["result"]["cancelled"] is True
    assert snapshot["args"]["script"] == "[REDACTED]"
    assert [x["data"] for x in store.job_events(job_id)] == ["cancelled"]


def test_broker_cancels_active_process_group(state):
    cfg, store = state
    broker = Broker(cfg, store)
    job_id = uuid4().hex
    finished = []
    thread = threading.Thread(target=lambda: finished.append(
        broker._run([sys.executable, "-c", "import time; time.sleep(20)"],
                    job_id=job_id, timeout=25)))
    thread.start()
    until = time.monotonic() + 5
    while time.monotonic() < until:
        with broker._job_lock:
            active = job_id in broker._active_jobs
        if active:
            break
        time.sleep(0.02)
    else:
        pytest.fail("Broker did not register the running process")
    result = broker.dispatch("job_cancel", {"job_id": job_id})
    assert result["accepted"] is True
    thread.join(6)
    assert not thread.is_alive(), "Cancelled process did not exit"
    assert finished[0]["cancelled"] is True
    assert finished[0]["exit_code"] == 130
    with broker._job_lock:
        assert job_id not in broker._active_jobs


def test_broker_prestart_cancellation_never_executes_command(state, tmp_path):
    cfg, store = state
    broker = Broker(cfg, store)
    job_id = uuid4().hex
    output = tmp_path / "should-not-exist"
    assert broker.dispatch("job_cancel", {"job_id": job_id})["accepted"] is True
    result = broker._run([sys.executable, "-c",
                          "from pathlib import Path; Path(%r).touch()" % str(output)],
                         job_id=job_id)
    assert result["cancelled"] is True
    assert not output.exists()


def test_jobs_cancel_queued_and_wait_for_running(state, monkeypatch):
    cfg, store = state
    started = threading.Event()
    release = threading.Event()

    def fake_call(sock, op, payload, *, timeout=45):
        if op == "job_cancel":
            return {"ok": True, "accepted": True}
        started.set()
        release.wait(5)
        return {"ok": True, "exit_code": 0}

    monkeypatch.setattr(jobs_module, "call", fake_call)
    jobs = Jobs(cfg, store)
    jobs.pool.shutdown(wait=True)
    jobs.pool = ThreadPoolExecutor(max_workers=1)
    try:
        first = jobs.submit(actor="mcp:one", tool_id="test", mode="host",
                            operation="execute", payload={"timeout": 10})["job_id"]
        assert started.wait(3)
        second = jobs.submit(actor="mcp:one", tool_id="test", mode="host",
                             operation="execute", payload={"timeout": 10})["job_id"]
        assert jobs.cancel(second)["state"] == "cancelled"
        assert jobs.status(second)["job"]["state"] == "cancelled"
        pending = jobs.wait(first, timeout=0)
        assert pending["pending"] is True
        release.set()
        assert jobs.wait(first, timeout=4)["job"]["state"] == "completed"
        assert jobs._pending == {}
    finally:
        release.set()
        jobs.pool.shutdown(wait=True)


def test_jobs_cancel_running_acknowledgement_and_terminal_state(state, monkeypatch):
    cfg, store = state
    started = threading.Event()
    cancelled = threading.Event()

    def fake_call(sock, op, payload, *, timeout=45):
        if op == "job_cancel":
            cancelled.set()
            return {"ok": True, "accepted": True}
        started.set()
        assert cancelled.wait(5)
        return {"ok": True, "exit_code": 130, "cancelled": True}

    monkeypatch.setattr(jobs_module, "call", fake_call)
    jobs = Jobs(cfg, store)
    try:
        job_id = jobs.submit(actor="mcp:owner", tool_id="test", mode="host",
                             operation="execute", payload={"timeout": 10})["job_id"]
        assert started.wait(3)
        response = jobs.cancel(job_id)
        assert response["ok"] is True
        assert response["state"] == "cancellation_requested"
        assert jobs.wait(job_id, timeout=4)["job"]["state"] == "cancelled"
        assert jobs.cancel(job_id)["ok"] is False
    finally:
        cancelled.set()
        jobs.pool.shutdown(wait=True)
