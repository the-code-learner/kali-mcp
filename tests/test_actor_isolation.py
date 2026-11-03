"""Client isolation regression tests for stored jobs and audit rows."""
from __future__ import annotations

from kali_mcp.store import Store


def test_job_and_audit_views_are_actor_scoped(tmp_path):
    store = Store(tmp_path / "state.db")
    a = store.new_job("mcp:alpha", "nmap", "host", {"target": "127.0.0.1"})
    b = store.new_job("mcp:beta", "dig", "host", {"target": "127.0.0.1"})
    store.job_state(a, "completed", result={"ok": True, "stdout": "alpha-private"})
    store.job_state(b, "completed", result={"ok": True, "stdout": "beta-private"})
    assert [j["id"] for j in store.list_jobs(actor="mcp:alpha")] == [a]
    assert [j["id"] for j in store.list_jobs(actor="mcp:beta")] == [b]
    assert len(store.list_jobs()) == 2
    store.audit("mcp:alpha", "script.run", "allow", "private-alpha")
    store.audit("mcp:beta", "script.run", "allow", "private-beta")
    assert [x["detail"] for x in store.list_audit(actor="mcp:alpha")] == ["private-alpha"]
    assert [x["detail"] for x in store.list_audit(actor="mcp:beta")] == ["private-beta"]
    store.close()


def test_long_tool_output_preserves_valid_json(tmp_path):
    store = Store(tmp_path / "large.db")
    job_id = store.new_job("mcp:alpha", "nmap", "host", {"argv": ["-x" * 5000]})
    store.job_state(job_id, "completed", result={"ok": True,
        "stdout": "A" * 100000, "stderr": "B" * 100000})
    loaded = store.get_job(job_id)
    assert loaded["args"]["truncated"] is True
    assert loaded["result"]["truncated"] is True
    assert len(loaded["result"]["stdout"]) == 24000
    assert len(loaded["result"]["stderr"]) == 24000
    store.close()
