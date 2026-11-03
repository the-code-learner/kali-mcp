"""Prevent HTML injection in administrative job results."""
from __future__ import annotations

from kali_mcp.reports import report_html


def test_job_report_escapes_untrusted_tool_output():
    markup = report_html({
        "id": "job-123", "state": "completed", "tool_id": "nmap",
        "actor": "mcp:client",
        "at": "2026-11-03T00:00:00Z", "finished_at": "2026-11-03T00:00:01Z",
        "exit_code": 0, "result": {"stdout": '<script>alert("xss")</script>',
                                   "stderr": '<img src=x onerror=alert(1)>'}
    }, [{"at":"2026-11-03", "kind":"state", "data":"completed"}])
    assert "<script>alert" not in markup
    assert "&lt;script&gt;" in markup
    assert "&lt;img" in markup
    assert "Job timeline" in markup
    assert "job-123" in markup
