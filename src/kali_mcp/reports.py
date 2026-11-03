"""Admin-only human-readable job report.

All job arguments and tool stdout/stderr are escaped, and downloads remain
subject to the administrator authentication guard in the HTTP application.
"""
from __future__ import annotations

from html import escape


def report_html(job: dict, events: list[dict]) -> str:
    status = escape(str(job.get("state") or "unknown"))
    item = escape(str(job.get("tool_id") or "unknown"))
    actor = escape(str(job.get("actor") or "unknown"))
    jid = escape(str(job.get("id") or ""))
    started = escape(str(job.get("at") or ""))
    finished = escape(str(job.get("finished_at") or "—"))
    result = job.get("result") or {}
    stdout = escape(str(result.get("stdout") or ""))
    stderr = escape(str(result.get("stderr") or ""))
    exit_code = escape(str(job.get("exit_code") if job.get("exit_code") is not None else "—"))
    failure = escape(str(result.get("error") or ""))
    details = "".join(f"<li><time>{escape(str(e.get('at') or ''))}</time>"
                      f" {escape(str(e.get('kind') or ''))}: {escape(str(e.get('data') or ''))}</li>"
                      for e in events)
    if not details:
        details = "<li>No execution events recorded</li>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>{item} · Kali MCP Report</title>
<link rel="stylesheet" href="/static/app.css"></head><body>
<header><h1>Kali MCP <small>Job report</small></h1>
<a href="/">Dashboard</a></header>
<main class="report">
<section><h2>{item}</h2>
<p><strong>Status:</strong> {status} &nbsp; <strong>Exit:</strong> {exit_code}</p>
<p class="muted">ID: <code>{jid}</code></p>
<p class="muted">Client: <code>{actor}</code></p>
<p class="muted">Started: {started} · Finished: {finished}</p></section>
<section><h2>Standard output</h2>
<pre class="job-output">{stdout or '(empty)'}</pre></section>
<section><h2>Standard error</h2>
<pre class="job-output">{stderr or '(empty)'}</pre>
{f'<p class="warning">{failure}</p>' if failure else ''}</section>
<section><h2>Job timeline</h2><ol>{details}</ol></section>
</main></body></html>"""
