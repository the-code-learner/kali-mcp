# Developer and hardware validation — Kali MCP beta.14

This checklist is for the **hybrid systemd Host Agent + unprivileged Docker Core** installation. It separates automated Linux AMD64 coverage from the tests still needed on physical ARM64 devices. Work only within an authorized lab and do not enable privileged operations merely to satisfy a smoke check.

## Local source validation (Python 3.12+)

Run from a clone of the repository:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt pytest PyYAML
python -m compileall -q src scripts tests
pytest -q
bash -n scripts/install-hybrid.sh
```

If Node.js is installed:

```bash
node --check src/kali_mcp/static/control-center.js
```

If Docker Compose is installed:

```bash
KALI_MCP_AGENT_GID=1000 docker compose -f kali-mcp-hybrid.yml config --quiet
```

To focus on beta.14 job cancellation and scope regression:

```bash
pytest -q tests/test_beta14_jobs.py
```

These tests cover pre-start and active process-group cancellation, queued/running jobs, long waits, immutable final job states and deny-first CIDR evaluation. They are not a substitute for live host-root or kernel-level containment testing.

## GitHub CI gates

| Workflow | What it verifies |
| --- | --- |
| [CI](../.github/workflows/ci.yml) | Python dependency installation, Compose syntax, compileall, pytest and Control Center JavaScript syntax |
| [Beta appliance Docker smoke](../.github/workflows/smoke.yml) | Legacy single-YAML Docker boot/HTTP verification, for compatibility |
| [Hybrid systemd + Docker smoke](../.github/workflows/hybrid-smoke.yml) | Real native Agent + nonprivileged Core, socket permissions, Core↔Agent IPC, sandbox execution, browser origins, deployment settings and OAuth |
| [Validated beta.14 release gate](../.github/workflows/release-beta14.yml) | Runs hybrid release-specific validation, preserves configuration across an idempotent upgrade and publishes immutable prerelease assets only after success |

The hybrid workflow restarts the **Agent twice without recreating the Core** to catch stale directory bind mounts. It also exercises authenticated OAuth/API-token flows, CORS and live MCP `tools/list`. CI runners are **Linux AMD64**; they do not certify every Raspberry Pi image, Wi-Fi chipset or actual Cloudflare Access zone.

## Physical Raspberry Pi acceptance checklist

Use a dedicated Kali Pi, a network you administer, and the [versioned installer](HYBRID.md).

1. **Version and services.** Run `sudo kali-mcp status`; confirm the installed version, systemd Agent, Docker Core and expected URL. Verify `sudo systemctl is-active kali-mcp-agent.service` reports `active`.
2. **Core health.** Run `sudo docker inspect --format '{{.State.Health.Status}}' kali-mcp-core` and `curl -fsS http://127.0.0.1:8787/healthz` from the host. If you intentionally use a non-default bind or port, adjust the test accordingly.
3. **Real IPC.** Use the following read-only probe from inside the running unprivileged Core:
   ```bash
   sudo docker exec kali-mcp-core /opt/venv/bin/python -c \
     "import sys; sys.path.insert(0, '/opt/kali-mcp/current/src'); from kali_mcp.broker_client import call; print(call('/run/kali-mcp-agent/agent.sock', 'ping', timeout=5))"
   ```
   The broker identifier should be `systemd-host-agent`.
4. **Socket restart regression.** In an explicitly scheduled maintenance window, restart `kali-mcp-agent.service`, then repeat the IPC ping **without** recreating the Core. Do not interrupt an active assessment; restarting the Agent can affect running tools.
5. **WebUI and ingress.** Check authenticated WebUI login, CSRF enforcement and that an unauthenticated `/mcp` request does **not** expose MCP tools. Verify the actual browser origin matches the configured canonical `KALI_MCP_PUBLIC_URL`.
6. **Authorized Scope.** Inspect **Control Center → Authorized Scope**. If you configured a denied CIDR (for example, an out-of-scope tether or management network), ensure it remains saved and appears in `capabilities_get` after application. A preview is not equivalent to a verified running policy.
7. **Read-only Wi-Fi.** Try `network_manage(action="status")` and `network_manage(action="scan")` on your actual interface, understanding that driver/NetworkManager support varies. A scan is an **active** operation, not a passive monitor-mode capture.
8. **Jobs (non-destructive).** Submit a bounded disposable sandbox script, then try `jobs_wait`. In a controlled test, cancel a deliberately sleeping sandbox process with `jobs_cancel` and verify the final job state through `jobs_wait` or `jobs_get`. A cancellation acknowledgement alone is insufficient.
9. **Scope/permission boundaries.** Confirm host/root execution remains disabled unless the operator explicitly enabled it. Do **not** enable host-root access solely for smoke tests.
10. **Update/rollback.** Only in a test window, verify update status, a safe upgrade and post-upgrade reauthentication/IPC. Preserve backups and review `/var/log/kali-mcp/install.log` if the installer fails.

For Cloudflare/hosted clients, also verify Access path policies, valid Bearer/API-token authenticated `initialize` and `tools/list`, actual Origin and Host handling, and OpenLink upload/download if enabled. A successful CORS preflight alone does not establish working OAuth/MCP.

## Reporting evidence and known limitations

Record exact release tag, hardware model, Kali/kernel version, selected interface, sanitized test parameters, timestamps, state transitions and the **observed** error/result. Avoid uploading raw passwords, OAuth tokens, OpenLink URLs, superuser records or root-owned environment files.

Use explicit confidence labels: observation vs. hypothesis, reachable service vs. authentication bypass, passive observation vs. active probing. Network scope is administrator-configurable, including intentional allow-all testing; it is not automatically a product defect.

Current missing guarantees include universal ARM64/driver compatibility, full descendant/cgroup process containment, Wi-Fi AP/Nexmon, rollback-safe gateway/NAT and complete end-to-end public edge configurations. See [STATUS.md](STATUS.md), [SECURITY.md](SECURITY.md) and [BETA14_RELEASE_NOTES.md](BETA14_RELEASE_NOTES.md).

Do not publish a **stable** release solely because CI is green. Require documented hardware, protocol, security and failure-recovery acceptance.
