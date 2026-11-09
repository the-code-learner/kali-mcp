# Kali MCP v0.1.0-beta.14 — cancellable assessments and lower-chatter job orchestration

This prerelease follows the beta.13 Raspberry Pi 5 assessment: a **single authorized prompt** completed a multi-hour network and Wi-Fi inventory, with many tool calls, a timed-out long port sweep, and a failed attempt to cancel a running job. It preserves the beta.13 Native Host Agent/socket architecture.

## Changes

- **Real `jobs_cancel`:** cancel queued jobs immediately; request termination of tracked running host processes and Docker sandbox containers through the existing private Unix socket. Each job has a random ID; no new TCP listener, privileged Core capability, or unauthenticated MCP endpoint is introduced.
- **Race-aware process lifecycle:** job IDs travel from Core to Agent, subprocesses run in their existing independent process groups, and cancellation can arrive before the Agent starts a process. A completed job remains terminal even if a late response arrives. Running-job cancellation is acknowledged first; use `jobs_wait` or `jobs_get` to confirm `cancelled`.
- **`jobs_wait(job_id, timeout=15)`:** bounded long poll (0–30 seconds), with the same per-client ownership checks as `jobs_get`. Replaces many rapid `jobs_get` calls during lengthy assessments.
- **Friendlier tool search:** word/synonym matching for ordinary requests such as `wifi wireless scan` and `network discovery scan`, without adding unreviewed executables or expanding permissions.
- **`network_manage(action="wifi_scan")`:** read-only alias of the existing `scan` action.
- **Assessment quality guidance:** distinguish passive RF observations from active network probes; label exploitability hypotheses clearly rather than claiming every reachable service is compromised.
- **Job status:** timed-out broker jobs are now represented as `timed_out` rather than generic `failed`.

## Explicitly unchanged: scope and privilege choices

The permissive target configuration used in the authorized lab (`allow_all_targets=true`) is **not classified as a beta.14 defect and is not tightened automatically**. The administrator's `allowed_target_cidrs`, `denied_target_cidrs`, and `allow_all_targets` persist across upgrades. The deny-first target policy continues to apply to typed adapters. As already documented in beta.13, arbitrary host shell commands are not universally restricted by typed-adapter CIDRs. Choose the scope appropriate to each authorized engagement.

Host/root/deployment ceilings and administrator approval remain unchanged. No forced changes are made to Wi-Fi, firewall, interfaces, NAT or the premises network.

## Limitations and operational notes

- Cancellation targets jobs launched through the registered job engine. Commands manually started within a persistent interactive PTY are still managed by `terminal_close`, not `jobs_cancel`.
- Cancellation is best effort for processes that already exited, during Agent restart, or while Docker is unavailable. `jobs_cancel` confirms acceptance, **not** terminal completion, until `jobs_wait` shows `cancelled`.
- A subprocess may have independently daemonized into a new session; process-group cancellation is not a full host-wide process containment guarantee.
- The 0–30-second `jobs_wait` limit reduces model/tool round trips but does not itself guarantee lower model-token output on every client.
- No scope change is made during upgrade; `192.168.137.0/24` remains excluded only on deployments that explicitly configured it.

## Validation and upgrade

The beta.14 release workflow gates publication on `pytest`, compilation, JavaScript validation, Compose validation, a real hybrid systemd/Docker install, OAuth/API/CORS smoke checks, two Agent socket restarts, and idempotent upgrade. New regression tests cover host process-group cancellation, pre-start cancellation, queued/running jobs, long polling, immutable final states, discovery and deny-first scope.

Upgrade through **Updates → Check now**, selecting the newly published `v0.1.0-beta.14` release when it becomes available. Check **Agent online**, **Core online**, and the configured scope after restart. A green CI result does not replace verification on the physical Raspberry Pi.
