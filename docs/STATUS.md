# Development status — Kali MCP v0.1.0-beta.14

**Current prerelease:** [v0.1.0-beta.14](https://github.com/the-code-learner/kali-mcp/releases/tag/v0.1.0-beta.14), native systemd Host Agent plus nonprivileged Docker Core. This is a **beta for dedicated Kali security-assessment appliances**, not a production-hardened remote-access product.

Status terms are deliberately distinct:
- **Implemented:** the relevant code/API exists; not a guarantee that every host/environment was tested.
- **CI verified:** automated integration or smoke coverage on GitHub-hosted **Linux AMD64**.
- **Field-observed:** a specific real Raspberry Pi/Kali test informed or verified a behavior; not universal ARM64 certification.
- **Partial / not implemented:** a feature has documented functional or containment limits, or no complete supported implementation.

## Current feature matrix

| Area | Beta.14 status | Evidence / limitation |
| --- | --- | --- |
| Hybrid installation | **Implemented; CI verified** | Native systemd Agent, nonprivileged Docker Core, SSH wizard, health checks, installer re-entry |
| Local trust boundary | **Implemented; CI verified** | Root systemd Agent behind restricted Unix socket; Core UID 10001, no Docker socket, all capabilities dropped |
| Agent IPC restart recovery | **Implemented; CI verified; field-observed issue** | Preserve `/run/kali-mcp-agent` directory across Agent restarts; CI restarts Agent twice while Core remains running |
| Application superuser | **Implemented; CI verified** | Named superuser, salted scrypt record, WebUI + sudo CLI login, reauthentication for Agent changes |
| MCP / OAuth | **Implemented; CI verified** | Protected streamable HTTP `/mcp`, PKCE S256, registration, consent, token rotation/revocation, unauthorized requests rejected |
| MCP API tokens and browser CORS | **Implemented; CI verified** | Dedicated revocable tokens, optional tool allowlist, exact configured browser origins, CORS/Host verification |
| Persistent jobs / audit | **Implemented; CI verified** | Actor-scoped SQLite history, bounded output, job reporting, per-client isolation |
| Job lifecycle | **Implemented; CI verified** | `jobs_get`, `jobs_wait` (0–30 s), `jobs_cancel` for queued/tracked running jobs; cancellation is best-effort, not full cgroup containment |
| Docker script sandbox | **Implemented; CI verified** | Python/Bash, network disabled, read-only root, limited CPU/memory/PIDs; Agent manages Docker execution |
| Host scripts / terminals | **Implemented, gated; partial validation** | Deployment + Agent approvals required; PTY ownership/quota/expiry; powerful host/root execution is not safe process isolation |
| Kali tool adapters | **Implemented, limited catalog** | Curated typed tools and package recipes; full capability of every installed Kali tool is not exposed as typed actions |
| Wi-Fi / NetworkManager | **Basic status and scan implemented** | `network_manage(status|scan)`, plus `wifi_scan` alias; adapter/driver behavior depends on host and privileges |
| Target scope | **Implemented for typed adapters** | Deny-first CIDR allowlist/denylist, explicit `allow_all_targets`; shell execution is not universally filtered by CIDR |
| Control Center configuration | **Implemented; CI verified** | Superuser-authenticated deployment inventory, async changes, effective Core/Agent state and rollback/unverified feedback |
| File transfers | **Implemented; CI verified** | Per-client workspace, Base64 and one-use signed OpenLink; 100 MB/file limit; no arbitrary host-file access |
| Updates | **Implemented; CI verified** | Stable/beta release lookup, manually approved install, source staging, SQLite backup, Agent/Core checks and limited source rollback |
| Cloudflare / Tailscale assistants | **Implemented; environment-specific verification required** | CLI setup helpers; public HTTPS/Access policy and private Tailscale Serve must be validated per installation |
| Wi-Fi AP / Nexmon / general monitor mode | **Not complete** | No supported end-to-end AP or Nexmon workflow; wireless adapter limitations remain |
| Ethernet gateway / NAT / NetworkManager checkpoint rollback | **Not complete** | Avoid relying on this beta for rollback-safe network reconfiguration |
| Full cgroups / descendant containment | **Not implemented** | Job cancellation targets managed process groups/containers; independently daemonized descendants may survive |
| Rich PCAP visualization | **Not complete** | Generic tools can process available files, but advanced PCAP presentation is not a complete supported feature |

## Validation actually performed

**GitHub Actions (Linux AMD64):**
- Python unit/integration suite, compilation, JavaScript syntax checks, Compose rendering.
- Docker appliance smoke and real hybrid systemd + Docker installer smoke.
- Root-owned Agent policy, nonprivileged Core, socket permissions and working Core-to-Agent IPC.
- Agent socket survival after **two systemd restarts** while the Core continues running.
- WebUI/Agent deployment changes, browser-origin CORS, OAuth/PKCE, API-token flows, MCP transport, and idempotent upgrade.
- Beta.14 job regression tests: queued and running cancellation, process-group kill, pre-start cancellation, job wait, terminal-state immutability and deny-first scope.

**Real Raspberry Pi/Kali observations:** previous beta reports captured Native Agent ↔ Core socket recovery and an extended authorized Wi-Fi/network assessment. Those sessions helped prioritize the beta.13/14 changes; they are **not a claim of completed ARM64 certification** or of a live beta.14 acceptance test.

**Not established by CI alone:** real Cloudflare Access zone behavior, externally hosted MCP client interoperability for every client, hardware-specific wireless capture/monitor mode, production-level root containment, and safe gateway/NAT operations.

## Residual limitations and release policy

A permissive target policy is an explicit administrator choice for authorized testing, **not an automatic priority-1 defect**. Adapter CIDR exclusions do not act as a host firewall when arbitrary host execution is allowed.

Host Agent compromise, root commands, untrusted MCP clients, and escaped child processes remain meaningful risks. Keep the raw HTTP listener private and place HTTPS, authorization, auditing and host/network controls at the appropriate boundaries.

Before considering a stable release, independently validate the real ARM64 device, network/driver behavior, Cloudflare/OAuth integration, security of Agent IPC, update/rollback failures, and dependency vulnerabilities. See [TESTING.md](TESTING.md), [SECURITY.md](SECURITY.md) and [HYBRID.md](HYBRID.md).

Historical beta.1 implementation claims are preserved in their original release documentation; this file represents the **current** status.
