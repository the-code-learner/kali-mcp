# Security architecture and operator responsibilities (beta.14)

Kali MCP is a **self-hosted control plane for authorized security assessments**, not a general-purpose production security boundary around an untrusted root-capable agent. Install on a dedicated lab appliance, keep the raw HTTP listener private and explicitly authorize each assessed network.

For current installation instructions see [HYBRID.md](HYBRID.md); for implementation/test status see [STATUS.md](STATUS.md).

## Supported vs. legacy deployment trust models

**Recommended hybrid:** the MCP/WebUI **Core** runs in a nonprivileged Docker container (UID 10001, `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem; no Docker socket or host PID namespace). A separate **root-owned native systemd Host Agent** runs on Kali, accepts commands only over `/run/kali-mcp-agent/agent.sock`, and manages explicitly approved host operations and Docker sandboxes.

**Legacy single-YAML Docker:** `kali-mcp.yml` includes a privileged Docker broker. A privileged container with Docker socket / host namespace capabilities has effectively host-root authority. This is a legacy mode for compatibility, **not the recommended mode for new installations**.

In either architecture, a compromised privileged broker/Agent or an intentionally approved root shell can control the machine. A WebUI setting is a **policy/consent gate**, *not* a complete containment boundary after compromise.

## Authenticated ingress and administrative privileges

- **MCP HTTP:** streamable transport at `/mcp`, with OAuth authorization-code + PKCE S256, resource-bound access tokens, or a separately managed API token. Unsupported/unauthenticated requests are rejected. A client credential never implicitly authorizes host/root execution.
- **Administration:** named application superuser, salted scrypt password-hash record, independent WebUI sessions and sudo-protected CLI. Sensitive administrative operations require CSRF and/or fresh superuser verification; the native Agent independently validates privilege changes against the root-owned credential record.
- **API tokens:** individually revocable with expiration and optional MCP tool allowlist. Treat any bearer/API token as a secret; rotate when exposed.
- **Browser security:** exact-origin CORS allowlisting for eligible MCP/OpenLink routes, Host/Origin checks, bounded HTTP bodies and authentication rate limits. **CORS is not an authentication or authorization mechanism.**
- **Transport:** by default the Core binds to `127.0.0.1:8787`. An HTTPS canonical origin and a hardened proxy/Tunnel are needed for remote access. Never expose plaintext `http://0.0.0.0:8787` directly to an untrusted network, regardless of login protections.
- **Cloudflare Access:** restrict management paths behind Access/MFA and make only the narrow OAuth/MCP protocol exceptions necessary for the client flow. Review [CLOUDFLARE.md](CLOUDFLARE.md), including signed OpenLink transfer paths when used.

## Host Agent and execution controls

The Unix socket is owned by root and the `kalimcp` group with mode 0660. The Docker Core mounts the socket directory read-only, which does **not** remove its ability to submit requests to the Agent. Protect membership in that group, host files and the Agent process; the socket is not exposed over TCP.

Two permission layers apply to host and root operations:

1. **Deployment ceilings:** `KALI_MCP_ALLOW_HOST_EXEC`, `KALI_MCP_ALLOW_HOST_ROOT`, `KALI_MCP_ALLOW_MCP_HOST_EXEC`, `KALI_MCP_ALLOW_MCP_ROOT`, and separate flags for package install, network changes and MCP updates.
2. **Administrator-controlled Agent toggles:** corresponding host execution/root/package/network/update approvals, initially disabled. Turning on host root requires prior host-execution approval.

The root systemd Agent remains privileged, even with all executable capabilities disabled. Native Agent settings persist in a root-owned policy file; authentication is verified on the host for privilege-changing operations.

**Sandbox mode:** Python/Bash scripts run in disposable Docker containers with network mode `none`, read-only root filesystem, dropped capabilities and CPU/memory/PID limits. A configured image and the Docker runtime remain part of the trusted computing base. Sandbox scripts are passed as Docker command arguments: **host Docker administrators can observe them during execution**. Do not put credentials directly into script bodies.

**Host mode:** permitted script/terminal execution can access the host as its configured user, or as root if approved. A privileged shell can spawn background tasks, alter networking and access local secrets; these operations are **not sandbox-equivalent**.

## Authorized network scope

The typed Kali adapter registry uses a centralized address check to apply configured CIDR rules. Explicit `KALI_MCP_DENIED_CIDRS` exclusions win over `KALI_MCP_ALLOWED_CIDRS` and `KALI_MCP_ALLOW_ALL_TARGETS=true`. Hostnames in typed calls are resolved and evaluated before the returned numeric address is passed to the adapter.

`allow_all_targets=true` is a valid **intentional, administrator-selected testing configuration** when the engagement is authorized. It should not be silently blocked or classified as a beta.14 bug.

**Critical boundary:** scope validation belongs to **typed tool adapters**, not to unrestricted host Bash, terminal commands, the kernel firewall or all possible child processes. Use host firewall/network egress policy and operational guardrails where strict target isolation is required, especially with Host Exec enabled.

## Job cancellation and lifecycle limits

Beta.14 supports `jobs_cancel` for queued and tracked running jobs, and `jobs_wait` for bounded long polling. The Agent can terminate managed host process groups or sandbox containers. Cancellation acknowledgement is **only a request/acceptance**, and the client must check the final `cancelled` state. Jobs may already have finished, the Agent may be restarting, and independently daemonized children can escape the original process group.

Interactive PTYs are managed with `terminal_close`; terminating a tracked job is not full process-tree/cgroup containment. Job output/history and audit trails have limits and cannot be treated as tamper-resistant evidence after a privileged host compromise.

## File transfer security

The per-client MCP transfer workspace resides under the unprivileged Core's persistent data directory; it is **not** arbitrary host filesystem read/write. Base64 and signed one-use OpenLink transfers share actor-scoped quota/retention limits. OpenLink URLs carry bearer-like secrets: whoever holds a still-valid unused link can consume it. Avoid recording them in external logs, screenshots or support tickets. See [MCP_FILE_TRANSFERS.md](MCP_FILE_TRANSFERS.md) for the exact quotas and edge-proxy caveats.

## Operational checklist

- Keep the Core bound to localhost behind SSH/Tailscale or a carefully configured HTTPS reverse proxy/Tunnel; use MFA for administrative access where available.
- Keep superuser, API tokens, tunnel tokens and root-owned environment files private. Do not copy them into reports or issue comments.
- Review effective Agent/Core state after capability/scope changes, which may be **scheduled** rather than already applied.
- Keep operating system, Docker, Kali packages and dependencies updated; maintain external backups and monitor disk consumption.
- Test only authorized target networks and use a dedicated appliance for elevated operations.
- Verify systemd Agent restart behavior and real Core-to-Agent IPC after updates.

**Outstanding requirements before stable production use:** independent assessment of Agent IPC authentication/isolation, wider hostile-input fuzzing, full descendant/cgroup controls, hardware-specific ARM64 and network adapter coverage, security reviews of installer/update rollback and dependencies, and real public-edge/OAuth interoperability testing.

The older beta.1/2 security model is retained as historical context in the legacy documentation; this file documents the **current recommended hybrid architecture**.
