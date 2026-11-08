# Kali MCP v0.1.0-beta.11 — WebUI Deployment & Security Settings

Designed after live Qwen 3.8 Flash Next testing against a Raspberry Pi Kali MCP beta.10. This prerelease closes the gap where the WebUI exposed permission toggles but target scope and most deployment variables still required SSH editing.

## New: Deployment & Security settings

The authenticated dashboard now links to **Deployment & Security**. It shows every known \`KALI_MCP_*\` variable from the hybrid \`stack.env\` and \`agent.env\` configuration. Sensitive values are **masked**; system identity and socket paths are identified as installer-managed rather than exposed as arbitrary editable strings.

Editable, strictly validated settings include the authorized target policy, deployment privilege ceilings, API Bearer authentication flag, release channel, update interval, job timeout, public origin, listening port and bind address. The existing dedicated Browser Origins/CORS panel continues to manage its own list.

Edits require a valid administrator session and CSRF token, plus a **second password verification by the root Native Host Agent**. A fixed detached systemd worker updates only approved keys in both protected environment files (0600), starts a controlled Core recreation and Agent restart, verifies runtime values and service health, and attempts rollback if activation fails. The dashboard distinguishes **scheduled** from the final deployment state. No root filesystem or Docker socket is mounted into the Core.

**Internal variables** (broker socket, agent identity, superuser credential file, deployment topology) remain visible with descriptions but cannot be arbitrarily edited; secrets may only be rotated through their dedicated protected workflows. This is intentional hardening, not missing fields. Edits to public URL, bind or port can interrupt remote access; use recovery over SSH if a tunnel is externally misconfigured.

## New: Authorized Scope with Allow all / Blacklist

The target configuration is now three explicit settings:

- \`KALI_MCP_ALLOWED_CIDRS\` — comma-separated IPs or CIDRs (default: \`127.0.0.1/32\`).
- \`KALI_MCP_DENIED_CIDRS\` — explicit always-excluded IPv4/IPv6 CIDRs or IPs (default empty).
- \`KALI_MCP_ALLOW_ALL_TARGETS\` — \`false\` by default. When set to \`true\`, all valid IP targets are eligible **except** those matched by the blacklist.

**Evaluation order:** any excluded address => deny; otherwise, Allow all => permit; otherwise, IP must match an allowed CIDR. Every address returned by DNS for a hostname must pass both checks. A blacklisted subnet wins even if covered by a broader allowed CIDR. All changes are audited, and enabling Allow all requires at least one explicit exclusion **and** typing \`ALLOW ALL\` in the protected WebUI form.

For the network observed in the Qwen test, an example configuration for an engagement that permits every other target is:

\`\`\`ini
KALI_MCP_ALLOW_ALL_TARGETS=true
KALI_MCP_DENIED_CIDRS=192.168.137.0/24
KALI_MCP_ALLOWED_CIDRS=127.0.0.1/32
\`\`\`

This is only an example: use Allow all only if the authorized engagement really covers all other addresses. A safer choice is to keep Allow all disabled and list only the authorized test networks, plus exclusions.

Qwen can read the new scope using \`capabilities_get\`, but **cannot update it**. \`tools_execute\` typed adapters apply the deny-first policy.

**Important remaining boundary:** unrestricted Host Exec and interactive terminals are separate privileged execution capabilities. Arbitrary shell commands are not network-filtered by the typed adapter scope. Therefore, a blacklist alone does **not** guarantee packets to excluded networks cannot originate from a deliberately enabled generic host shell. If strict exclusion is required, keep generic host execution disabled while using typed adapters, until an OS-level egress enforcement mechanism is provided. The WebUI warns about this distinction explicitly. This build does not falsely claim host-wide network enforcement.

## Tests

Unit tests cover default loopback-only policy, allowlist, Allow all with excluded subnet, mixed DNS answers, malformed CIDRs, 64-entry limit and secret redaction.

Integration tests cover CSRF, independent superuser confirmation and Allow all acknowledgment, rejection of unknown/internal settings, atomic writes preserving secrets and attempted rollback after a simulated unhealthy restart.

Hybrid systemd + Docker smoke exercises a **real** authenticated scope update to both environment files, Core recreation, Agent restart, and subsequent OAuth/API token operations. CI and release gating must pass before publication.

Upgrades are installed using the existing WebUI Updates panel; verify the installed version in the dashboard once restarted. No automatic adjustment of your existing authorized scope occurs during the upgrade.
