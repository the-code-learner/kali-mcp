# Kali MCP v0.1.0-beta.12 — Production Control Center

This prerelease promotes the user-reviewed beta.11 UI/UX staging to the **real, authenticated Kali MCP WebUI**, retaining its Console Dark / Light visual languages, responsive sidebar, grouped settings, and live job/audit panels. The staging's simulated interactions have been replaced with protected backend operations. This is a **UI deployment**, not a change to the public MCP protocol or any unrestricted host permission.

## What changed

**Control Center** is now the default authenticated WebUI at \`/\`. The old dashboard remains available at \`/legacy\` for diagnostics and a reversible UX migration.

Navigation: Overview, Updates, Authorized Scope, Permissions, Clients & API Tokens, CORS, File Transfers & Jobs, Audit, All Settings and Guide. The 17 beta.11 editable deployment variables remain accessible, alongside masked, installer-managed settings. Admin modifications still require a valid cookie, CSRF and superuser confirmation. Browser origins remain separate from API authorization and do not bypass OAuth or Bearer authentication.

The front end uses the same approved staging CSS for responsive/mobile and dark/light layouts but **does not synthesize data or mark fake changes as completed**. Data comes from the authenticated, no-store \`GET /api/v1/ui/snapshot\` endpoint, which aggregates the actual Native Host Agent, deployment settings, origins, jobs, audit, tokens and OAuth client inventory. The dashboard retries status calls automatically after transient service interruptions and redirects expired admin sessions to login without replaying the pending POST.

API token secrets continue to appear **once only**. File transfer permissions remain per-MCP-client; the admin dashboard does not show arbitrary MCP client file contents or pretend to offer a privileged direct upload.

## Real update monitoring across a Core restart

The beta.11 UI showed a \`core-upgrade\` job that only tracked scheduling. The beta.12 update path uses a detached **root-owned systemd upgrade supervisor**:

- \`scripts/upgrade_supervisor.py\` starts the fixed, signed/tag-checked \`install-hybrid.sh --upgrade\` workflow and watches its installer phase events.
- The supervisor writes a minimal, root-only, atomic \`/var/lib/kali-mcp/update-status.json\` (0600), independent of Core/Docker lifetimes.
- The Native Host Agent exposes only sanitized state through \`update_status_get\` on its existing protected Unix socket.
- The UI distinguishes \`scheduled\`, actual \`running\` phases, \`completed\`, \`failed\`, and \`rolled_back\`. A \`completed\` result requires an installer exit code of zero and verification of the requested deployed release, a healthy Docker Core, and an active Host Agent/socket.
- Each client polls the authenticated snapshot every three seconds, reattempting after a temporary outage without resubmitting installation requests.
- The progress bar shows **workflow phases**, not a fabricated download byte percentage.

An update that cannot safely be confirmed is marked failed, not silently shown as successful. Existing installer rollback and configuration backups remain in force; the supervisor reports their outcome instead of replacing their safety logic.

## Security and compatibility

- New frontend assets are local: \`control-center.html\`, \`control-center.css\`, \`control-center.js\`. Inline executable scripts are forbidden by a strict Content-Security-Policy.
- The snapshot never exposes stored Bearer secrets, refresh tokens, superuser passwords, private keys or root installer logs.
- Admin UI actions use the existing same-origin form endpoints, CSRF and separate superuser password checks. Batch changes are restricted to a maximum of three whitelisted non-scope settings, with CIDRs confined to their dedicated, strongly confirmed form.
- Host Root / Host Exec, OAuth 2.0 with PKCE, DNS rebinding, the Cloudflare public URL, API Bearer, browser origins, one-time OpenLink/100 MB Base64 file transfers and the unprivileged Core topology are unchanged.
- The explicit CIDR blacklist continues to protect **typed adapters**; it is **not** an OS-level network firewall for unrestricted host shell commands, even with Allow all disabled.

**Known limits:** File uploads and per-MCP-client file listings are still performed through authenticated MCP tools, not an admin file browser. Visual progress steps approximate named installer stages; no unmeasured download percentage is claimed. Offline demo data is never mixed into production.

## Validation and rollout

Tests cover authenticated Control Center shell/CSP, redacted live snapshot, batch action CSRF and key restrictions, upgrade state persistency and duplicate scheduling, detached upgrade outcome and no false rollback, JS syntax, previous UI compatibility via \`/legacy\`, plus existing OAuth, OpenLink, CORS, Raspberry-style systemd + Docker smoke and upgrade preservation.

Update through the authenticated **Updates** screen after verifying this GitHub prerelease is eligible. Confirm **Installed: v0.1.0-beta.12** and watch the real installer timeline. After an expected Core restart, the client will reconnect; do not interpret the scheduling job alone as success. For a temporary UI regression, navigate to \`https://<your-kali-mcp-host>/legacy\`; do not alter Host Root permissions as a workaround.
