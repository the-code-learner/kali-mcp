# Changelog

For the current architecture and verified implementation status, see the [beta.14 documentation index](docs/README.md) and [status matrix](docs/STATUS.md). Older entries below are historical snapshots and may describe features later implemented.

## v0.1.0-beta.14 — cancellable jobs and assessment efficiency

- Add `jobs_wait` bounded long polling, reducing repeated `jobs_get` during long assessments.
- Implement `jobs_cancel` for queued and broker-tracked running jobs, including non-root host process groups and sandbox containers; preserve terminal state and audit cancellation.
- Improve plain-language tool discovery and add the `wifi_scan` read-only alias.
- Encourage evidence-graded reporting: passive RF findings are distinct from active scans.
- Keep permissive assessment target configuration under explicit administrator control; retain deny-first CIDR behavior and privilege gates.
- Add lifecycle/scope regression tests and a gated hybrid beta.14 release workflow.

See [beta.14 release notes](docs/BETA14_RELEASE_NOTES.md) for limits and validation details.


## Beta.3–beta.13 historical milestones

Detailed records are retained in [beta.3 hybrid notes](docs/HYBRID_BETA_RELEASE_NOTES.md), [beta.4 security notes](docs/SECURITY_BETA_RELEASE_NOTES.md), and [beta.5–13 release notes](docs/README.md#historical-documents-preserved-as-release-snapshots). These earlier notes are not current installation or security guidance.

## v0.1.0-beta.2 — Portainer single-YAML installation

- Replaced manual download/edit installation instructions with Portainer Git repository or Web Editor deployment.
- Compose YAML uses Stack environment variables for administrator password, public URL, stable/beta channel and permission ceilings.
- Inline GitHub-release bootstrap remains self-contained; no separate setup script on the Raspberry Pi.


## v0.1.0-beta.1 — first installable beta

- Adopted exactly the Apache-2.0 LICENSE file from Postmaster MCP; retained its original attribution in NOTICE.
- Added a single-YAML Docker Compose bootstrap with a staged, validated GitHub archive cache, persistent Python virtual environments and SQLite application state.
- Separated non-root MCP/WebUI core from an explicitly privileged host broker over a Unix-domain socket; privileged capabilities are disabled by default.
- Added OAuth authorization-code/PKCE S256, dynamic public-client registration, audience-bound access tokens, rotation of refresh tokens, and password-protected WebUI consent.
- Added dashboard login, CSRF-protected administrator toggles with root disclaimer, recent job and audit views, SSE job events and periodic release metadata checks.
- Added an initial bounded tool registry, package-install recipes, Python/Bash Docker sandbox prototype, host execution prototype, and a target CIDR policy.
- Added stable/beta SemVer release selection; actual manual installation/rollback is not implemented yet.
- Added OAuth-client attribution and per-client isolation for persistent MCP job/audit reads.
- Added continuous integration tests, compilation checks, actual Docker Compose YAML parsing, full AMD64 Docker startup, HTTP OAuth client flow and sandbox Python smoke tests.
- Added Cloudflare Access/OAuth routing guide and security validation checklist.

**Still missing before a stable production release:** actual Kali ARM64 and Docker integration testing, crash-safe manual updates/rollback, complete safe PTY and process lifetime handling, NetworkManager checkpoints, Wi-Fi AP/Ethernet/Nexmon implementations, complete plugin catalogue and output artifact rendering. No production-ready release has been published.
