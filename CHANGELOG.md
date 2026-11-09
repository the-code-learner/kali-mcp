# Changelog

## v0.1.0-beta.15 — release candidate: update-check recovery and optional Core DNS

- Automatically retry failed GitHub release checks (30–300 seconds), expose the actual error and retry state on the Control Center overview, and avoid false success messages.
- Add an administrator-configurable `KALI_MCP_DNS_SERVER` opt-in resolver for the Docker Core only. The default remains Docker-managed DNS; no site-specific or public resolver is forced.
- Ensure all managed Core recreation paths keep the same DNS overlay; validate the applied Docker host DNS configuration and retain the setting on upgrades.
- Cover DNS address validation, SSH wizard persistence and Compose rendering in regression tests.
- A beta.15 installer also preserves a single explicit existing Core DNS override from beta.14, without altering host DNS, firewall or other containers. The CLI wrapper is made accessible when Kali sudo's PATH excludes `/usr/local/bin`.
- The beta.15 source is **not part of the immutable v0.1.0-beta.14 release**. Publication of the beta.15 tag/release assets is a separate release step. See [candidate notes](docs/BETA15_RELEASE_NOTES.md).


For the current architecture and verified implementation status, see the [documentation index](docs/README.md) and [status matrix](docs/STATUS.md). Older entries below are historical snapshots and may describe features later implemented.

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
