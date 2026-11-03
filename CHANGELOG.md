# Changelog

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
