# Development status: v0.1.0-beta.1

This is an installable **early beta for dedicated Kali lab systems**,
not a production-hardened remote access product.

| Component | Status |
| --- | --- |
| Postmaster-compatible Apache-2.0 LICENSE/NOTICE | Exact LICENSE SHA matched; attribution preserved |
| Single-YAML bootstrap, persistent source and virtualenvs | Docker Compose AMD64 live startup PASSED |
| Non-root Core / privileged broker split | Docker smoke PASSED; Kali ARM64 pending |
| OAuth discovery, registration, browser consent, PKCE, tools/list | Full HTTP integration PASSED on AMD64 |
| Unauthorized MCP request rejected | HTTP 401 PASSED |
| WebUI login, toggle, disclaimer, CSRF | Integration tests PASSED |
| SQLite jobs and client isolation | Unit/integration tests PASSED |
| Python sandbox (network none, read-only rootfs) | Real Docker execution PASSED on AMD64 |
| Bash sandbox | Implemented but not yet tested live |
| Stable/beta release selection and periodic checks | Unit tests PASSED; metadata only |
| Install/rollback of a newer app release | Not implemented in beta |
| Tool registry, installer recipes, target scopes | Initial curated catalog; more adapters pending |
| Kali host command/PTY/root execution | Experimental, host hardware testing required |
| NetworkManager Wi-Fi scan/status | Prototype; real Pi validation pending |
| Wi-Fi AP, Ethernet gateway/NAT and Nexmon control | Not implemented |
| Host cgroups, reliable cancellation, PCAP artifacts | Not implemented |
| Cloudflare Tunnel/Access interoperability | Policy documented; live zone test pending |

## Test history

- GitHub Actions unit tests, compile checks and Docker Compose config parsing.
- Linux AMD64 hosted Docker smoke with source-cache bootstrap and both containers healthy.
- Full OAuth client registration → administrator login/consent → PKCE token issuance →
  authenticated MCP tools/list over localhost HTTP.
- Authorized Python sandbox via Unix broker with observed stdout and exit code.

## Security caveat

The requested privileged broker has host-level power even when its application
toggle is off. Use a standalone lab device, keep the host/root execution
ceilings disabled by default, and do not publish the raw container port.

For installation and upgrade limitations see [BETA.md](BETA.md).
