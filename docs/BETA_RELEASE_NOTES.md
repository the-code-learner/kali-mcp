# Kali MCP v0.1.0-beta.1

**First installable prerelease for isolated Kali Linux lab testing.**

## Included

- Postmaster-style, single-file Compose bootstrap with versioned GitHub source cache and persistent Python environments.
- `stable` and `beta` release channels, with periodic metadata checks (no automatic upgrades).
- Non-root MCP + WebUI service, private Unix-socket broker, privileged host mode disabled by default.
- OAuth authorization-code + PKCE S256, client registration, Bearer enforcement, browser admin consent and hashed, rotatable tokens.
- WebUI admin login, capability toggles, root disclaimer, live job status, human-readable job reports and bounded audit history.
- Initial Kali adapter catalog and tightly scoped typed actions; basic read-only network status/scan.
- Experimental Python/Bash Docker sandbox, resource limits and no sandbox network access.
- CI coverage for authorization policies, OAuth exchange, release selection, source extraction, Compose parsing and integration tests.

## Installation

Use the YAML pinned to this release:

```sh
curl -fsSL https://raw.githubusercontent.com/the-code-learner/kali-mcp/v0.1.0-beta.1/kali-mcp.yml -o kali-mcp.yml
```

Edit `KALI_MCP_ADMIN_PASSWORD` (unique 16+ characters) and, for remote OAuth, `KALI_MCP_PUBLIC_URL` in **Core and Broker**, then:

```sh
docker compose -f kali-mcp.yml up -d --wait
```

The default browser URL is `http://127.0.0.1:8787` on the Pi itself. Other machines can use SSH local port forwarding; for Cloudflare Tunnel point the origin to `http://127.0.0.1:8787` and follow [OAuth/Access policy documentation](https://github.com/the-code-learner/kali-mcp/blob/v0.1.0-beta.1/docs/CLOUDFLARE.md).

Complete instructions and caveats: [docs/BETA.md](https://github.com/the-code-learner/kali-mcp/blob/v0.1.0-beta.1/docs/BETA.md).

## Known limits

**Experimental; not production hardened.** Root/host commands are exposed only after explicit YAML and admin toggles, but the privileged Docker broker itself already has effective host-level authority. Hardware-specific networking (Wi-Fi AP, Ethernet gateway/NAT, Nexmon), safe checkpoint rollback, full module installation and process cancellation are not complete. The periodic update scan does **not** install releases; manual in-app install/rollback is not implemented in beta. OAuth/Cloudflare compatibility needs testing on the actual Cloudflare zone and MCP client. This initial beta should only run on a dedicated test Pi/Kali host.

Do not enable host root, expose the MCP publicly or scan third-party networks before completing the relevant authorization and security checks.
