# Kali MCP 0.1.0-beta.5 (candidate — not yet released)

## Scope and compatibility

This is the next hybrid beta candidate based on `0.1.0-beta.4`.
It retains the systemd Host Agent, non-privileged Docker MCP Core, existing
OAuth 2.0 Authorization Code + PKCE S256 (including discovery, registration,
access/refresh and rotation), and the **single** `/mcp` endpoint.

### Authentication

- Named, auditable API credentials: one-time display, random 384-bit secrets,
  SHA-256 digests in SQLite, 1–90-day expiry, immediate revocation,
  last-used metadata and optional per-tool allowlists.
- New WebUI **MCP Clients → API Tokens**, with superuser reauthentication/CSRF.
- Local sudo-authenticated CLI `api-tokens`, `api-token-create`,
  `api-token-revoke`, `api-token-rotate`. Rotation revokes the previous\n  key in the same SQLite transaction and displays the replacement just once.\n  Never place a secret in command arguments.
- Identity audit separation: `mcp:oauth:<client_id>` and
  `mcp:api:<token_id>`. Keys are invalidated when the issuing superuser
  credential fingerprint changes.
- Browser direct: `Authorization: Bearer <API_TOKEN>`, or the optional
  `X-Kali-MCP-API-Key`. Keep OAuth clients on the existing grants.

### HTTP protection and browser support

- MCP-specific exact-origin allowlist with `KALI_MCP_BROWSER_ORIGINS`.
- `OPTIONS /mcp` preflight, CORS on MCP responses/errors and SSE, no CORS
  for admin/session routes. Duplicate or mixed authentication headers rejected.
- Browser-safe login Referrer-Policy with guarded `Origin: null` handling
  when same-origin Referer and Fetch Metadata both agree.
- MCP request ingress rate limiting plus existing Admin/OAuth throttles.

### Hybrid installer reliability

- `--resume`, `--repair`, `--reconfigure`, `--upgrade`; partial config
  detection and a last-written `config.ready` marker.
- Atomic 0600 environment file replacements with fsync and safe retry;
  superuser hash preserved on resume; no secrets in installer phase logs.
- Exclusive flock, durable phase diagnostics under
  `/var/log/kali-mcp/install.log`, release-directory traversal
  normalization, checks as Core uid 10001 and Host Agent execution user.
- Online SQLite backup under `/var/lib/kali-mcp/backups/` before upgrade.
  Rollback swaps binaries/release symlink; **it does not downgrade database
  schema**. The additive `api_tokens` table does not replace OAuth tables.
- Cloudflared APT failure is nonfatal: reuse an existing binary or install
  an appropriately verified official package manually; no unverified binary
  downloads by the wizard. Installer prints absolute sudo CLI paths.

### How to test on Kali ARM64

Run the installer from a pinned candidate commit/archive and then:

```bash
sudo /usr/local/bin/kali-mcp status
sudo /usr/local/bin/kali-mcp api-tokens
sudo /usr/local/bin/kali-mcp api-token-create "llama.cpp-WebUI" --days 30
```

Set the browser origin in `/etc/kali-mcp/stack.env` (or run the wizard):
```ini
KALI_MCP_BROWSER_ORIGINS=https://llm.davidecasalin.it
```
Restart the Core using the systemd hybrid installer or normal Docker Compose
procedure; the `/mcp` URL remains unchanged.

### Validation gates before public tag

GitHub Actions CI + hybrid/legacy smoke must pass. Additionally test real
Chrome/Firefox HTTPS login, `OPTIONS` through Cloudflare, direct llama.cpp,
llama.cpp `/cors-proxy` behind Nginx Basic Auth, ARM64 clean install and
interruption during each wizard phase. The separately observed installer
crash B05 has no captured original traceback and cannot be root-caused yet.

Host/root operations, network modification, package installs and MCP updates
are still protected by the original host-owned controls and deployment ceilings.
