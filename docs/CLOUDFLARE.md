# Cloudflare Tunnel + Access + OAuth

Single public origin: https://kali.example.com
MCP URL: https://kali.example.com/mcp

## Access policy
Use a default-deny Access application on the entire hostname. Create narrowly
scoped Bypass rules only for the protocol paths below. The app enforces OAuth
and admin consent independently from Cloudflare.

| Path | Why it must be reachable to an MCP client |
| --- | --- |
| /mcp | OAuth Bearer MCP endpoint |
| /.well-known/oauth-protected-resource | RFC 9728 discovery |
| /.well-known/oauth-protected-resource/mcp | Path-specific RFC 9728 discovery |
| /.well-known/oauth-authorization-server | RFC 8414 metadata |
| /register | Dynamic public-client registration |
| /token | OAuth code and refresh exchange |
| /authorize | Interactive OAuth authorization entry |

Do NOT bypass /, /login, /logout, /api/v1/* or /static/*.
Browsers using /authorize redirect to /login and must pass Cloudflare Access
and a separate Kali MCP administrator login before authorizing a client.

## Hardening requirements
- Bind Docker port 8787 to 127.0.0.1 when using cloudflared on the same Pi.
- Never route the raw Docker port directly from the public Internet.
- Set KALI_MCP_PUBLIC_URL consistently to the canonical HTTPS origin.
- Apply Cloudflare rate limits to /register, /token and /authorize.
- Keep the admin password private and never commit it to this repository.
- Require OAuth PKCE S256, exact redirect URI checks, token audience binding,
  hashed tokens, single-use authorization codes and refresh-token rotation.
- Validate real-world interoperability with ChatGPT and other supported clients.
- A successful OAuth connection does not itself enable host or root execution.

Cloudflare path precedence and this deployment's OAuth login callback behavior
must be integration-tested before public exposure.
