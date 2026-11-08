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

## API tokens + llama.cpp browser integration (beta.5)

OAuth Authorization Code + PKCE S256 is preserved for interactive clients;
self-contained API tokens are an **additional** credential type on the SAME `/mcp` endpoint.
Only bypass Cloudflare Access for protocol routes in the table above.
Do not bypass `/api/v1/api-tokens/*`, `/login`, `/logout`, or the dashboard.

- Create a 30-day API token under **Dashboard → MCP Clients → API Tokens**.
  Confirm the current superuser password and copy the token immediately.
- Set `KALI_MCP_BROWSER_ORIGINS=https://llm.davidecasalin.it` in
  `/etc/kali-mcp/stack.env`, then recreate the Core. Only exact HTTPS
  origins are permitted, never a wildcard or `Origin: null` without
  the administrative form checks.
- In llama.cpp WebUI set MCP URL `https://kali-mcp.warebench.com/mcp`,
  transport `streamable_http`, and use `Authorization: Bearer <one-time-token>`.
  Alternatively, use `X-Kali-MCP-API-Key: <one-time-token>`.
  For direct browser calls, set **Use llama-server proxy = OFF**.
- With llama-server `/cors-proxy`, set **Use llama-server proxy = ON**.
  Keep any Nginx Basic Auth on the LLM hostname separate from the MCP
  credential. The browser proxy should forward MCP Bearer using
  `x-llama-server-proxy-header-authorization` and must NEVER forward
  upstream Nginx Basic credentials to Kali.
- Allow `OPTIONS /mcp` on the edge; only origins in the exact allowlist
  receive CORS preflight/response headers. Administrative routes are not CORS enabled.

Browser-side llama.cpp may persist MCP tokens in its browser profile.
Use short-lived, dedicated, revocable keys and prefer a tool allowlist for
read-only workflows. Bearer or custom-header tokens never grant root/host
capabilities: existing deployment ceilings and Host Agent toggles still govern
them. Revocation takes effect immediately; password rotation invalidates API
tokens bound to the previous superuser fingerprint.

Rotate API keys with the **Rotate** action in the WebUI, or use the
superuser-authenticated CLI `sudo /usr/local/bin/kali-mcp api-token-rotate <token_id>`.
The old key is invalidated immediately and only the replacement secret is shown.
