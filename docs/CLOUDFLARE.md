# Cloudflare Tunnel, Access, OAuth and browser MCP — beta.14

Use **one canonical HTTPS public origin**, for example `https://mcp.example.com`, with the MCP endpoint at **`https://mcp.example.com/mcp`**. The Docker Core should continue listening privately on `127.0.0.1:8787`; Cloudflare Tunnel supplies remote HTTPS connectivity. Never expose the raw Core HTTP port on the Internet.

This is an **operator configuration guide**, not proof that a particular Cloudflare zone/client works. Verify the actual policy and live OAuth flow on your deployment. Also read [HYBRID.md](HYBRID.md) and [SECURITY.md](SECURITY.md).

## Tunnel setup

Run `sudo kali-mcp access` and choose **Cloudflare Tunnel**. The CLI checks for `cloudflared`, can attempt installation from a distribution package, verifies the executable and asks you to confirm the Access policy first. A remotely managed Tunnel token is entered using hidden terminal input, saved in a root-only file and used by a dedicated systemd service via `--token-file`, rather than embedding the token in process arguments.

Configure the public hostname to forward to `http://127.0.0.1:8787` on the same host. Update the canonical `KALI_MCP_PUBLIC_URL` to the **HTTPS origin without `/mcp`**; the CLI may perform this after confirmation. Changes to the origin/token audience can require OAuth clients to reauthorize.

Package availability and architecture-specific install details vary; if `cloudflared` is missing, follow the vendor's verified installation instructions rather than trusting arbitrary binaries.

## Cloudflare Access routing

Start with **default-deny administrative routes** and an Access application with appropriately strong authentication/MFA. To support public remote MCP clients that cannot present Cloudflare Access session credentials, configure carefully scoped policy exceptions for **only** the protocol routes needed by the client:

| Route | Purpose |
| --- | --- |
| `/mcp` | Authenticated streamable HTTP MCP resource |
| `/.well-known/oauth-protected-resource` | Protected-resource metadata |
| `/.well-known/oauth-protected-resource/mcp` | MCP-specific protected-resource metadata |
| `/.well-known/oauth-authorization-server` | OAuth server discovery |
| `/register` | Dynamic public client registration |
| `/token` | OAuth authorization-code/refresh-token exchange |
| `/authorize` | Interactive authorization and consent entry |

**Do not exempt** the general dashboard (`/`), `/login`, `/logout`, `/api/v1/*`, `/settings/deployment`, `/jobs/*` or `/static/*` as a group. OAuth `/authorize` can redirect a browser to the protected `/login` page; you must test that the browser can satisfy both Cloudflare Access and Kali MCP's independent superuser/consent step.

Cloudflare bypass of the transport routes is **not bypass of Kali MCP authentication**: `/mcp` still requires a valid resource-bound OAuth Bearer token or enabled API token. Apply tight request/rate limits to registration and token endpoints and verify the exact Access path matching behavior in your zone.

### Optional OpenLink file transfers

If using signed one-time `files_upload` / `files_download` URLs, the client must also reach `/files/openlink/*` with HTTP **PUT** or **GET**. Cloudflare Access login redirects can break raw uploads/downloads; a narrowly scoped exception for this path may be needed. **These URLs are bearer-like credentials**: use short lifetimes, avoid logging them and never exempt the entire dashboard or wildcard all paths. Cloudflare plan upload size/time limits may be below Kali MCP's 100 MB/file limit; Base64 chunks are an alternative. See [MCP_FILE_TRANSFERS.md](MCP_FILE_TRANSFERS.md).

## OAuth clients and API tokens

**Interactive MCP clients** use OAuth authorization-code + PKCE S256, including browser consent. Register via the supported metadata/DCR flow, complete WebUI superuser approval and connect to the canonical `https://mcp.example.com/mcp` resource.

**API tokens** are a separate, revocable credential type. Create them through **Control Center → MCP Clients → API Tokens** (fresh superuser confirmation), or from the SSH CLI. Copy the token once, store it securely and consider a per-token tool allowlist. Use one of these client request headers where supported:

```text
Authorization: Bearer <api-token>
X-Kali-MCP-API-Key: <api-token>
```

Do **not** send both credential forms in the same request. The custom API key header can be disabled by setting `KALI_MCP_API_HEADER_ENABLED=false`; ordinary Bearer authentication remains available. Neither API tokens nor OAuth consent enable privileged host/root capabilities by themselves.

Revoke or rotate API tokens through Control Center or `sudo kali-mcp api-token-rotate <token-id>`. Keep separate keys per client and do not confuse upstream LLM-provider credentials, Nginx Basic Auth and Kali MCP Bearer credentials.

## Browser-based clients (e.g., llama.cpp WebUI)

When a browser makes direct cross-origin MCP calls:

1. In **Control Center → MCP Browser Origins / CORS**, allow only the exact browser origin, for example `https://llm.example.com`. Wildcards are not supported; localhost HTTP is reserved for local development.
2. Wait for the controlled settings deployment and Core restart; verify that the saved Host value is **active in the Core**. The presence of an entry in an editor is not proof it has applied.
3. Set the MCP URL to `https://mcp.example.com/mcp`, choose streamable HTTP, and pass the correct **Kali MCP** credential in the client.
4. Allow the edge to handle **`OPTIONS /mcp`**. An HTTP 204 CORS preflight is useful but **insufficient**; also test authenticated `POST initialize` and `tools/list` with the actual public **Host** header.
5. For direct browser fetches, configure the client to avoid unnecessary intermediary proxies. For a client-side/LLM-server proxy, ensure only intended Kali MCP credentials are forwarded to Kali, not credentials for the LLM interface's own Nginx/Basic Auth.

The Core enforces the Host/Origin checks and the precise origin allowlist. Administrative APIs do **not** become cross-origin public APIs. A browser API token does **not** automatically grant CORS; register the browser origin separately.

Browser profiles and proxy logs can expose stored API tokens to local administrators or other applications. Prefer dedicated, short-lived, revocable credentials and do not paste them into screenshots or reports.

## Troubleshooting checklist

- **401 from `/mcp`:** confirm the bearer is valid, unexpired, intended for the current canonical resource URL, and not revoked; check API-token enablement for custom headers.
- **Invalid Host header:** confirm `KALI_MCP_PUBLIC_URL` matches the actual public hostname, with no path and the correct scheme; do not disable DNS-rebinding checks to suppress the error.
- **Browser CORS failure:** check the exact origin (scheme + hostname + port), that the Core reports it as active, and the proxy's `OPTIONS` forwarding.
- **Cloudflare Access redirect:** compare the path and browser/client class against your Access application rules; protect all unrelated administrative paths.
- **Tunnel reaches UI but MCP fails:** test actual OAuth discovery, registration/consent, token exchange and authenticated `tools/list`; a green `/healthz` is not a complete MCP smoke test.
- **OpenLink fails:** check signed URL expiry/one-time consumption, PUT/GET forwarding and Cloudflare body/time limits.

For a local/private alternative, **Tailscale Serve** is limited to the tailnet by default; hosted clients outside that tailnet cannot connect without another supported gateway. The access assistant does not automatically enable Funnel.

## Security reminder

Access/MFA, HTTPS, WAF/rate limits, strong superuser credentials, scoped/revocable API tokens and host-level firewall policies are complementary controls. Root execution is independently gated and can still compromise the entire appliance if deliberately enabled. The authorized target CIDR scope is an administrator choice, not a universal egress firewall.
