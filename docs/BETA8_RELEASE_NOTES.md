# Kali MCP v0.1.0-beta.8 — llama.cpp WebUI / public HTTPS MCP integration

Based on the Raspberry Pi 5 / Kali ARM64 beta.7 integration report of 8 November 2026.

## Fixed: public HTTPS MCP 421 Invalid Host header (P1)

The outer HTTP security gate accepted the public hostname but the MCP Python SDK's DNS-rebinding allowlist accepted only `hostname:*`, requiring an explicit port. Browsers usually send `Host: kali-mcp.warebench.com`, without `:443`. The SDK now gets both the exact configured public hostname and its explicit-port variant. **DNS-rebinding protection remains enabled**. There are no global wildcards, no reliance on client-supplied `X-Forwarded-Host` and no Cloudflare/TLS bypass.

SDK regression tests exercise exact public HTTPS host, `:443`, untrusted Host (421) and untrusted Origin (403). Hybrid HTTP smoke now exercises real OAuth and API-token MCP POST requests with portless Host (including `initialize`, `tools/list`, `tools/call`) after a successful CORS OPTIONS preflight.

## New: MCP Browser Origins / CORS WebUI panel (P2)

- Display **Active in Core** and **Saved on Host** origins independently and show the latest deployment state.
- Add/remove exact HTTPS browser origins from the dashboard. All changes require an authenticated WebUI superuser, a valid per-session CSRF token, and **independent superuser-password verification by the root Native Host Agent**.
- The root Host Agent schedules a dedicated systemd job. A narrow root-only script atomically updates the protected `stack.env` and `agent.env`, recreates **only `kali-mcp-core`**, checks Docker health and checks the active environment. If the change fails, it restores the previous files and attempts to restore the previous Core.
- The Core container never receives a writable `/etc/kali-mcp` mount, Docker socket or host/root MCP execution entitlement.
- The API token form has an optional **Browser origin** field. It validates the origin is *already* authorized and explicitly explains that CORS authorization and API-token authorization are distinct.
- **Check CORS** tests the actual OPTIONS preflight. Providing a valid Bearer token additionally tests the SDK Host validation and real `initialize` and `tools/list` POSTs against the local MCP listener while preserving the public Host header. The test token is not logged, persisted or reflected in the result. Without a token, Host/MCP testing is clearly marked *not tested*.
- Unknown origins remain blocked with HTTP 403. The allowlist is MCP-only; no administrative CORS wildcard or permissive Origin fallback was introduced.

## Improved: API token usability (P3)

Responsive full-width panel; labeled inputs with desktop grid/mobile single column; a keyboard-accessible horizontally scrollable table with reachable Rotate/Revoke actions. This does not modify token permissions or secrets.

## Deployment and validation

Existing installations may install this release using **Updates → Check now** if the current version is healthy and updates are authorized. The installer retains credentials, persistent state and browser origins. As always, verify the **Installed** version rather than relying on the scheduled update job.

For a browser client (e.g. llama.cpp WebUI):

1. In Kali MCP WebUI, authorize the exact browser origin, e.g. `https://llm.davidecasalin.it`. Wait until **Active in Core** reflects it and deployment state is **active**.
2. Create an API Token for the browser client; copy it once.
3. In llama.cpp, use Streamable HTTP `https://kali-mcp.warebench.com/mcp` with `Authorization: Bearer <API_TOKEN>`, custom headers empty, and `Use llama-server proxy = OFF`.
4. Optionally run **Check CORS** with your origin and Bearer token. Successful preflight alone does **not** confirm MCP functionality; check the SDK Host and `initialize/tools/list` results too.

The example domains are only illustrative; the actual `KALI_MCP_PUBLIC_URL` and allowed browser origins must match your deployment. Keep the API token secret.

No OAuth 2.0 / PKCE, CLI, host/root policy, llama.cpp `--tools all` behavior or remote proxy architecture is changed. No bridge/container addition is required.

## Testing

CI covers exact SDK Host/Origin matching, browser-origin validation and UI CSRF, privileged Agent authorization, atomic config mutation/rollback, Docker smoke for the pinned legacy release, and hybrid systemd/Docker integration. Hybrid smoke exercises real MCP OAuth/API Bearer and the Native Host Agent's CORS configuration update with Core-only recreate. Physical Raspberry Pi and Cloudflare browser integration still require operator validation.
