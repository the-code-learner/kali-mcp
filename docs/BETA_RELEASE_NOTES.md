# Kali MCP v0.1.0-beta.2 — Portainer single-YAML deployment

This prerelease updates the deployment workflow to match Postmaster MCP.

## Install directly from Portainer

1. **Stacks → Add stack → Git repository**.
2. Repository: `https://github.com/the-code-learner/kali-mcp`.
3. Reference: `refs/tags/v0.1.0-beta.2`.
4. Compose file: `kali-mcp.yml`.
5. In **Environment variables** set `KALI_MCP_ADMIN_PASSWORD` to a unique password of 16+ characters.
6. Click **Deploy the stack**.

No terminal command, YAML download or text editor is necessary. The Python
bootstrap is embedded **directly in the YAML** and downloads the latest
GitHub Release appropriate for the selected channel.

Optional Portainer variables: `KALI_MCP_RELEASE_CHANNEL=beta` (default),
`KALI_MCP_PUBLIC_URL=https://your.example.com` for Cloudflare OAuth,
`KALI_MCP_VERSION=latest` (default), and disabled-by-default permission
ceilings such as `KALI_MCP_ALLOW_HOST_ROOT`.

## Changes since beta.1

- Replaced blank hard-coded administrator password in the Compose file with
  mandatory Portainer Stack interpolation.
- Introduced Portainer variables for release channel, version pin, public
  URL and host/privilege ceilings.
- Kept the validated GitHub Release download, checked source archive extraction,
  cached version and persistent data/virtualenv bootstrap **inside** the
  single Compose YAML.
- Documented Git-repository and Web editor deployment instead of
  curl/nano-based installation.

## Safety and feature scope

All previous beta capabilities remain: OAuth PKCE and MCP discovery, WebUI,
bounded jobs/results, initial Kali registry and Docker sandbox. The broker
is privileged and effectively host-root; its WebUI toggle is an application
authorization control and not host isolation.

This is still **experimental**. Real Raspberry Pi 5/Kali ARM64 verification,
Cloudflare Access setup, hardware Wi-Fi/Nexmon, host root and the in-app
upgrade/rollback engine remain outstanding. Run only on a dedicated lab Pi.

See [beta installation guide](https://github.com/the-code-learner/kali-mcp/blob/v0.1.0-beta.2/docs/BETA.md).
