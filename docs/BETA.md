# Legacy beta.2 — Portainer single-YAML installation (historical)

> **Historical documentation only.** This page records the original beta.2 privileged-Docker/Portainer setup and intentionally preserves its old tag, variables and limitations. It is **not the recommended installation for v0.1.0-beta.14**. New installations should follow the [current hybrid systemd + Docker guide](HYBRID.md) or the [root README](../README.md). Do not run both the legacy broker stack and the native Host Agent against the same installation.
>
> Current feature availability is listed in [STATUS.md](STATUS.md), current trust boundaries in [SECURITY.md](SECURITY.md), and current release information in [BETA14_RELEASE_NOTES.md](BETA14_RELEASE_NOTES.md). All instructions below apply **only to the historical beta.2 design**.

This early beta is intended for a **dedicated Kali Linux lab appliance**.
Do not yet enable host root or expose the service publicly until the Kali
ARM64 and Cloudflare-specific security tests have been completed.

The **historical beta.2** installation path used the **Portainer Stack UI**:
**no curl, no nano, no manual Python installation and no auxiliary scripts.**

## Prerequisites

- Kali Linux on Raspberry Pi 5 ARM64 (or a Linux AMD64 lab host)
- Docker Engine, Compose plugin and Portainer installed and operational
- Network access to Docker Hub, GitHub Releases, GitHub's source archive and PyPI
- A unique administrator password of 16 or more characters

## Historical beta.2: Portainer Git repository stack

1. In Portainer choose the Docker environment, then **Stacks → Add stack**.
2. Enter stack name `kali-mcp` and choose **Git repository**.
3. Repository URL: `https://github.com/the-code-learner/kali-mcp`
4. Repository reference: `refs/tags/v0.1.0-beta.2` (the published prerelease).
5. Compose path: `kali-mcp.yml` (repository root).
6. Expand **Environment variables** and add `KALI_MCP_ADMIN_PASSWORD`
   with a unique password of at least 16 characters.
7. Leave `KALI_MCP_RELEASE_CHANNEL` unset to use `beta` by default,
   or set it explicitly to `beta`.
8. For a Cloudflare deployment also add
   `KALI_MCP_PUBLIC_URL=https://YOUR_SUBDOMAIN.YOUR_DOMAIN`
   and configure the Access policy in [CLOUDFLARE.md](CLOUDFLARE.md).
   For the first isolated/local smoke test leave it unset.
9. Click **Deploy the stack**.

**What happens automatically:** the Compose bootstrap executes Python already
embedded inside `kali-mcp.yml`. It queries GitHub Releases, selects the highest
version allowed by `KALI_MCP_RELEASE_CHANNEL`, downloads the source archive,
rejects unsafe archive members, stores the version in a persistent source
volume, and starts the broker and MCP/WebUI with persistent Python environments.

Portainer fetches the Compose definition from the repository for this approach.
This is not a requirement to download or edit YAML on the Raspberry Pi.

## Historical alternative: Portainer Web editor

Choose **Stacks → Add stack → Web editor**, paste the **entire** contents of
[kali-mcp.yml](../kali-mcp.yml), add the same Stack environment variables and
click **Deploy the stack**. The inline bootstrap downloads the application just
as in the Git repository method.

## Minimal Portainer environment variables

| Name | Value | Required |
| --- | --- | --- |
| `KALI_MCP_ADMIN_PASSWORD` | A unique strong administrator password, 16+ characters | Yes |
| `KALI_MCP_PUBLIC_URL` | `https://kali.example.com`, same hostname used for MCP and WebUI | Only for remote OAuth |
| `KALI_MCP_RELEASE_CHANNEL` | `beta` (accepts stable and beta) or `stable` (stable only) | No, defaults to `beta` |
| `KALI_MCP_VERSION` | `latest` or a pinned tag | No, defaults to `latest` |

Other YAML ceilings, such as `KALI_MCP_ALLOW_HOST_ROOT` and
`KALI_MCP_ALLOW_MCP_ROOT`, remain `false` by default; they can be set through
the Stack environment variables when testing host capabilities on a dedicated
device. The **WebUI root toggle** is a second, independent requirement.

**Important:** while the Core is non-root, the Docker broker itself is privileged
and has effective host-level authority regardless of the WebUI toggle.

## Local browser access

The Compose file maps the server to `127.0.0.1:8787` on the Pi.
For access from another computer without exposing the port publicly,
an SSH tunnel can forward local port 8787. After connecting, browse to
`http://localhost:8787` and use the Portainer-configured password.

For remote MCP clients the public URL is
`https://YOUR_SUBDOMAIN.YOUR_DOMAIN/mcp` and the app implements
OAuth authorization code + PKCE S256. Cloudflare Access must permit only
the necessary OAuth discovery/exchange and protected MCP paths, with the
WebUI behind Access. Real client and Cloudflare zone testing remain necessary.

## Releases and update behavior

With `KALI_MCP_RELEASE_CHANNEL=beta`, initial installation selects the newest
beta **or** stable GitHub release. With `stable`, only stable releases count.
After initial installation, startup deliberately reuses the cached version.
Release **metadata** is checked periodically, but installing an update via
MCP/WebUI is not yet supported. Updating the Git-backed Compose definition
alone does **not** force a new application version.

There is no stable release currently; keep the channel `beta` for this beta.

## Beta.2-era feature limits (historical)

Available: authenticated WebUI, OAuth MCP, initial tool registry,
typed read-only actions, persistent job/results/audit status and experimental
sandbox Python/Bash execution. The Docker AMD64 bootstrap, HTTP OAuth
and sandbox Python smoke tests passed in CI.

Not yet complete: reliable application update/rollback, Kali ARM64 host
verification, root PTY hardening, Wi-Fi AP/Nexmon management, Ethernet NAT
configuration with NetworkManager checkpoint rollback and PCAP artifacts.

Do not treat the current beta as a production-hardened remote root endpoint.
