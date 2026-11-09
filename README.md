# Kali MCP

**A self-hosted MCP control plane for authorized security assessments with Kali Linux.** Manage Kali tools, execution jobs, network reconnaissance, MCP clients and appliance settings through an authenticated WebUI or an SSH-friendly CLI.

[Latest published prerelease: v0.1.0-beta.14](https://github.com/the-code-learner/kali-mcp/releases/tag/v0.1.0-beta.14) · [Beta.15 candidate notes](docs/BETA15_RELEASE_NOTES.md) · [Beta 14 release notes](docs/BETA14_RELEASE_NOTES.md) · [Hybrid deployment guide](docs/HYBRID.md) · [Security model](docs/SECURITY.md)

> **Beta software for dedicated lab/assessment systems, not a production-hardened remote-access appliance.** GitHub CI validates Linux AMD64 Docker and systemd/Docker deployments, including OAuth and Agent socket recovery. Testing on a real Raspberry Pi has informed recent fixes, but your specific Kali ARM64 installation, network interfaces and Cloudflare/Tailscale setup still need validation. Run security tests only against systems you own or are authorized to assess.

## Architecture

The **recommended deployment** is the hybrid systemd + Docker design:

```text
Authorized MCP client ── HTTPS /mcp ──┐
                                      │
Administrator browser ── HTTPS ───────┤
                                      ▼
                         Unprivileged Docker Core
                         MCP • OAuth • WebUI • jobs
                                      │
                              Private Unix socket
                                      ▼
                        Native systemd Host Agent
                        Kali host tools • controlled
                        execution • Docker sandboxes
```

- **Core:** Docker container running as UID 10001, with dropped capabilities, a read-only root filesystem, no Docker socket mount and no host-root privileges.
- **Host Agent:** native systemd service, with privileged operations behind a private Unix socket and separately approved capability gates. It can run supported Kali tools and isolated, network-disabled script sandboxes.
- **WebUI / Control Center:** authenticated administration, job history, audit and scope/configuration management.
- **SSH CLI:** local dashboard, diagnostics, credentials, client management and guided access configuration using `sudo kali-mcp`.

The legacy privileged-Docker single-YAML deployment (`kali-mcp.yml`) remains in the repository for compatibility; **new installations should use the hybrid installer** (`kali-mcp-hybrid.yml`). Do not deploy both stacks against the same application state.

## Quick start — hybrid installation

**Requirements:** a dedicated Kali/Debian-based ARM64 (`aarch64`) or AMD64 (`x86_64`) host with systemd, apt, internet access to GitHub/Docker/PyPI and sudo privileges. Docker Engine and the Compose plugin are required; the installer attempts to install missing supported packages.

For a Raspberry Pi, use an SSH terminal or its local console. Download the *versioned* installer and verify the official release manifest **before** executing it:

```bash
mkdir -p ~/kali-mcp-install && cd ~/kali-mcp-install
TAG=v0.1.0-beta.14
BASE="https://github.com/the-code-learner/kali-mcp/releases/download/$TAG"

curl -fL --retry 3 -o install-hybrid.sh "$BASE/install-hybrid.sh"
curl -fL --retry 3 -o kali-mcp-hybrid.yml "$BASE/kali-mcp-hybrid.yml"
curl -fL --retry 3 -o SHA256SUMS "$BASE/SHA256SUMS"
sha256sum --check SHA256SUMS

sudo env KALI_MCP_VERSION="$TAG" KALI_MCP_RELEASE_CHANNEL=beta \
  bash ./install-hybrid.sh
```

The text-based wizard runs over SSH and configures your **application superuser** (username + password), release channel, remote-access mode (`local`, `tailscale` or `cloudflare`), bind address and execution permission ceilings. It preserves existing configuration on ordinary reinstall/upgrade; use `--reconfigure` only when you intend to change settings. Do not paste credentials or access tokens into issue reports.

After installation:

```bash
sudo kali-mcp status   # Agent, Docker, local endpoint and configuration
sudo kali-mcp          # Interactive SSH dashboard
```

Both commands require sudo and application-superuser authentication. The default Core HTTP listener is **127.0.0.1:8787**, not a publicly exposed port.

### Open the WebUI locally

On the Pi itself, use `http://localhost:8787`. From your own computer, tunnel to the Pi:

```bash
ssh -L 8787:127.0.0.1:8787 <ssh-user>@<pi-address>
```

Then open **http://localhost:8787** in your computer's browser and sign in with the superuser created by the wizard.

The MCP endpoint is `<configured-origin>/mcp`, not the WebUI root URL. For hosted clients, configure a reachable **HTTPS origin** first.

## MCP client authentication and remote access

Kali MCP offers **OAuth 2.1-style Authorization Code + PKCE (S256)** for interactive MCP clients and separately managed **API tokens** for compatible clients. Neither credential implicitly authorizes host or root execution.

- **Cloudflare Tunnel:** `sudo kali-mcp access` can assist with the tunnel; configure your hostname, Cloudflare Access, HTTPS and narrowly scoped protocol-path exceptions as documented in [Cloudflare + OAuth](docs/CLOUDFLARE.md). Keep the origin service bound to localhost.
- **Tailscale Serve:** provides **private tailnet HTTPS**, suitable for private remote management. A hosted/cloud MCP client outside the tailnet cannot connect through Serve alone.
- **Browser-based MCP clients:** configure the client's exact origin in **Control Center → MCP Browser Origins / CORS** where applicable. CORS does not replace authentication.
- **API tokens:** manage them in the WebUI or through `sudo kali-mcp api-tokens` / `sudo kali-mcp api-token-create`; store issued credentials securely and revoke unused ones.

**Never expose the raw HTTP port 8787 to the public Internet.** Binding to `0.0.0.0` is an explicit operator choice and requires compensating HTTPS proxy/firewall controls; WebUI authentication does not encrypt plaintext HTTP. See [security details](docs/SECURITY.md) and [hybrid guide](docs/HYBRID.md).

## Available functionality

| Area | Current beta behavior |
| --- | --- |
| MCP access | Protected streamable HTTP at `/mcp`, OAuth/PKCE and optional API-token authentication |
| Kali tools | Curated dynamic registry with typed, bounded actions (e.g. Nmap discovery/service inventory); availability depends on installed host packages |
| Execution | Network-disabled Docker Python/Bash sandbox; separately gated host scripts and SSH-like terminal sessions |
| Jobs | Persistent per-client job history, audit and bounded results; `jobs_get`, **`jobs_wait`** and **`jobs_cancel`** |
| Network | Read-only Wi-Fi status/scan via NetworkManager; `wifi_scan` is an alias of `scan` |
| Administration | WebUI Control Center + SSH dashboard for capabilities, clients, settings, jobs and release checks |
| File transfer | Per-client MCP transfer workspace, Base64 chunks or signed single-use OpenLink transfers, up to **100 MB per file** ([details](docs/MCP_FILE_TRANSFERS.md)) |
| Updates | Stable/beta GitHub release checks and operator-triggered hybrid upgrades, with limited source rollback |

**Beta 14 highlights:** cancellation of queued/tracked running jobs, bounded `jobs_wait(job_id, timeout=15)` (maximum wait 30 seconds), clearer `timed_out` states and improved natural-language tool discovery. Cancellation acceptance is **not** confirmation of termination; use `jobs_wait` or `jobs_get` to verify the terminal job state. Persistent terminal sessions are managed separately using `terminal_close`.

The registry is intentionally small: not every installed Kali binary has a fully featured typed adapter. Complex authorized tests can use host execution *only if* explicitly enabled by the administrator.

## Scope and privilege controls

Execution permissions have two layers: deployment ceilings and administrator approval. **Host execution, host root, package installation and network changes are disabled by default.** Enabling a host/root capability is a deliberate, high-impact action; the systemd Agent itself remains a privileged trust boundary.

Target scope is **configurable per authorized engagement**:

- `KALI_MCP_ALLOWED_CIDRS`: optional allowlist for typed tool adapters.
- `KALI_MCP_DENIED_CIDRS`: denylist that takes priority over allowlists and `allow_all_targets`.
- `KALI_MCP_ALLOW_ALL_TARGETS`: explicit permissive mode, useful in appropriately authorized lab assessments.

A permissive target scope is **not inherently a product defect**. However, typed-adapter CIDRs are **not a host firewall** and do not comprehensively constrain arbitrary host shell or terminal commands. Maintain out-of-scope restrictions at the network/firewall and operational level when host execution is enabled. The beta does not silently reset your scope on upgrade.

## SSH CLI quick reference

```bash
sudo kali-mcp                 # Refreshing interactive dashboard
sudo kali-mcp status          # Host Agent, Docker and endpoint
sudo kali-mcp jobs            # Recent job history
sudo kali-mcp job <job-id>    # One job and its event timeline
sudo kali-mcp audit           # Audit events
sudo kali-mcp clients         # Registered OAuth clients
sudo kali-mcp api-tokens      # API-token inventory
sudo kali-mcp updates         # Check available releases
sudo kali-mcp upgrade         # Confirm and run hybrid upgrade
sudo kali-mcp wizard          # Reconfigure with superuser confirmation
sudo kali-mcp access          # Cloudflare/Tailscale assistant
```

For a complete command list, run `sudo kali-mcp --help`. The CLI requires interactive credential entry for normal administration; root execution still obeys deployment ceilings and Agent-side approval.

## Updating, troubleshooting and rollback

**DNS in bridged Docker networks:** if the Kali host resolves GitHub but the Core reports `Temporary failure in name resolution`, inspect Core `/etc/resolv.conf` and test a temporary container with `docker run --rm --network current_default --dns <your-host-dns-ip> ...` before changing anything. The **beta.15 release candidate** adds an optional **`KALI_MCP_DNS_SERVER`** Core-only override, configurable in the SSH wizard or Control Center; blank keeps Docker's normal resolver. It is never hard-coded to a public or site-specific DNS server. See [hybrid DNS diagnostics](docs/HYBRID.md#optional-dns-upstream-for-the-core-beta15-candidate).
**Important for beta.14 users with a local DNS override:** when beta.15 is published, use its SHA256-verified `install-hybrid.sh --upgrade` release asset (see [migration instructions](docs/BETA15_RELEASE_NOTES.md)) rather than the old beta.14 CLI installer, which does not know how to migrate the override.

**Existing hybrid appliance:** use **Control Center → Updates → Check now** and apply the latest eligible beta after review, or run `sudo kali-mcp upgrade`. The versioned installer also supports `--upgrade`, `--resume` and `--repair`. Upgrades preserve configured application-superuser credentials and scope, and create a safety backup of the Core SQLite database.

Health checks:

```bash
sudo kali-mcp status
sudo systemctl status kali-mcp-agent.service --no-pager
sudo docker inspect --format '{{.State.Health.Status}}' kali-mcp-core
sudo docker logs --tail 100 kali-mcp-core
```

If installation fails, read `/var/log/kali-mcp/install.log` and use the [hybrid recovery procedure](docs/HYBRID.md). The installer may restore the previous application-source link if activation fails; it **does not** promise rollback of OS packages, kernel changes, external services or all database migrations.

**Migrating from the old privileged-Docker/Portainer deployment:** stop the legacy broker stack before starting the hybrid installer. Do not assume an old stack can be transparently converted or that both can run simultaneously. See [hybrid migration/security notes](docs/HYBRID.md).

## Current limitations

This remains a beta. Hardware-dependent Wi-Fi monitor/AP modes, Nexmon integration, Ethernet gateway/NAT configuration with checkpoint rollback and advanced PCAP presentation are not complete supported workflows. A process that deliberately daemonizes outside its original process group may escape a job cancellation. Hosted clients, TLS/Access rules and privileged host operations require assessment-specific integration testing.

Verified CI is **not** a guarantee of a secure production deployment. Prefer a dedicated test appliance, keep access restricted and review the [security model](docs/SECURITY.md).

## Documentation

**[Complete documentation index (current guides vs. historical beta notes)](docs/README.md)**

- [Hybrid installation and trust boundaries](docs/HYBRID.md)
- [Beta 14 release notes](docs/BETA14_RELEASE_NOTES.md)
- [Cloudflare Tunnel, Access and OAuth](docs/CLOUDFLARE.md)
- [MCP file transfers](docs/MCP_FILE_TRANSFERS.md)
- [Testing and security model](docs/TESTING.md) · [Security](docs/SECURITY.md)
- [Legacy Portainer deployment guide](docs/BETA.md) (historical)

## License

Licensed under **Apache-2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for copyright and attribution.
