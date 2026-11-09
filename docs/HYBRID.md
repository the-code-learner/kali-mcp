# Hybrid installation and operations — Kali MCP beta.14

**Current recommended deployment:** native **systemd Host Agent** on the Kali/Debian host plus an **unprivileged Docker MCP/WebUI Core**. This guide describes `v0.1.0-beta.14`; the single-YAML privileged-Docker installation documented in [BETA.md](BETA.md) is historical/legacy.

> Beta for dedicated assessment/lab appliances, not a guarantee of production-grade remote administration. CI runs real Linux AMD64 systemd/Docker, OAuth, socket-restart and upgrade smoke tests. Raspberry Pi 5 testing has informed the beta, but hardware-specific ARM64, Wi-Fi and deployed edge configurations must be verified separately.

## Prerequisites and first installation

- Kali Linux or compatible Debian-based host, `aarch64` or `x86_64`, with **systemd**, **apt**, Internet access and sudo.
- Docker Engine and the Compose plugin; the installer attempts to install missing supported dependencies.
- An SSH TTY or local console for the guided setup. Do not run an interactive wizard from a detached service.
- A dedicated strong application-superuser password, distinct from the Linux root account.

Use the immutable release assets and verify SHA256 *before* executing the downloaded installer:

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

The text-based SSH wizard asks for a **named application superuser** (username and password), release channel, access mode (`local`, `tailscale`, `cloudflare`), canonical public URL, local binding, and host/root permission ceilings. It stores the effective deployment values in root-owned environment files, starts the native Agent, deploys the unprivileged Core, and verifies the *real Core-to-Agent Unix socket ping*. Existing valid settings are reused unless you explicitly reconfigure them.

Installer flags:

| Flag | Purpose |
| --- | --- |
| `--upgrade` | Install the selected release while preserving validated configuration |
| `--reconfigure` | Reopen the SSH wizard to revise settings |
| `--resume` | Resume an incomplete installation |
| `--repair` | Repair an incomplete/broken installation |
| `--non-interactive` | CI/automation with explicitly supplied configuration and credentials (avoid shell-history secrets) |

For a development build, `KALI_MCP_VERSION` may be a full 40-character commit SHA; do not mistake a development commit for a signed or validated release.

## Access the dashboard and MCP

On the appliance:

```bash
sudo kali-mcp status
sudo kali-mcp
```

Every CLI invocation requires **sudo plus application-superuser authentication**. Without an interactive terminal, the dashboard command prints a status/jobs snapshot instead of the interactive refresh loop.

Default binding: `127.0.0.1:8787`, with the WebUI at `http://localhost:8787`. To browse from a separate machine:

```bash
ssh -L 8787:127.0.0.1:8787 <ssh-user>@<pi-address>
```

Open `http://localhost:8787` on the computer that started the tunnel, then authenticate at `/login`. An MCP client uses the **canonical** `<origin>/mcp` endpoint, with OAuth authorization-code/PKCE or a separately issued API token; a successful login does not enable host execution.

Useful CLI commands:

```bash
sudo kali-mcp jobs
sudo kali-mcp job <job-id>
sudo kali-mcp audit
sudo kali-mcp clients
sudo kali-mcp client-revoke <client-id>
sudo kali-mcp api-tokens
sudo kali-mcp api-token-create "my-client" --days 30
sudo kali-mcp api-token-revoke <token-id>
sudo kali-mcp updates
sudo kali-mcp upgrade
sudo kali-mcp wizard
sudo kali-mcp access
```

The CLI also offers capability toggles (`sudo kali-mcp toggle host_exec on`, etc.) subject to deployment ceilings, superuser verification and extra root confirmation. For accurate supported command syntax use `sudo kali-mcp --help`.

## Superuser and credential handling

The installer generates a salted scrypt password-hash record for the application superuser, **not a plaintext Docker environment variable**.

- Canonical record: `/etc/kali-mcp/superuser.json` (root-owned, mode 0600).
- Core-readable hash copy: `/var/lib/kali-mcp/auth/superuser.json` (root:10001, mode 0640), mounted read-only.
- Core SQLite state: `/var/lib/kali-mcp/core`, including job history and OAuth client state.
- Agent-owned capability settings and deployment credentials: root-owned host files; the Core cannot directly edit the host's environment files.
- WebUI uses login sessions, CSRF protections and reauthentication for sensitive Agent changes; the Agent independently validates fresh superuser credentials for privilege-changing requests.

Changing the superuser password revokes existing browser sessions and OAuth/API credentials as implemented by the upgrade/credential migration path. Reconnect clients as needed. Do not store passwords, API tokens or Cloudflare tunnel tokens in the Git repository, a shared terminal history or support tickets. `KALI_MCP_CLI_PASSWORD_FILE` is intended only for tightly controlled local automation with a root-owned 0600 file.

## Security architecture and capability ceilings

```text
HTTPS client / browser
        |
  Core container  (UID 10001, cap_drop=ALL, read-only root, no Docker socket)
        |
  /run/kali-mcp-agent/agent.sock  (private Unix socket)
        |
  systemd Native Agent  (host root; controlled operations and sandbox manager)
```

The Host Agent uses the `kalimcp` Unix group with a mode-0660 socket; the Core mounts the socket directory read-only. The native service preserves its runtime directory through restarts so an existing Core bind mount does not become stale. A Core healthcheck alone does not prove Agent IPC works; check both.

Permission gates are **deliberately separate**: deployment ceilings (`KALI_MCP_ALLOW_HOST_EXEC`, `KALI_MCP_ALLOW_HOST_ROOT`, `KALI_MCP_ALLOW_MCP_HOST_EXEC`, `KALI_MCP_ALLOW_MCP_ROOT`, etc.) and the administrator-controlled Host Agent toggles. All powerful host/root operations are off by default. `host_root` also depends on `host_exec` being enabled. A permitted root shell has powerful host authority and is not contained by the WebUI policy.

**Authorized target scope** is a distinct setting:

- `KALI_MCP_ALLOWED_CIDRS`: addresses permitted to *typed adapters*.
- `KALI_MCP_DENIED_CIDRS`: explicit exclusions, always checked first.
- `KALI_MCP_ALLOW_ALL_TARGETS=true`: administrator-selected permissive mode for authorized testing, without removing the denylist.

Permissive scope is **not** treated as a product failure. CIDR checks in typed adapters do **not** constitute OS-level egress filtering; unrestricted host shell/terminal access can bypass typed-adapter scopes. Set network/firewall restrictions separately when that matters.

See [SECURITY.md](SECURITY.md) for trust boundaries and residual risks, and [BETA14_RELEASE_NOTES.md](BETA14_RELEASE_NOTES.md) for cancellation-specific limits.

## Remote access: Cloudflare and Tailscale

Run `sudo kali-mcp access` to configure an access method.

**Cloudflare Tunnel:** the CLI attempts an available package install if `cloudflared` is missing and verifies the executable; it does **not** guarantee that a distribution package exists on every Kali architecture. You must configure an HTTPS public hostname, an appropriate Access policy, and the controlled OAuth protocol exceptions. The wizard accepts a *hidden-input* remotely managed Tunnel token, stores it in a root-only file and starts the tunnel with `--token-file`. The tunnel should forward to local port 8787; keep that port bound to localhost. See [CLOUDFLARE.md](CLOUDFLARE.md).

**Tailscale Serve:** can expose HTTPS privately to your tailnet and may update the canonical `*.ts.net` origin after confirmation. A hosted MCP client **outside the tailnet cannot reach Serve alone**; Funnel is not enabled automatically.

The canonical public URL must match the HTTPS browser/MCP hostname (no `/mcp` suffix). Changing it can require OAuth reauthorization. **Never publish the plain HTTP listener directly to the Internet.** Binding `0.0.0.0` is explicit and needs independent firewall plus TLS reverse-proxy controls; password authentication is not transport encryption.

## WebUI / Control Center

The authenticated Control Center provides job history, audit, OAuth/API clients, browser origin allowlisting, update tracking and deployment settings. **Authorized Scope** can be edited there by an authenticated superuser; the change is first **scheduled**, then verified against the running Core and host inventory. A scheduled HTTP 202 response is not proof that the change has taken effect.

If the Agent is unavailable, the settings inventory may be shown as unavailable rather than replaced with fabricated defaults. When recovering from an Agent restart or deployment edit, verify the actual Core and Agent states, not only a green page status.

## Upgrade and rollback boundaries

For an existing hybrid installation, use **Control Center → Updates → Check now**, then review and install the latest eligible release, or run:

```bash
sudo kali-mcp updates
sudo kali-mcp upgrade
```

The installer can also be called with `--upgrade` and an explicit `KALI_MCP_VERSION`. It stages source, takes an online SQLite backup where applicable, activates a versioned directory, restarts Agent/Core and checks the Agent IPC from within the Core. On activation failure it attempts to restore the previous *application source link* and restart services. **This is not a full system rollback:** OS packages, Docker/venv dependencies, kernels, database schema migrations and external services may not be reverted.

Check results after any update:

```bash
sudo kali-mcp status
sudo systemctl is-active kali-mcp-agent.service
sudo test -S /run/kali-mcp-agent/agent.sock
sudo docker inspect --format '{{.State.Health.Status}}' kali-mcp-core
sudo docker exec kali-mcp-core /opt/venv/bin/python -c \
  "import sys; sys.path.insert(0, '/opt/kali-mcp/current/src'); from kali_mcp.broker_client import call; print(call('/run/kali-mcp-agent/agent.sock', 'ping', timeout=5))"
```

The IPC ping must report `systemd-host-agent`. If setup fails, inspect the **root-only** `/var/log/kali-mcp/install.log` and retry with `--resume` or `--repair` as appropriate. Do not disclose private `.env` files or credential records.

**Legacy migration:** stop the old privileged-Docker `kali-mcp-broker` stack first. The installer intentionally refuses to proceed while it is running. Follow an explicit migration plan; do not run both architectures against the same state.

## Feature and validation status

Implemented as of beta.14: authenticated MCP transport, curated Kali registry, sandbox and approved host operations, persistent jobs, `jobs_wait`, queued/tracked-job `jobs_cancel`, NetworkManager status/scan, file transfer and update tracking.

Not generally supported as complete features: Wi-Fi AP/Nexmon, Ethernet gateway/NAT with safe checkpoint rollback, generalized monitor-mode workflows, full process/cgroup containment, and advanced PCAP presentation. Cancelled jobs can leave independent daemonized descendants; interactive PTYs use `terminal_close`.

See [STATUS.md](STATUS.md) for the detailed matrix and [TESTING.md](TESTING.md) for a practical hardware acceptance checklist.
