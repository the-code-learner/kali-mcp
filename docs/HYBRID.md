# Kali MCP — systemd hybrid with named superuser (security beta)

The previous privileged-Docker beta is legacy and should not be exposed publicly.
The recommended mode uses a native systemd Host Agent plus a nonprivileged
MCP/WebUI container. New security features are verified on Linux AMD64; Kali
ARM64 hardware and Cloudflare Access still require end-to-end validation.

## Initial installation

Run from a Kali ARM64/AMD64 checkout with root privileges:

    sudo bash scripts/install-hybrid.sh

The Bash entrypoint validates hardware and dependencies, downloads a GitHub
release archive, rejects unsafe source members and launches the SSH wizard.
The wizard requires no curses or keyboard hotkeys. It asks for release channel,
a **superuser username and strong password**, access method and maximum host/root permissions.
Re-running the installer preserves configuration; --reconfigure reopens the
wizard, and --non-interactive uses preset environment variables.

Before the first hybrid prerelease, test with a pinned branch commit:

    sudo KALI_MCP_VERSION=<full-40-character-commit> bash scripts/install-hybrid.sh

The new CLI command is installed automatically:

    sudo kali-mcp
    sudo kali-mcp status
    sudo kali-mcp jobs
    sudo kali-mcp audit
    sudo kali-mcp updates
    sudo kali-mcp toggle host_exec on
    sudo kali-mcp toggle host_root on
    sudo kali-mcp access

The CLI dashboard is designed for SSH and displays systemd/Docker status,
recent jobs, active capabilities and endpoint URLs. Root activation requires
typing ENABLE ROOT and remains off by default.

## Superuser and login protection

On first install the SSH wizard creates one **application superuser** (distinct
from the Linux root account) using a named username and password. It can
generate a strong password or accept one entered with hidden terminal input.
Credentials are stored as a salted scrypt password hash (N=131072, r=8, p=1),
not in Docker environment variables or shell commands.

- Canonical root-owned record: `/etc/kali-mcp/superuser.json` (0600).
- Read-only copy for the Core: `/var/lib/kali-mcp/auth/superuser.json`
  (root:10001, 0640, mounted read-only in Docker).
- Login to `/login` requires **username + password**.
- Every `sudo kali-mcp` CLI invocation requires **Linux sudo and the same
  named superuser credentials**. The CLI does not accept passwords as flags.
- Changes to Host Agent privileges additionally require re-entry of the
  superuser password in WebUI. The Agent validates it against the root-owned
  record, independently of WebUI session state.
- Browser sessions use HttpOnly/Secure cookies, CSRF checks, a four-hour
  lifetime and invalidation when the credential record changes.
- `sudo kali-mcp wizard` permits credential changes after confirming the old
  superuser password; then Core/Agent are restarted.
- For automated local CLI tests only, a root-owned 0600 file may be
  specified using `KALI_MCP_CLI_PASSWORD_FILE`. Do not expose such a file
  to untrusted users or put passwords in shell history.

Existing beta.3 upgrades **must use the new versioned Bash installer** rather
than beta.3's in-place `kali-mcp upgrade` command to migrate from the old
plaintext environment password. After migration, subsequent upgrades can use
the dashboard again.

## Exposure and bind-address policy

The default Docker host binding is **127.0.0.1:8787**. The wizard permits
`KALI_MCP_BIND_ADDRESS=0.0.0.0` only as an explicit choice, with an HTTPS
canonical origin and a warning about protecting port 8787 by firewall and a
TLS reverse proxy. **Authentication does not encrypt HTTP.** Never expose
the raw HTTP origin directly to the untrusted Internet. Cloudflare Tunnel
(origin localhost) or private Tailscale Serve are safer defaults.

There is no guarantee of zero unauthorized access, especially with unrestricted
host root enabled. Cloudflare Access with MFA, a restrictive firewall, regular
security patching and testing of real client OAuth flows remain necessary.

## Trust boundaries

- Core runs as UID 10001 in Docker: no privileged, no Docker socket, no host
  PID/mount namespace, ALL capabilities dropped, no-new-privileges.
- Host Agent is a native root systemd service using a restricted Unix socket
  at /run/kali-mcp-agent/agent.sock with root:kalimcp ownership and mode 0660.
- Host privilege toggles persist in a root-owned policy file in /etc/kali-mcp;
  WebUI settings are synchronized to the Agent; its hard ceilings are separate.
- Core jobs/results and OAuth database persist in /var/lib/kali-mcp/core.
- The Agent owns access to Docker Engine for short-lived isolated script
  sandboxes. The Core never mounts Docker's socket.

**The Agent is privileged by design. A compromised Core with socket access
can still target this trusted Agent API. The WebUI toggle is a consent control,
not a root-level compromise containment guarantee.**

## Remote access setup

Use sudo kali-mcp access.

Cloudflare Tunnel: the assistant can install cloudflared from Cloudflare's
signed apt repository, request a remotely-managed Tunnel token invisibly,
store it in a 0600 file and install a systemd service using --token-file,
never including the token in process arguments. It asks for explicit
confirmation that the Cloudflare Access policy has been prepared. The operator
must configure the public hostname to forward to localhost:8787 and allow
only necessary OAuth endpoints and the protected MCP resource through Access.
Admin login and other WebUI routes remain protected by Access.

Tailscale: the assistant can install Kali's tailscale apt package, run
tailscale up and enable Tailscale Serve HTTPS for the private tailnet. Hosted
ChatGPT or other cloud MCP clients outside the tailnet CANNOT access this
private service through Serve alone. Funnel is intentionally not auto-enabled.

For cloud MCP clients use a configured HTTPS origin + /mcp and native OAuth.
For local/private management use SSH forwarding or Tailscale.

## Update behavior

The CLI scans stable/beta GitHub releases. Re-running the versioned installer
with --upgrade stages the next release and restarts Agent/Core; if startup
fails, it attempts to restore the previous source symlink.

This initial approach does not roll back OS packages, kernel, Nexmon,
database migrations or virtual environment changes. One-click update and
systemd transient jobs remain planned features.

## Status and prerequisites

This mode is NOT yet released or tested on a Kali Raspberry Pi 5. It requires
Kali/Debian, systemd, apt, Docker Engine and Docker Compose. Host/root mode,
networking hardware, real Cloudflare Access and installer upgrade/rollback must
be validated on ARM64 before public exposure.

See docs/CLOUDFLARE.md for OAuth path exemptions.
