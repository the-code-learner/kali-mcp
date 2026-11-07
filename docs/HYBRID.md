# Kali MCP — hybrid systemd + Docker (development preview)

The existing privileged-Docker beta remains available separately. This feature
branch adds a native Host Agent supervised by systemd and a nonprivileged
MCP/WebUI container.

## Initial installation

Run from a Kali ARM64/AMD64 checkout with root privileges:

    sudo bash scripts/install-hybrid.sh

The Bash entrypoint validates hardware and dependencies, downloads a GitHub
release archive, rejects unsafe source members and launches the SSH wizard.
The wizard requires no curses or keyboard hotkeys. It asks for release channel,
administrator password, access method and maximum host/root permissions.
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
