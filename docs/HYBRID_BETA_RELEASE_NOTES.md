# Kali MCP v0.1.0-beta.3 — systemd hybrid preview

This beta introduces a second deployment model. The Docker-only
v0.1.0-beta.2 release remains available; it is not modified.

## New: native systemd Host Agent + nonprivileged MCP Core

- A one-time Bash installer safely stages a selected stable/beta GitHub Release,
  installs a native systemd Agent and launches the nonprivileged Docker Core.
- Interactive text wizard suitable for Kali over SSH. Guided first-run choices
  for release channel, generated administrator password, remote-access method
  and maximum host/root permission ceilings.
- The persistent command sudo kali-mcp opens an SSH CLI dashboard showing
  systemd/Docker status, tool jobs, audit history, permissions and update status.
- sudo kali-mcp access assists with Cloudflare Tunnel and Tailscale Serve.
  Cloudflare tunnel tokens are stored in a root-only file and passed via
  --token-file, not command-line token arguments.
- WebUI and CLI toggles synchronize with an independent host-owned policy file.
  Host root remains disabled until explicitly permitted.
- The Host Agent can schedule an approved manual beta/stable update as a
  detached systemd unit, while periodic checks never auto-install releases.
- CLI upgrades can reuse the installer, atomically select a version and
  attempt to restore the previous source on failed activation.

## Installation

Download the Bash installer (once), review it, then run with sudo over SSH:

    curl -fL https://github.com/the-code-learner/kali-mcp/releases/download/v0.1.0-beta.3/install-hybrid.sh -o install-hybrid.sh
    less install-hybrid.sh
    sudo bash install-hybrid.sh

After the wizard:

    sudo kali-mcp
    sudo kali-mcp access
    sudo kali-mcp status

No separate Compose installation command is required: the installer downloads
the application source, creates the systemd unit and starts the nonprivileged
Core itself. The companion kali-mcp-hybrid.yml is also included as a release
asset for auditing or adapting existing installations.

The base WebUI binds to localhost:8787. To reach it from another SSH machine,
use an SSH local port forward. Hosted MCP clients require an HTTPS origin
reachable externally; Cloudflare Tunnel with Cloudflare Access for the WebUI
and OAuth for /mcp is recommended. Private Tailscale Serve does not expose
the service to hosted cloud clients outside your tailnet.

## Security and beta limitations

The Agent executes as root on Kali and listens through an ACL-controlled Unix
socket; Docker Core runs unprivileged, without Docker socket access. Root is
a persistent administrator opt-in, but compromise of the Core's Agent socket
access remains a high-impact threat. This is experimental software; it is
not a host-root sandbox or production security boundary.

The implementation has passed hosted AMD64 Docker/systemd/SSH-installer
smoke tests and OAuth integration tests. **Raspberry Pi 5 ARM64, real Kali
Wi-Fi/Nexmon, Cloudflare Access and full root PTY are not yet hardware tested.**
Host package/kernel changes are outside app rollback. Use a dedicated lab Pi.

Full details: docs/HYBRID.md.
