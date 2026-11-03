# Kali MCP v0.1.0-beta.1 — installation and test guide

This **early beta is intended for a dedicated Kali Linux lab appliance**.
It is not yet a production pentesting gateway. The source is published under
the same exact Apache-2.0 LICENSE as Postmaster MCP; attribution is in NOTICE.

## Requirements

- Raspberry Pi 5 with Kali Linux ARM64 and Docker Engine + Compose plugin, or a dedicated Linux AMD64 lab host.
- A live Internet connection for GitHub Releases, the first Python environment install and Docker image pulls.
- At least 64 GiB available disk space is suggested; consider a 128 GB microSD or SSD for capture files.
- A dedicated admin password of **16+ characters**.
- Any target assessment must remain within a network you own or are authorized to test.

## Install from one YAML

After the GitHub beta release appears, download its pinned Compose YAML:

    curl -fsSL https://raw.githubusercontent.com/the-code-learner/kali-mcp/v0.1.0-beta.1/kali-mcp.yml -o kali-mcp.yml

Edit the YAML in a private location:

- Set `KALI_MCP_ADMIN_PASSWORD` in the Core service to a long unique value.
- Keep `KALI_MCP_RELEASE_CHANNEL: "beta"` in both bootstrap and Core.
- Keep `KALI_MCP_VERSION: "latest"` in bootstrap to install the highest available beta-or-stable release the first time.
- Leave host, root, apt and network-changing capabilities **false** until explicitly testing on isolated hardware.
- For a browser accessed by SSH port forwarding, leave `KALI_MCP_PUBLIC_URL` as `http://localhost:8787`.
- For Cloudflare Tunnel/Access, set `KALI_MCP_PUBLIC_URL` to the same HTTPS origin in **both** Core and Broker and configure the policies in [CLOUDFLARE.md](CLOUDFLARE.md).

Start the service:

    docker compose -f kali-mcp.yml up -d --wait

Inspect status and logs:

    docker compose -f kali-mcp.yml ps
    docker compose -f kali-mcp.yml logs --tail=120

The WebUI binds to `127.0.0.1:8787` by default. On a different computer,
use SSH local forwarding instead of exposing the port:

    ssh -L 8787:127.0.0.1:8787 kali@RASPBERRY_IP

Visit `http://localhost:8787` and sign in with the administrator password.
For Cloudflare Tunnel, point the origin at `http://127.0.0.1:8787` and access
the configured HTTPS hostname.

The MCP address for a client is the single URL `https://YOUR_DOMAIN/mcp`.
OAuth authorization code with PKCE S256 is implemented; actual third-party
client interoperability and Cloudflare Access behavior must be tested in
your zone before exposing the service to the Internet.

## What you can test in this beta

- OAuth server discovery, registration, browser admin consent and bearer enforcement.
- WebUI sign-in, CSRF protection and capability toggles with root disclaimer.
- Tool catalog and typed read-only inventory.
- Sandbox Python/Bash execution with network disabled by default.
- Live and saved jobs, read-only output reports and recent audit events.
- Stable/beta release metadata checks (automatically every six hours).
- A preliminary Wi-Fi scan/interface-status capability.

**Currently not supported:** actual in-app update installation and rollback;
automatic Nexmon setup, full Wi-Fi AP/Ethernet gateway switching and rollback;
long-term packet artifacts/PCAP management; robust cancellation of all
descendant processes. The MCP endpoints for unfinished changes return an
explicit error rather than pretending to perform the action.

Host root and terminal functions are **experimental** and should not be
enabled until separately validated on Kali ARM64. The privileged broker
has effective host-level authority even while its WebUI root toggle is off.
Do not use this deployment on a shared or production host.

## First-run failure modes

- The Core will intentionally refuse to start if the administrator password is empty or shorter than 16 characters.
- The initial beta channel must be `beta`; a stable-only channel has no published stable build at this point.
- A previously cached release is reused at restart. The update checker **does not install** new versions automatically.
- If the broker cannot reach host tools through namespace entry on your Kali image, do not enable host execution; collect the broker logs for debugging.
- The Docker bridge's host port maps to localhost only. To provide LAN access, modify the binding explicitly and protect it with a firewall.

## Stop

    docker compose -f kali-mcp.yml down

Do not use `down -v` unless you intentionally want to erase source cache,
settings, jobs and persistent data.
