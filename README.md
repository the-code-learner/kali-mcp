# Kali MCP

## Systemd hybrid beta — v0.1.0-beta.4 (superuser + access hardening)

The preferred architecture now uses **a native systemd Kali Host Agent**
with a **nonprivileged Docker MCP/WebUI Core**, installed with a guided SSH
Bash wizard. The older privileged-Docker beta.2 remains available.

On the Raspberry Pi, the one-time installer sets up systemd, Docker,
a named application superuser, stable/beta channel, socket permissions and
Cloudflare/Tailscale options. After installation run **sudo kali-mcp**
and authenticate with the same superuser as the WebUI for the SSH dashboard (jobs, audit, capabilities, update checks, root
toggle and guided remote access).

Read the [hybrid installation and security guide](docs/HYBRID.md) and
[beta.4 security release notes](docs/SECURITY_BETA_RELEASE_NOTES.md).
The hybrid Core no longer receives a plaintext admin password through
Docker. The wizard hashes superuser credentials, and Host Agent permission
changes require a fresh superuser proof. When binding to `0.0.0.0`, HTTPS
at the edge and a restrictive firewall remain mandatory; a password alone
cannot make direct HTTP safe.

**Upgrading from beta.3:** download and run the beta.4 installer once to migrate
credentials; beta.3's built-in update command cannot perform that migration.

This is a lab-device beta, not production hardened. The root Host Agent
must still be tested on Kali ARM64 before public exposure.

**Self-hosted Kali Linux MCP control plane with modular tools, network management, sandboxed execution, optional host execution and a live WebUI.**

> **Status: v0.1.0-beta.2 — Portainer-ready early beta, not production ready.** Full Docker Compose boot, OAuth client flow, protected MCP tool discovery and a Python sandbox smoke test passed on Linux AMD64. Kali Raspberry Pi 5 ARM64, host-root execution and Cloudflare Access have not yet been validated end to end.

**[Beta installation guide](docs/BETA.md)** · [single YAML](kali-mcp.yml) · [release notes](docs/BETA_RELEASE_NOTES.md) · [implementation status](docs/STATUS.md)

**Installazione consigliata:** Portainer → **Stacks → Add stack → Git repository** → URL `https://github.com/the-code-learner/kali-mcp` → riferimento `refs/tags/v0.1.0-beta.2` → Compose `kali-mcp.yml`. Imposta `KALI_MCP_ADMIN_PASSWORD` nelle variabili dello Stack e premi Deploy. Lo YAML scarica autonomamente la release: non serve scaricare né modificare file sul Pi.

## Design targets

- Initial target: Kali Linux ARM64 on Raspberry Pi 5 (8 GB), with a future AMD64 target.
- **Single** `kali-mcp.yml` Compose deployment, inspired by [Postmaster MCP](https://github.com/the-code-learner/mail-task-mcp-server).
- Multi-service internal architecture: non-root MCP/WebUI core, isolated privileged host broker, ephemeral sandbox workers.
- Dynamic tool registry: Kali tool adapters and installer recipes must **not** create new public MCP endpoints.
- Stable/beta GitHub Release channels; **automatic periodic update checks**, with manual install/health checks/rollback planned for a subsequent beta.
- OAuth authentication for remote MCP clients; Cloudflare Access for the administrative WebUI; same public hostname with narrowly scoped OAuth discovery/authorization exceptions.
- Persistent jobs, bounded stdout/stderr, audit events and live status; richer artifacts and PCAP previews are planned.
- Wi-Fi managed/AP, optional Nexmon, Ethernet DHCP/static/shared, NetworkManager checkpoints and rollback are planned; only basic status/scan is prototyped in the initial beta.
- A persistent, explicit WebUI toggle for host root execution, capped by the Compose deployment settings. **Disabled by default.**

## Critical trust boundary

The user has explicitly requested a privileged Docker deployment. A Docker `privileged: true` broker has effectively host-level authority. The WebUI root toggle is a **policy gate for authenticated MCP clients, not isolation from compromise of the broker itself**. The MCP HTTP core must never mount the Docker socket, the host root filesystem or run privileged.

For users operating this system, limit security assessments to systems and networks they own or have permission to test.

## Current implementation

- [kali-mcp.yml](kali-mcp.yml): experimental single-YAML Compose with a root-owned broker and non-root core.
- [docs/STATUS.md](docs/STATUS.md): verified vs. missing functionality.
- [docs/CLOUDFLARE.md](docs/CLOUDFLARE.md): one-hostname OAuth discovery and Access bypass plan.
- [docs/SECURITY.md](docs/SECURITY.md): trust boundaries and untested privileged paths.
- [docs/TESTING.md](docs/TESTING.md): CI and hardware validation steps.

**Do not enable host root or expose the MCP publicly until the documented
security and integration tests pass.** The version selector is currently
set to main for development. Release checks are automatic; installation
and rollback are still pending implementation.

## Roadmap

1. Exact Apache 2.0 licensing and Postmaster attribution.
2. Repository scaffold, versioning, tests, single-YAML bootstrapping and stable/beta resolver.
3. OAuth protected MCP endpoint and WebUI with administrative authentication.
4. Capability gates, persistent job engine, registry and results/audit storage.
5. Privileged host broker and safe execution/sandbox boundaries.
6. Wi-Fi/Ethernet/Nexmon adapter, tool packs, richer result presentation.

The deployment YAML and privileged execution paths will only be documented as supported after integration testing on Kali ARM64.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The `LICENSE` file is a verbatim copy of the license from Postmaster MCP; attribution to Postmaster is preserved in `NOTICE`.
