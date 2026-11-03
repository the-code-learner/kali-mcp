# Kali MCP

**Self-hosted Kali Linux MCP control plane with modular tools, network management, sandboxed execution, optional host execution and a live WebUI.**

> **Status: development prototype — not production ready.** A first single-YAML Compose file, MCP core, OAuth endpoints, WebUI, broker, source cache and tests exist, but end-to-end Raspberry Pi, privileged broker and Cloudflare validation are not complete. No stable release has been published.

## Design targets

- Initial target: Kali Linux ARM64 on Raspberry Pi 5 (8 GB), with a future AMD64 target.
- **Single** `kali-mcp.yml` Compose deployment, inspired by [Postmaster MCP](https://github.com/the-code-learner/mail-task-mcp-server).
- Multi-service internal architecture: non-root MCP/WebUI core, isolated privileged host broker, ephemeral sandbox workers.
- Dynamic tool registry: Kali tool adapters and installer recipes must **not** create new public MCP endpoints.
- Stable/beta GitHub Release channels; **automatic periodic checks, manual installation only**, health checks and rollback.
- OAuth authentication for remote MCP clients; Cloudflare Access for the administrative WebUI; same public hostname with narrowly scoped OAuth discovery/authorization exceptions.
- Persistent jobs, stdout/stderr, artifacts, audit events, network status and live operation monitoring.
- Wi-Fi managed/AP, optional Nexmon, Ethernet DHCP/static/shared, NetworkManager checkpoints and rollback.
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
