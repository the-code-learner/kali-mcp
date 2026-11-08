# Kali MCP v0.1.0-beta.13 — Native Host Agent socket recovery and safe scope editing

This prerelease fixes regressions discovered on a real Raspberry Pi 5 running beta.12. In that session systemd reported the Native Host Agent **active**, but the Core reported `Broker unavailable: FileNotFoundError` and the new Control Center showed `Agent offline` and `0/0 variables`. Recreating only the Core restored the IPC ping, supporting the stale Docker bind-mount diagnosis.

## Fixed: agent socket remains visible across systemd restarts

- `systemd/kali-mcp-agent.service` now sets `RuntimeDirectoryPreserve=yes` for `/run/kali-mcp-agent`. This keeps the **directory inode** stable when the service restarts. The unprivileged Core mounts the directory read-only; it does not receive new host or root permissions.
- The installer verifies a **real IPC ping from inside the Core**, rather than treating a healthy HTTP endpoint as sufficient.
- The authenticated deployment-settings worker similarly verifies Core-to-Agent IPC after a service restart, before reporting settings applied.
- A new hybrid CI gate restarts the Agent **twice** while keeping the Core running, verifies the directory device/inode match and the real authenticated socket connection, and checks the Core remains healthy.

## Fixed: Control Center accurately reports offline configuration

- If Native Host Agent settings cannot be read, **All Settings** lists the known variables as **unavailable**, rather than showing an empty inventory or inventing defaults. All mutation controls are disabled. Secret values stay masked.
- The snapshot distinguishes Agent reachability from authoritative deployment-inventory availability. When Agent is unavailable, it separately reports the actual **running Core's effective CIDR policy** for diagnosis.
- Scope editing preserves CIDRs typed by the operator during scheduled application and Core restarts. A successful form request now returns **HTTP 202 Scheduled** for SPA requests, not a misleading success after a redirect.
- The UI only declares the scope **applied** when the Native Agent inventory, running Core's effective scope and deployment worker status all agree. It reports rollback/unverified outcomes explicitly.
- The IPv4 preview remains labelled as a **local simulation**, not evidence that the CIDR blacklist is enforced by host shells or firewall.

## Safe upgrade

Upgrade through **Updates → Check now** after confirming this release is listed. The existing beta.12 update path launches the previous detached supervisor; the beta.13 worker's monitoring and directory-preservation fixes take effect after its installation and service restart.

The only confirmed production recovery in the reported case was to recreate the Core container, without reinstalling or changing the `.env` files. After upgrading to beta.13, verify **Core online · Agent online**, that **All Settings** shows the actual configured variables, and `192.168.137.0/24` is persisted and reflected by `capabilities_get` (not merely shown as a local preview).

This release does **not** add host-wide egress firewall enforcement: denied CIDRs apply to typed Kali adapters; unrestricted Host Exec/terminal can bypass typed-adapter scope. Leave those capabilities disabled if host-wide isolation is required.

## Validation

GitHub CI must pass Python tests, JavaScript syntax checks, Docker smoke, and hybrid systemd/Docker smoke. The hybrid gate includes the extra **two Agent restarts with the same Core process** as well as idempotent upgrades, OAuth 2.0, API Bearer, CORS, 100 MB file-transfer contracts and existing privilege boundaries. Real-world Cloudflare integration must still be verified on the Raspberry.
