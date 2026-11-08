# Kali MCP v0.1.0-beta.6 — WebUI Update Clarity

This prerelease follows v0.1.0-beta.5 and leaves the OAuth, API tokens, native Host Agent, permission ceilings, and `--tools all` behavior unchanged.

## Improvements

- **Installed vs latest:** The WebUI Updates panel displays the release version of the **currently running Core** separately from the newest eligible GitHub Release.
- **Actionable permission guidance:** When WebUI upgrade is disabled, the interface explains whether the native Host Agent, the deployment ceiling `KALI_MCP_ALLOW_MCP_UPDATES`, or the administrator's **MCP Updates** toggle is blocking it.
- **No-op protection:** The WebUI disables the installation button when no newer version can be verified and rejects attempts to install the same or an older release.
- **Clear scheduling semantics:** Clicking Install requests a detached systemd upgrade. A job marked completed means **the upgrade was scheduled**, not that the new release was installed. Verify completion when the dashboard displays the new **Installed** version after Core restarts.
- **Usable browser errors:** Blocked update requests now render a human-readable page with navigation back to the dashboard instead of a raw JSON error document.
- **Browser cache refresh:** The version-specific dashboard script URL avoids stale JavaScript after upgrade.

## Upgrade

On an existing v0.1.0-beta.5 hybrid appliance with update installation authorized, use the WebUI **Updates** panel to install the latest eligible release. If no installation is allowed, enable the deployment ceiling through the SSH wizard and the **MCP Updates** toggle with superuser approval. The installer preserves the existing configuration and creates a WAL-consistent SQLite backup.

Check the **Installed** field on the dashboard after services restart. `Latest available` alone is **not** evidence that an upgrade succeeded.

This prerelease passed CI, Docker and hybrid systemd/Docker smoke checks. Physical hardware, Cloudflare and llama.cpp browser behavior should still be validated on your deployment.
