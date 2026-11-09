# Kali MCP v0.1.0-beta.15 — GitHub release verification visibility

This maintenance prerelease addresses the beta.13/beta.14 **Updates → Verify release** diagnostic gap: the Control Center could display **"Non verificata"** and an unconditional success toast even when GitHub lookup had failed or the selected channel had no eligible releases.

## Fixed

- `/api/v1/updates/check` now reports the real GitHub lookup result to the authenticated Control Center. Successful checks return the eligible release tag (if any); failures return **HTTP 503 with the underlying bounded diagnostic** instead of redirecting as if verification had succeeded.
- The Updates screen shows the **selected stable/beta channel** and the saved GitHub error when a lookup fails. A successful check with no matching release is clearly different from DNS/HTTP/TLS problems.
- The Check button communicates **verified release / no eligible release / lookup failed** accurately rather than giving a generic "request accepted" confirmation.
- Background status snapshots continue to read the cached checker result, preserving the actual failure reason for later page loads.
- GitHub HTTPS checks run in a worker thread so slow requests do not block the Core's ASGI event loop; also applied to manual update installation verification.
- Tests cover release selection, failed lookups, and the WebUI's JSON status and HTTP responses.

## Not changed

- The GitHub API remains the authoritative release source; this change **does not invent a release** if the appliance cannot reach `api.github.com`.
- There is **no new authentication bypass**, no automatic installation, no scope/CIDR change and no change to root/host permission controls.
- Beta.14 job cancellation/long polling and other capabilities remain included.

## Diagnose an existing beta.13 appliance

Before updating, in the Kali host's SSH session run:

```bash
sudo kali-mcp updates
```

This checks GitHub from the **host**. Then compare the Core network path without altering its configuration:

```bash
sudo docker exec kali-mcp-core /opt/venv/bin/python -c \
  "import sys; sys.path.insert(0, '/opt/kali-mcp/current/src'); from kali_mcp.releases import query_releases,select_release; print(select_release(query_releases('the-code-learner/kali-mcp'), 'beta'))"
```

If the host sees a release but the Core fails, investigate Core DNS/HTTPS egress, CA certificates or proxy settings. If the active channel is `stable`, no beta prerelease will be listed; select `beta` explicitly. Do not disable TLS verification.

## Upgrade

This version does not alter the installed Core until the operator upgrades. If the older WebUI cannot discover releases but the host can access GitHub, use **`sudo kali-mcp upgrade`** from an authenticated SSH session, review its confirmation prompt and then verify Core/Agent health. The versioned hybrid installer is also available on the [GitHub release page](https://github.com/the-code-learner/kali-mcp/releases/tag/v0.1.0-beta.15).

The CI release workflow validates the Python suite, JavaScript, Docker Compose, hybrid systemd/Docker smoke and the idempotent upgrade before publishing release assets. Real Raspberry Pi network connectivity is environment-specific and must be verified on the appliance.
