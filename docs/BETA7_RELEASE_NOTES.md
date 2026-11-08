# Kali MCP v0.1.0-beta.7 — WebUI origin and form submission fixes

This prerelease fixes the `{"error":"origin_mismatch"}` page reported when using **Updates → Check now** on the beta.6 dashboard. The application still requires CSRF tokens and validates Origin/Referer and Fetch Metadata for security-sensitive POSTs.

## Fixes

- The dashboard previously set `Referrer-Policy: no-referrer`, while the hardened ingress requires a verifiable **same-origin Referer** when Chrome sends `Origin: null` for a form POST. Dashboard responses now use `Referrer-Policy: same-origin`. This sends a Referer only to the same origin; it is not shared across sites.
- For browser form submissions blocked by the Origin safeguard, return a human-readable **Request blocked** page with a dashboard link instead of displaying raw JSON. Programmatic API callers continue to receive `{"error":"origin_mismatch"}`.
- Add regression coverage for a legitimate same-origin `Origin: null` request, missing Referer/Fetch Metadata, mismatched Origin and invalid CSRF token.

## Recovering legacy beta.4 installations

Some appliances upgraded from beta.4 were activated with the old installer, which did not write the `config.ready` completion marker. The beta.7 installer now validates the existing credential and settings files and atomically writes this marker **without changing them**. Incomplete or insecure configurations are not silently marked ready. This migration is exercised by regression tests and the hybrid release workflow.

If the old WebUI's forms are blocked by origin checks, the first upgrade to beta.7 must be run through SSH using the **beta.7 release installer**, not the old `/opt/kali-mcp/current/scripts/install-hybrid.sh`. After installation you can manage updates normally through the WebUI.

## Important: deployment origin must still match

`KALI_MCP_PUBLIC_URL` must be the exact HTTPS origin used to access the WebUI, without trailing path. If you open `https://kali-mcp.warebench.com`, the value must be `https://kali-mcp.warebench.com`. A misconfigured origin is **not** bypassed by this fix. You can inspect just that nonsecret setting via:

```bash
sudo grep '^KALI_MCP_PUBLIC_URL=' /etc/kali-mcp/stack.env
```

The update keeps OAuth, MCP API tokens, security ceilings and `--tools all` unchanged. Host Root and Host Exec are not required for authorized WebUI updates.

## Upgrade

Use the WebUI **Updates → Check now** after installing this release (or the SSH installer if an incorrect public-origin configuration prevents browser forms). Verify **Installed: v0.1.0-beta.7** in the dashboard rather than relying on an update job's `completed` state.

See the CI and hybrid installation checks for automated regression results. Physical device and Cloudflare integration still require validation.
