# Kali MCP v0.1.0-beta.9 — Safe WebUI reauthentication for capability forms

This prerelease addresses the raw browser response
`{"error":"Administrator login required"}` observed after submitting
**Execution capabilities → Enable/Disable** on a previously open dashboard.

## Changes

- When the administrator session cookie is expired, missing or invalidated, a
  **browser HTML form POST** now receives **303 See Other** to the superuser
  login page with an explanatory session-expired message.
- The failed POST is **discarded**. No attempted capability change is queued,
  enabled, disabled, retried or replayed automatically after login.
  The administrator must return to the dashboard, select the capability and
  confirm the operation again, including password and root disclaimer as before.
- The dashboard's asynchronous status check redirects to reauthentication on
  HTTP 401, avoiding an apparently usable page with inactive login credentials.
- CSRF failures and protected capability-setting errors display a navigable,
  safely escaped browser message, rather than a raw JSON document.
- Programmatic API clients continue to receive HTTP **401** with the original
  `{"error":"Administrator login required"}` JSON response, and retain the
  existing CSRF and error status contracts.
- Expiry and superuser credential rotation still invalidate browser sessions.
  Cookies retain their existing four-hour maximum and Secure, HttpOnly,
  SameSite=Lax attributes; no security checks were relaxed.

## What to do on beta.8 before upgrading

If a capability change shows the JSON login error, return to the main
dashboard, sign out if necessary, and sign back in to refresh the browser
cookie and CSRF token. Then reload the dashboard and repeat the intended
setting change. A failed 401 POST never enables the setting.

## Installation

Install this beta using the authenticated WebUI Updates panel, if available.
After service restart, verify **Installed: v0.1.0-beta.9**. The installer
preserves superuser credentials and persistent settings. As always, the
`core-upgrade` job only confirms scheduling; check the installed version
after the detached installer finishes.

## Scope and security

No OAuth PKCE, API token, MCP `/mcp` transport, `--tools all`, CORS,
systemd Host Agent, host/root privilege ceilings or Cloudflare settings are
changed. In particular, no Host Root or Host Exec permission is required to
repair an expired administrator session.

Regression tests exercise expired cookies, stale CSRF, credential rotation,
browser form redirect, API JSON contract and the non-execution of stale
capability changes. CI, the legacy Docker smoke and the hybrid systemd + Docker
smoke must pass before publishing.
