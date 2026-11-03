# Current-head CI validation

This draft PR validates the current development head without authorizing a release.

The project requires a real Kali ARM64 host and Cloudflare integration test before user-facing deployment claims.

Current CI merge-base validation includes the administrator WebUI integration assertions recently added on main.

This validation also runs docker compose config --quiet for the single YAML deployment.

The current merge-base also exercises per-client isolation for persistent jobs and audit records.

OAuth regression coverage now verifies token-family revocation after refresh-token replay.

The latest merge checks OAuth replay revocation and HTML escaping of job output.
