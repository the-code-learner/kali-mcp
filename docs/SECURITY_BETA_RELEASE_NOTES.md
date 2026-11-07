# Kali MCP v0.1.0-beta.4 — superuser and access hardening

Security-focused prerelease for the **systemd Host Agent + nonprivileged Docker Core** architecture.
The v0.1.0-beta.3 release and earlier privileged-Docker beta remain available but are legacy.

## First installation through SSH

Download and inspect the signed-by-GitHub-release asset and its checksum,
then start the interactive wizard:

```bash
curl -fsSL https://github.com/the-code-learner/kali-mcp/releases/download/v0.1.0-beta.4/install-hybrid.sh -o install-hybrid.sh
curl -fsSL https://github.com/the-code-learner/kali-mcp/releases/download/v0.1.0-beta.4/kali-mcp-hybrid.yml -o kali-mcp-hybrid.yml
curl -fsSL https://github.com/the-code-learner/kali-mcp/releases/download/v0.1.0-beta.4/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS
sudo bash install-hybrid.sh
```

The installer downloads Kali MCP automatically, initializes systemd, Docker
and persistent storage, and asks you to create a **named application superuser**.

On every login, WebUI requires both username and password. The CLI also
requires the same superuser credentials **after sudo**, including for read-only
status and jobs. Use `sudo kali-mcp` for the SSH text dashboard.

## Security improvements

- Superuser credentials created in the first-run SSH wizard.
- Scrypt salted password storage (N=131072, r=8, p=1); no plaintext admin
  password in Docker environment variables or the Agent's systemd unit.
- Root-owned credential record and read-only hash copy mounted in Docker.
- WebUI: username/password login, secure HttpOnly cookies, CSRF-protected
  logout/settings, brute-force throttling and session invalidation on password change.
- CLI: sudo PLUS superuser login; high-impact root toggles require explicit text confirmation.
- Host Agent independently verifies the superuser password for privilege changes.
  Core's access to the Unix socket alone cannot enable a root capability.
- Limits on HTTP payloads, login/registration/token rates, job queue and
  persistent terminal sessions; enhanced response security headers.
- Sensitive command arguments and script bodies redacted in stored job metadata.
- WebUI and SSH CLI can inventory registered MCP clients and revoke their
  access/refresh tokens immediately; credential rotation revokes all existing
  MCP tokens and authorization codes as well as browser sessions.
- OAuth client-specific jobs require an attributed client identity and fail
  closed if attribution is unavailable.
- Loopback-only host binding by default; optional 0.0.0.0 bind requires
  explicit wizard choice and HTTPS-origin + firewall acknowledgment.

## Upgrading from v0.1.0-beta.3

**Use the new beta.4 Bash installer from this release**, rather than running
`sudo kali-mcp upgrade` from beta.3. The old installer cannot run the
new credential migration.

The new script detects the former `KALI_MCP_ADMIN_PASSWORD`, creates the
named superuser hash, removes that plaintext value from the Stack environment,
preserves settings/jobs, and starts the updated Core.

You will be asked to save your new superuser password during an interactive
migration. Subsequent in-app updates can use the normal CLI/WebUI/MCP flow.

## Network access model

The only supported management entrypoints are:

- **CLI dashboard:** via SSH/sudo + application superuser.
- **WebUI:** browser session after named-superuser login (and Cloudflare Access
  with MFA for external access).
- **MCP:** Streamable HTTP endpoint `/mcp` requiring OAuth bearer and
  interactive superuser approval during client authorization.

Some OAuth discovery/registration/token paths must remain reachable for
protocol interoperability; these paths never grant shell access by themselves.

`0.0.0.0` does NOT inherently provide secure exposure. The Core HTTP port
must not be accessible on an untrusted network without a TLS reverse proxy
and firewall. Cloudflare Tunnel with Access remains the recommended option.

## Limits

No system can guarantee zero unauthorized access. Full root access intentionally
bypasses application isolation once authorized. A compromised control plane
or host agent remains high impact. Hosted Linux AMD64 CI is NOT a substitute
for Raspberry Pi 5 Kali ARM64, Cloudflare Access MFA, Nexmon/network tests,
security audit and independent penetration testing.

The older Docker-only installer still uses its legacy password mechanism; do
not expose that stack publicly. See docs/HYBRID.md and docs/SECURITY.md.
