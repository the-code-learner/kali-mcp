# Kali MCP documentation index

**Current version: [v0.1.0-beta.14](https://github.com/the-code-learner/kali-mcp/releases/tag/v0.1.0-beta.14).** Start from the [project README](../README.md) for the supported installation path.

The project has two architectural generations. Documentation for the old **privileged-Docker single-YAML** release is retained for historical reference; the current recommendation is the **native systemd Host Agent + unprivileged Docker Core** hybrid installation. Do not follow the old beta.2 Portainer guide for new installs.

## Current guides (beta.14 published / beta.15 candidate)

| Document | Purpose |
| --- | --- |
| [Hybrid installation and operations](HYBRID.md) | Versioned installer, SSH wizard, superuser, CLI, remote access, updates and recovery |
| [Implementation and validation status](STATUS.md) | Evidence-graded feature matrix: implemented, CI-verified, field-observed, incomplete |
| [Security architecture](SECURITY.md) | Native Agent trust boundary, access controls, permitted scope and residual risk |
| [Developer and Raspberry Pi testing](TESTING.md) | Python/CI commands, hybrid checks and physical ARM64 acceptance checklist |
| [Cloudflare, OAuth and browser MCP](CLOUDFLARE.md) | Narrow Access path policy, origins, tokens, browser CORS and signed transfer links |
| [MCP file transfers](MCP_FILE_TRANSFERS.md) | Current Base64/OpenLink contract and retention/size limits (introduced in beta.10) |
| [Beta.14 release notes](BETA14_RELEASE_NOTES.md) | Published historical beta.14 milestone |
| [Beta.15 candidate notes](BETA15_RELEASE_NOTES.md) | Recovery from GitHub DNS errors, optional Core DNS and migration-safe upgrade |

The [project CHANGELOG](../CHANGELOG.md) records major milestones. Source code, current tests and actual running settings take precedence over archived descriptions when there is a difference.

## Historical documents (preserved as release snapshots)

These pages document earlier releases. Their commands, capability claims and architecture **are not current guidance**:

| Era | Historical references |
| --- | --- |
| Beta.1–2, early privileged-Docker / Portainer | [Portainer guide](BETA.md), [original release notes](BETA_RELEASE_NOTES.md) |
| Beta.3, initial hybrid installer | [Hybrid beta notes](HYBRID_BETA_RELEASE_NOTES.md) |
| Beta.4, named superuser/security migration | [Security beta notes](SECURITY_BETA_RELEASE_NOTES.md) |
| Beta.5–9 | [5](BETA5_RELEASE_NOTES.md) · [6](BETA6_RELEASE_NOTES.md) · [7](BETA7_RELEASE_NOTES.md) · [8](BETA8_RELEASE_NOTES.md) · [9](BETA9_RELEASE_NOTES.md) |
| Beta.10–13 | [10](BETA10_RELEASE_NOTES.md) · [11](BETA11_RELEASE_NOTES.md) · [12](BETA12_RELEASE_NOTES.md) · [13](BETA13_RELEASE_NOTES.md) |

Historic release notes are **not rewritten retroactively**. They explain what was true at publication, while the current guides above explain what is implemented now.

## Documentation maintenance rules

1. A new beta should update the version/entry points in the root README, index and [STATUS.md](STATUS.md), and create immutable release notes.
2. Validate installer flags and CLI examples against `scripts/install-hybrid.sh` and `src/kali_mcp/cli.py`; validate MCP tools against `src/kali_mcp/server.py`.
3. Distinguish a merged implementation from GitHub-hosted CI verification and from real Raspberry Pi/ARM64 acceptance.
4. Never present intentional `allow_all_targets` settings as automatically unsafe or invalid; document deny-first typed-adapter scope and the separate unrestricted host-shell boundary.
5. Keep secrets and private deployment values out of docs. Use example domains, no actual API tokens, Cloudflare tunnel secrets or privileged `.env` contents.
6. Verify links and release asset names before merging changes to `main`.

If there is an inconsistency, open a GitHub issue with the affected file and a minimal redacted reproduction; do not upload superuser credentials, OpenLink URLs or live API keys.
