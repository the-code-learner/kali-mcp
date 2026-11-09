# Kali MCP v0.1.0-beta.15 — Reliable update discovery and Core DNS recovery

This prerelease addresses a real Raspberry Pi 5/Kali upgrade case: the beta.13 host CLI could discover beta.14, but the unprivileged Docker Core could not resolve `api.github.com`. The Control Center showed **"Non verificata"**, even after the operator restored Core DNS, until a fresh check was performed.

## Fixed

- **Release-check feedback:** the protected `/api/v1/updates/check` endpoint returns the actual GitHub result or an actionable HTTP 503 diagnostic. It no longer reports unconditional success on a DNS/HTTP error.
- **Automatic recovery:** failed background GitHub release checks retry with bounded 30 → 60 → 120 → 240 → 300-second backoff, rather than waiting up to six hours for the usual successful-check interval. A manually requested check bypasses the backoff.
- **Dashboard clarity:** the Overview and Updates screens distinguish verified, unverified, empty-channel and failed GitHub lookups, show the selected channel, and provide an estimated retry time after failure.
- **Optional per-Core upstream DNS:** `KALI_MCP_DNS_SERVER` is a validated IPv4/IPv6 literal, chosen by the operator in the SSH wizard or authenticated deployment settings. Empty preserves Docker's normal DNS. A separate Compose overlay applies it **only to `kali-mcp-core`**, never the whole Docker daemon or Raspberry host.
- **Upgrade persistence:** a beta.15 installer invoked with `--upgrade` can preserve an already configured, single explicit DNS server from the running Core's Docker `HostConfig.Dns`. The setting is carried into root-owned hybrid deployment files before the Core is recreated; it survives later Core restarts, browser-origin changes and upgrades.
- **Regression tests:** failed GitHub checks/backoff, explicit DNS validation, wizard persistence, overlay rendering, standard hybrid smoke and Core-to-Agent IPC.

No target CIDR, allow-all, host/root permission, auth or Cloudflare policy is changed. A permissive network scope remains an intentional operator decision for authorized tests.

## Upgrading a beta.14 appliance that uses a local DNS override

**Important:** beta.14's bundled CLI upgrade invokes **the old beta.14 installer**, which does not know how to preserve `dns.override.yml`. For a first transition to beta.15, use the **verified beta.15 release installer** instead of the old CLI's `upgrade` command. The new installer discovers the existing explicit Core DNS, migrates it and applies its new Compose overlay.

On the Kali host over SSH, with no active assessment job:

```bash
mkdir -p ~/kali-mcp-beta15 && cd ~/kali-mcp-beta15
TAG=v0.1.0-beta.15
BASE="https://github.com/the-code-learner/kali-mcp/releases/download/$TAG"
curl -fL --retry 3 -o install-hybrid.sh "$BASE/install-hybrid.sh"
curl -fL --retry 3 -o kali-mcp-hybrid.yml "$BASE/kali-mcp-hybrid.yml"
curl -fL --retry 3 -o SHA256SUMS "$BASE/SHA256SUMS"
sha256sum --check SHA256SUMS
sudo env KALI_MCP_VERSION="$TAG" KALI_MCP_RELEASE_CHANNEL=beta \
  bash ./install-hybrid.sh --upgrade
```

The installer performs a SQLite backup and checks the Core/Agent after recreation. It does not replace Docker daemon DNS, host resolver files or your selected network scope.

Afterward:

```bash
readlink -f /opt/kali-mcp/current
sudo docker inspect kali-mcp-core \
  --format 'DNS={{json .HostConfig.Dns}} Health={{.State.Health.Status}}'
sudo docker exec kali-mcp-core /opt/venv/bin/python -c \
  'import socket; print("GitHub DNS:", socket.gethostbyname("api.github.com"))'
sudo docker exec -e PYTHONPATH=/opt/kali-mcp/current/src kali-mcp-core \
  /opt/venv/bin/python -c \
  'from kali_mcp.broker_client import call; print(call("/run/kali-mcp-agent/agent.sock","ping",timeout=5))'
```

Check **Control Center → Aggiornamenti → Verifica release**. If the DNS server changes with a new DHCP network, edit `KALI_MCP_DNS_SERVER` in the authenticated Control Center and verify the Core's active DNS. Local DNS may be necessary to resolve private services; no public DNS is assumed.

## Limitations

A DNS override is not a firewall, proxy or guaranteed fix for blocked HTTPS egress. It does not diagnose all HTTP failures, repair an unreachable upstream DNS or make a privileged host shell subject to typed-adapter CIDR restrictions. A host HTTP healthcheck alone is not proof of the Core-to-Agent socket; verify both after any upgrade.
