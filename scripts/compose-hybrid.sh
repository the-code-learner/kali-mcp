#!/usr/bin/env bash
# Canonical Core Compose invocation. Applies the optional per-container DNS
# overlay consistently across install, upgrade, rollback, WebUI edits and CLI.
set -Eeuo pipefail
ROOT=/opt/kali-mcp/current
ENV=/etc/kali-mcp/stack.env
test -r "$ENV" || { echo "Kali MCP stack.env is missing" >&2; exit 1; }
test -f "$ROOT/kali-mcp-hybrid.yml" || { echo "Kali MCP Compose file is missing" >&2; exit 1; }

files=(--env-file "$ENV" -f "$ROOT/kali-mcp-hybrid.yml")
dns_line="$(grep '^KALI_MCP_DNS_SERVER=' "$ENV" || true)"
dns_server="${dns_line#*=}"
if test -n "$dns_server"; then
  # Reject shell/Compose substitutions, loopback and invalid IP literals.
  # The address is read from the root-owned config; never from caller env.
  PYTHONPATH="$ROOT/src" python3 -c \
    'import sys; from kali_mcp.deployment_settings import normalize_dns_server; assert normalize_dns_server(sys.argv[1]) == sys.argv[1]' \
    "$dns_server"
  test -f "$ROOT/kali-mcp-hybrid-dns.yml" ||
    { echo "DNS overlay missing from installed source" >&2; exit 1; }
  files+=(-f "$ROOT/kali-mcp-hybrid-dns.yml")
  export KALI_MCP_DNS_SERVER="$dns_server"
else
  unset KALI_MCP_DNS_SERVER
fi
exec docker compose "${files[@]}" "$@"
