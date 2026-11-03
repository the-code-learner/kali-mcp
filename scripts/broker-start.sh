#!/bin/sh
set -eu
ROOT=/opt/kali-mcp/current
cd "$ROOT"
if ! command -v nsenter >/dev/null 2>&1 || ! command -v runuser >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends util-linux
  rm -rf /var/lib/apt/lists/*
fi
VENV_DIR=/opt/broker-venv
MARKER="$VENV_DIR/.requirements.sha256"
HASH="$(sha256sum "$ROOT/broker-requirements.txt" | awk '{print $1}')"
if [ ! -x "$VENV_DIR/bin/python" ] || [ ! -f "$MARKER" ] || [ "$(cat "$MARKER" 2>/dev/null)" != "$HASH" ]; then
  mkdir -p "$VENV_DIR"
  find "$VENV_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  python -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --disable-pip-version-check --no-cache-dir -r "$ROOT/broker-requirements.txt"
  printf '%s\n' "$HASH" > "$MARKER"
fi
export PYTHONPATH="$ROOT/src"
exec "$VENV_DIR/bin/python" -m kali_mcp.broker
