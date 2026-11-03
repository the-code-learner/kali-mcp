#!/bin/sh
set -eu
ROOT=/opt/kali-mcp/current
cd "$ROOT"
VENV_DIR=/opt/venv
MARKER="$VENV_DIR/.requirements.sha256"
HASH="$(sha256sum "$ROOT/requirements.txt" | awk '{print $1}')"
if [ ! -x "$VENV_DIR/bin/python" ] || [ ! -f "$MARKER" ] || [ "$(cat "$MARKER" 2>/dev/null)" != "$HASH" ]; then
  mkdir -p "$VENV_DIR"
  find "$VENV_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  python -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --disable-pip-version-check --no-cache-dir -r "$ROOT/requirements.txt"
  printf '%s\n' "$HASH" > "$MARKER"
fi
export PYTHONPATH="$ROOT/src"
exec "$VENV_DIR/bin/python" -m kali_mcp.runtime
