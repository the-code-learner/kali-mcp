#!/usr/bin/env bash
# Kali MCP systemd hybrid installer. Run as root from an SSH terminal.
set -Eeuo pipefail
umask 077
ROOT=/opt/kali-mcp
CONFIG=/etc/kali-mcp
STATE=/var/lib/kali-mcp
REPO=the-code-learner/kali-mcp
CHANNEL="\${KALI_MCP_RELEASE_CHANNEL:-beta}"
REF="\${KALI_MCP_VERSION:-latest}"
NONINTERACTIVE=false
RECONFIGURE=false
OLD=""
ACTIVATED=false

usage() {
  printf '%s\n' \
    'Usage: sudo bash install-hybrid.sh [--non-interactive] [--reconfigure] [--upgrade]' \
    'Environment: KALI_MCP_RELEASE_CHANNEL=beta|stable, KALI_MCP_VERSION=latest|vX.Y.Z-beta.N' \
    'Once installed: sudo kali-mcp (SSH dashboard)'
}
for arg in "$@"; do
  case "$arg" in
    --non-interactive) NONINTERACTIVE=true ;;
    --reconfigure) RECONFIGURE=true ;;
    --upgrade) : ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument $arg" >&2; exit 2 ;;
  esac
done

test "$EUID" = "0" || { echo 'Installer requires sudo' >&2; exit 1; }
command -v systemctl >/dev/null && test -d /run/systemd/system ||
  { echo 'systemd as PID 1 is required' >&2; exit 1; }
case "$(uname -m)" in aarch64|x86_64) : ;; *) echo 'ARM64 or AMD64 required' >&2; exit 1 ;; esac
command -v apt-get >/dev/null || { echo 'Kali/Debian apt-get required' >&2; exit 1; }
case "$CHANNEL" in stable|beta) : ;; *) echo 'Invalid release channel' >&2; exit 2 ;; esac
echo "Kali MCP Hybrid · SSH installer · channel $CHANNEL"
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  apt-get update
  apt-get install -y python3 python3-venv curl
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3-venv
fi
if ! command -v docker >/dev/null; then
  echo 'Installing Docker Engine (Kali package: docker.io)'
  apt-get update
  apt-get install -y docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get update
  apt-get install -y docker-compose-plugin || apt-get install -y docker-compose-v2
fi
docker compose version >/dev/null
systemctl enable --now docker.service
if ! getent group kalimcp >/dev/null; then groupadd --system kalimcp; fi
GID="$(getent group kalimcp | cut -d: -f3)"
test -n "$GID"
if id kali >/dev/null 2>&1; then
  HOST_USER=kali
else
  HOST_USER=kalimcp-run
  if ! id kalimcp-run >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin kalimcp-run
  fi
fi
install -d -m 0700 "$CONFIG"
install -d -m 0755 "$ROOT" "$ROOT/releases"
install -d -m 0750 -o 10001 -g 10001 "$STATE/core" "$STATE/venv"

# Never automatically remove a previous privileged Docker stack.
if docker ps --format '{{.Names}}' | grep -Fxq kali-mcp-broker; then
  echo 'Old privileged kali-mcp-broker is running. Stop the old Stack before migration.' >&2
  exit 1
fi

echo 'Downloading staged GitHub source release (validated archive)'
SELECTED="$(
  KALI_SOURCE_ROOT="$ROOT" KALI_SOURCE_REPO="$REPO" \
  KALI_SOURCE_REF="$REF" KALI_SOURCE_CHANNEL="$CHANNEL" python3 - <<'PY'
import io
import json
import os
import re
import shutil
import stat
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath
root=Path(os.environ["KALI_SOURCE_ROOT"])
repo=os.environ["KALI_SOURCE_REPO"]
ref=os.environ["KALI_SOURCE_REF"]
channel=os.environ["KALI_SOURCE_CHANNEL"]
headers={"Accept":"application/vnd.github+json","User-Agent":"Kali-MCP-hybrid-installer"}
if ref=="latest":
    req=urllib.request.Request(f"https://api.github.com/repos/{repo}/releases?per_page=100",headers=headers)
    with urllib.request.urlopen(req,timeout=25) as response:
        rows=json.load(response)
    candidates=[]
    for row in rows:
        tag=str(row.get("tag_name",""))
        match=re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?",tag)
        if not match or row.get("draft"): continue
        is_beta=bool(row.get("prerelease")) or match.group(4) is not None
        if channel=="stable" and is_beta: continue
        candidates.append(((int(match.group(1)),int(match.group(2)),int(match.group(3)),
            0 if is_beta else 1,int(match.group(4) or 0)),tag))
    if not candidates: raise SystemExit("No eligible GitHub release for selected channel")
    ref=max(candidates)[1]
if not re.fullmatch(r"(?:main|v\d+\.\d+\.\d+(?:-beta\.\d+)?|[a-f0-9]{40})",ref):
    raise SystemExit("Invalid release tag")
target=root/"releases"/ref
if (target/".source-ready").exists():
    print(ref)
    raise SystemExit(0)
stage=root/"releases"/(".staging-"+str(os.getpid()))
stage.mkdir(parents=True,mode=0o700,exist_ok=False)
try:
    req=urllib.request.Request(f"https://codeload.github.com/{repo}/tar.gz/{ref}",headers=headers)
    with urllib.request.urlopen(req,timeout=60) as response:
        data=response.read(64*1024*1024+1)
    if len(data)>64*1024*1024: raise RuntimeError("Source archive exceeds 64MiB")
    with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as archive:
        members=archive.getmembers()
        if len(members)>5000: raise RuntimeError("Too many archive entries")
        if sum(m.size for m in members if m.isfile())>96*1024*1024:
            raise RuntimeError("Expanded archive exceeds 96MiB")
        roots={m.name.split("/",1)[0] for m in members}
        if len(roots)!=1: raise RuntimeError("Bad archive root")
        prefix=next(iter(roots))
        for member in members:
            path=PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or path.parts[0]!=prefix:
                raise RuntimeError("Unsafe archive path")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise RuntimeError("Unsupported archive member")
            if len(path.parts)==1: continue
            location=stage.joinpath(*path.parts[1:])
            if member.isdir():
                location.mkdir(parents=True,exist_ok=True)
            else:
                if member.size>8*1024*1024: raise RuntimeError("Oversized file")
                location.parent.mkdir(parents=True,exist_ok=True)
                source=archive.extractfile(member)
                if source is None: raise RuntimeError("Unreadable archive member")
                with source, location.open("wb") as output: shutil.copyfileobj(source,output)
                location.chmod(0o755 if member.mode & stat.S_IXUSR else 0o644)
    needed=("scripts/wizard.py","scripts/start.sh","kali-mcp-hybrid.yml",
            "systemd/kali-mcp-agent.service","src/kali_mcp/host_agent.py")
    for entry in needed:
        if not (stage/entry).is_file(): raise RuntimeError("Hybrid component missing: "+entry)
    (stage/".source-ready").write_text(ref+"\n",encoding="utf-8")
    stage.chmod(0o755)
    stage.rename(target)
finally:
    shutil.rmtree(stage,ignore_errors=True)
print(ref)
PY
)"
TARGET="$ROOT/releases/$SELECTED"
echo "Staged version: $SELECTED"
if test ! -f "$CONFIG/stack.env" || test "$RECONFIGURE" = true; then
  if test "$NONINTERACTIVE" = true; then
    python3 "$TARGET/scripts/wizard.py" --config-dir "$CONFIG" --agent-gid "$GID" --non-interactive
  else
    test -t 0 || { echo 'Interactive SSH TTY required (or use --non-interactive)' >&2; exit 1; }
    python3 "$TARGET/scripts/wizard.py" --config-dir "$CONFIG" --agent-gid "$GID"
  fi
else
  echo 'Reusing stored settings. Use --reconfigure to launch the wizard again.'
fi
sed -i "s/^KALI_MCP_HOST_USER=.*/KALI_MCP_HOST_USER=$HOST_USER/" "$CONFIG/agent.env"
if ! grep -q "^KALI_MCP_HOST_USER=" "$CONFIG/agent.env"; then
  echo "KALI_MCP_HOST_USER=$HOST_USER" >> "$CONFIG/agent.env"
fi
chmod 0600 "$CONFIG"/*.env

echo 'Installing native Agent Python dependencies'
if test ! -x "$ROOT/agent-venv/bin/python"; then python3 -m venv "$ROOT/agent-venv"; fi
"$ROOT/agent-venv/bin/python" -m pip install --disable-pip-version-check \
  -r "$TARGET/broker-requirements.txt"

if test -L "$ROOT/current"; then
  OLD="$(readlink -f "$ROOT/current")"
elif test -e "$ROOT/current"; then
  echo 'Refusing to overwrite non-symlink /opt/kali-mcp/current' >&2
  exit 1
fi
rollback() {
  code=$?
  trap - ERR
  if test "$ACTIVATED" = true && test -n "$OLD" && test -d "$OLD"; then
    echo "Activation failed; restoring previous release: $OLD" >&2
    ln -sfn "$OLD" "$ROOT/.rollback-link"
    mv -Tf "$ROOT/.rollback-link" "$ROOT/current"
    systemctl restart kali-mcp-agent.service || true
    docker compose --env-file "$CONFIG/stack.env" -f "$ROOT/current/kali-mcp-hybrid.yml" \
      up -d --force-recreate || true
  fi
  exit "$code"
}
trap rollback ERR
ln -sfn "$TARGET" "$ROOT/.next-link"
mv -Tf "$ROOT/.next-link" "$ROOT/current"
ACTIVATED=true
install -m 0644 "$TARGET/systemd/kali-mcp-agent.service" \
  /etc/systemd/system/kali-mcp-agent.service
cat > /usr/local/bin/kali-mcp <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/kali-mcp/current
export PYTHONPATH=/opt/kali-mcp/current/src:/opt/kali-mcp/current
exec /opt/kali-mcp/agent-venv/bin/python -m kali_mcp.cli "$@"
WRAPPER
chmod 0755 /usr/local/bin/kali-mcp

systemctl daemon-reload
systemctl enable kali-mcp-agent.service
systemctl restart kali-mcp-agent.service
for count in 1 2 3 4 5 6 7 8 9 10; do
  if test -S /run/kali-mcp-agent/agent.sock; then break; fi
  sleep 1
done
test -S /run/kali-mcp-agent/agent.sock
docker compose --env-file "$CONFIG/stack.env" -f "$ROOT/current/kali-mcp-hybrid.yml" config --quiet
docker compose --env-file "$CONFIG/stack.env" -f "$ROOT/current/kali-mcp-hybrid.yml" \
  up -d --wait --wait-timeout 300
ACTIVATED=false
trap - ERR
echo
echo "Kali MCP hybrid installation successful: $SELECTED"
echo '  sudo kali-mcp          interactive SSH dashboard'
echo '  sudo kali-mcp status   systemd, Docker and MCP URL'
echo '  sudo kali-mcp access   guided Cloudflare/Tailscale setup'
echo '  WebUI: http://localhost:8787 (local or SSH tunnel)'
echo 'Root is OFF until explicit administrator permission.'
