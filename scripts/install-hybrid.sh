#!/usr/bin/env bash
# Kali MCP systemd hybrid installer. Run as root from an SSH terminal.
set -Eeuo pipefail
umask 077
ROOT=/opt/kali-mcp
CONFIG=/etc/kali-mcp
STATE=/var/lib/kali-mcp
REPO=the-code-learner/kali-mcp
CHANNEL="${KALI_MCP_RELEASE_CHANNEL:-beta}"
REF="${KALI_MCP_VERSION:-latest}"
NONINTERACTIVE=false
RECONFIGURE=false
RESUME=false
REPAIR=false
UPGRADE=false
PHASE=preflight
OLD=""
ACTIVATED=false

usage() {
  printf '%s\n' \
    'Usage: sudo bash install-hybrid.sh [--non-interactive] [--resume|--repair|--reconfigure|--upgrade]' \
    'Environment: KALI_MCP_RELEASE_CHANNEL=beta|stable, KALI_MCP_VERSION=latest|vX.Y.Z-beta.N' \
    'Once installed: sudo kali-mcp (SSH dashboard)'
}
for arg in "$@"; do
  case "$arg" in
    --non-interactive) NONINTERACTIVE=true ;;
    --reconfigure) RECONFIGURE=true ;;
    --resume) RESUME=true ;;
    --repair) REPAIR=true ;;
    --upgrade) UPGRADE=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument $arg" >&2; exit 2 ;;
  esac
done

test "$EUID" = "0" || { echo 'Installer requires sudo' >&2; exit 1; }
install -d -m 0700 /var/log/kali-mcp
LOG=/var/log/kali-mcp/install.log
touch "$LOG"
chmod 0600 "$LOG"
phase() {
  PHASE="$1"
  printf '%s phase=%s\n' "$(date -u +%FT%TZ)" "$PHASE" >> "$LOG"
}
on_error() {
  local code="$1" line="$2"
  printf '%s FAILED phase=%s line=%s exit=%s\n' "$(date -u +%FT%TZ)" "$PHASE" "$line" "$code" >> "$LOG"
  echo "Install failed in phase '$PHASE' (line $line, exit $code)." >&2
  echo "Review /var/log/kali-mcp/install.log; rerun with --resume or --repair." >&2
  exit "$code"
}
trap 'on_error "$?" "$LINENO"' ERR
phase preflight
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
command -v flock >/dev/null || { echo 'flock (util-linux) is required' >&2; exit 1; }
exec 9>"$CONFIG/.install.lock"
flock -n 9 || { echo 'Another Kali MCP installation is in progress' >&2; exit 1; }
phase prerequisites
install -d -m 0755 "$ROOT" "$ROOT/releases"
install -d -m 0750 -o 10001 -g 10001 "$STATE/core" "$STATE/venv"
install -d -m 0750 -o root -g 10001 "$STATE/auth"

# Never automatically remove a previous privileged Docker stack.
if docker ps --format '{{.Names}}' | grep -Fxq kali-mcp-broker; then
  echo 'Old privileged kali-mcp-broker is running. Stop the old Stack before migration.' >&2
  exit 1
fi

phase staging
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
    # mkdir() inherited root's restrictive umask (often 077): explicitly
    # normalize *only* code-directory traversal, never secrets in /etc or /var.
    for directory in (stage, *(p for p in stage.rglob("*") if p.is_dir())):
        directory.chmod(0o755)
    stage.rename(target)
finally:
    shutil.rmtree(stage,ignore_errors=True)
print(ref)
PY
)"
TARGET="$ROOT/releases/$SELECTED"
# Revalidate permissions on existing staged releases from earlier beta installers.
find "$TARGET" -type d -exec chmod 0755 {} +
chmod 0755 "$ROOT" "$ROOT/releases"
python3 - "$TARGET" "$HOST_USER" <<'PY'
import os, pwd, sys
path, host_user = sys.argv[1:]
for uid, gid in ((10001, 10001), (pwd.getpwnam(host_user).pw_uid, pwd.getpwnam(host_user).pw_gid)):
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            with open(os.path.join(path, "src/kali_mcp/runtime.py"), "rb") as source:
                source.read(1)
        except (OSError, PermissionError):
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise SystemExit(f"Release not readable by uid {uid}; check staging permissions")
PY
echo "Staged version: $SELECTED"
phase backup
# SQLite online backup preserves WAL-consistent job, OAuth and configuration data.
# Backups are root-only and never silently deleted during rollback/upgrade.
if test -f "$STATE/core/app.db"; then
  install -d -m 0700 "$STATE/backups"
  BACKUP="$STATE/backups/app-$(date -u +%Y%m%dT%H%M%SZ)-$.sqlite"
  KALI_MCP_DB_SOURCE="$STATE/core/app.db" KALI_MCP_DB_BACKUP="$BACKUP" python3 - <<'PY'
import os, sqlite3
source = sqlite3.connect("file:" + os.environ["KALI_MCP_DB_SOURCE"] + "?mode=ro", uri=True)
dest = sqlite3.connect(os.environ["KALI_MCP_DB_BACKUP"])
try:
    source.backup(dest)
finally:
    dest.close()
    source.close()
os.chmod(os.environ["KALI_MCP_DB_BACKUP"], 0o600)
PY
  sha256sum "$BACKUP" > "$BACKUP.sha256"
  chmod 0600 "$BACKUP.sha256"
  echo "Created SQLite upgrade safety backup: $BACKUP"
fi
phase wizard
OLD_SUPERUSER_FINGERPRINT="absent"
if test -f "$CONFIG/superuser.json"; then
  OLD_SUPERUSER_FINGERPRINT="$(sha256sum "$CONFIG/superuser.json" | cut -d' ' -f1)"
fi
VERIFY=(python3 "$TARGET/scripts/wizard.py" --config-dir "$CONFIG" --verify)
# Appliances originally installed by beta.4 have complete settings but no
# config.ready marker. During an upgrade, migrate only if every existing
# config/credential file passes the strict beta.7 validator. Do not run the
# interactive wizard from the detached systemd update unit and do not reset
# any deployment ceilings, superuser credentials, or MCP settings.
if test "$UPGRADE" = true && test ! -e "$CONFIG/config.ready" &&
   test -f "$CONFIG/stack.env" && test -f "$CONFIG/agent.env" &&
   test -f "$CONFIG/superuser.json"; then
  phase legacy-config-migration
  python3 "$TARGET/scripts/wizard.py" --config-dir "$CONFIG" --migrate-legacy
  phase wizard
fi
if ! "${VERIFY[@]}"; then
  if test "$NONINTERACTIVE" = false && test "$RECONFIGURE" = false &&
     test "$REPAIR" = false && test "$RESUME" = false && test "$UPGRADE" = false &&
     test -f "$CONFIG/superuser.json"; then
    echo 'Incomplete setup detected (no valid completion marker).'
    echo '  [r] Resume using existing credentials  [f] Repair  [c] Reconfigure  [q] Quit'
    read -r -p 'Choice [r]: ' choice
    case "${choice:-r}" in
      r|R) RESUME=true ;;
      f|F) REPAIR=true ;;
      c|C) RECONFIGURE=true ;;
      *) exit 1 ;;
    esac
  fi
fi
if test "$RECONFIGURE" = true || ! "${VERIFY[@]}"; then
  flags=(--config-dir "$CONFIG" --agent-gid "$GID" --host-user "$HOST_USER")
  if test "$NONINTERACTIVE" = true; then
    flags+=(--non-interactive)
  else
    test -t 0 || { echo 'Interactive SSH TTY required (or use --non-interactive)' >&2; exit 1; }
  fi
  python3 "$TARGET/scripts/wizard.py" "${flags[@]}"
else
  echo 'Reusing committed settings. Use --reconfigure to run the wizard.'
fi
"${VERIFY[@]}" || { echo 'Wizard did not produce a complete configuration' >&2; exit 1; }
# Preserve the explicitly selected DNS upstream from an already-running Core
# when upgrading from a beta that used a local Docker Compose override.
if test "$UPGRADE" = true; then
  python3 "$TARGET/scripts/preserve_core_dns.py" --config-dir "$CONFIG"
fi
"${VERIFY[@]}" || { echo 'DNS configuration migration failed validation' >&2; exit 1; }
chmod 0600 "$CONFIG"/*.env "$CONFIG/superuser.json" "$CONFIG/config.ready"
phase credentials
# Keep the canonical superuser hash root-only. Core receives an immutable,
# read-only copy; the Core never receives the password through Docker env.
install -m 0640 -o root -g 10001 "$CONFIG/superuser.json" "$STATE/auth/superuser.json"
if ! grep -q '^KALI_MCP_SUPERUSER_FILE=' "$CONFIG/agent.env"; then
  printf '%s\n' 'KALI_MCP_SUPERUSER_FILE=/etc/kali-mcp/superuser.json' >> "$CONFIG/agent.env"
fi
chmod 0600 "$CONFIG/agent.env"
NEW_SUPERUSER_FINGERPRINT="$(sha256sum "$CONFIG/superuser.json" | cut -d' ' -f1)"
if test "$NEW_SUPERUSER_FINGERPRINT" != "$OLD_SUPERUSER_FINGERPRINT" && test -f "$STATE/core/app.db"; then
  echo 'Superuser changed or migrated: revoking outstanding WebUI sessions and MCP OAuth tokens'
  KALI_MCP_CORE_DB="$STATE/core/app.db" python3 - <<'PY'
import os, sqlite3
db = sqlite3.connect(os.environ["KALI_MCP_CORE_DB"], timeout=20)
try:
    db.execute("PRAGMA busy_timeout=20000")
    with db:
        db.execute("UPDATE oauth_tokens SET revoked=1")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='api_tokens'").fetchone():
            db.execute("UPDATE api_tokens SET revoked=1")
        db.execute("DELETE FROM oauth_codes")
        db.execute("DELETE FROM admin_sessions")
finally:
    db.close()
PY
  for file in "$STATE/core/app.db" "$STATE/core/app.db-wal" "$STATE/core/app.db-shm"; do
    if test -e "$file"; then chown 10001:10001 "$file"; fi
  done
fi

phase native-dependencies
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
  printf '%s FAILED phase=%s exit=%s\n' "$(date -u +%FT%TZ)" "$PHASE" "$code" >> "$LOG"
  echo "Activation failed in phase '$PHASE'; retry with --repair" >&2
  if test "$ACTIVATED" = true && test -n "$OLD" && test -d "$OLD"; then
    echo "Activation failed; restoring previous release: $OLD" >&2
    ln -sfn "$OLD" "$ROOT/.rollback-link"
    mv -Tf "$ROOT/.rollback-link" "$ROOT/current"
    systemctl restart kali-mcp-agent.service || true
    run_core_compose up -d --force-recreate || true
  fi
  exit "$code"
}
# All Core recreation paths must share the same optional DNS overlay.
# The fallback is for rollback to a pre-DNS release that lacks the helper.
run_core_compose() {
  if test -f "$ROOT/current/scripts/compose-hybrid.sh"; then
    bash "$ROOT/current/scripts/compose-hybrid.sh" "$@"
  else
    docker compose --env-file "$CONFIG/stack.env" \
      -f "$ROOT/current/kali-mcp-hybrid.yml" "$@"
  fi
}
trap rollback ERR
phase activation
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
# Some Kali sudo secure_path settings omit /usr/local/bin. Provide a
# non-clobbering /usr/bin entry point rather than editing sudoers or PATH.
if test ! -e /usr/bin/kali-mcp && test ! -L /usr/bin/kali-mcp; then
  ln -s /usr/local/bin/kali-mcp /usr/bin/kali-mcp
fi

systemctl daemon-reload
systemctl enable kali-mcp-agent.service
systemctl restart kali-mcp-agent.service
for count in 1 2 3 4 5 6 7 8 9 10; do
  if test -S /run/kali-mcp-agent/agent.sock; then break; fi
  sleep 1
done
test -S /run/kali-mcp-agent/agent.sock
run_core_compose config --quiet
phase healthcheck
run_core_compose up -d --force-recreate --wait --wait-timeout 300
# A healthy HTTP listener alone does NOT prove the root Native Host Agent
# socket is reachable from the unprivileged Core. After a service restart,
# Docker may otherwise retain a stale bind mount of /run/kali-mcp-agent.
docker exec kali-mcp-core /opt/venv/bin/python -c \
  "import sys; sys.path.insert(0, '/opt/kali-mcp/current/src'); from kali_mcp.broker_client import call; assert call('/run/kali-mcp-agent/agent.sock','ping',timeout=8).get('broker') == 'systemd-host-agent'"
ACTIVATED=false
trap - ERR
echo
echo "Kali MCP hybrid installation successful: $SELECTED"
echo '  sudo /usr/local/bin/kali-mcp          interactive SSH dashboard'
echo '  sudo /usr/local/bin/kali-mcp status   systemd, Docker and MCP URL'
echo '  sudo /usr/local/bin/kali-mcp access   guided Cloudflare/Tailscale setup'
echo '  WebUI: http://localhost:8787 (local or SSH tunnel)'
echo 'Root is OFF until explicit administrator permission.'
