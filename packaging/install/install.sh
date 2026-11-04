#!/bin/sh
# Ocliv relay install. Run as root on the relay host.
# Usage: DOMAIN=relay.example.org [MCP_HOST=relay.example.org] ./install.sh
# Transactional: the binary, environment, launcher, and systemd unit are
# staged and validated BEFORE activation; any failure after activation
# starts restores the previous state (binary from $BIN.prev, env/launcher/
# unit from .ocliv-bak sidecars, newly created files removed). Idempotent:
# safe to re-run; never replaces the binary before the new one builds, and
# never starts the service (the operator enables it explicitly). Caddy
# validation failure rolls back exactly like a unit failure.
set -eu

SRC_DIR="${SRC_DIR:-/opt/ocliv}"
# Destination overrides (OCLIV_INSTALL_*) exist for hermetic tests: they
# default to the production paths and are never needed in production.
BIN="${OCLIV_INSTALL_BIN:-/usr/local/bin/ocliv}"
LAUNCHER="${OCLIV_INSTALL_LAUNCHER:-/usr/local/bin/ocliv-relay-launch.sh}"
DATA_DIR="${OCLIV_INSTALL_DATA_DIR:-/var/lib/ocliv}"
ENV_DIR="${OCLIV_INSTALL_ENV_DIR:-/etc/ocliv}"
ENV_FILE="${OCLIV_INSTALL_ENV_FILE:-$ENV_DIR/relay.env}"
UNIT_FILE="${OCLIV_INSTALL_UNIT_FILE:-/etc/systemd/system/ocliv-relay.service}"
CADDY_FILE="${OCLIV_INSTALL_CADDY_FILE:-/etc/caddy/Caddyfile}"
DOMAIN="${DOMAIN:-}"
MCP_HOST="${MCP_HOST:-}"
MCP_PORT="${MCP_PORT:-}"
RELAY_HOST="${RELAY_HOST:-}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi
if [ -z "$DOMAIN" ]; then
  echo "usage: DOMAIN=<public relay domain> [MCP_HOST=<exact mcp host>] [MCP_PORT=<edge port>] [RELAY_HOST=<control host>] $0" >&2
  echo "  staging example: DOMAIN=ocliv.test ./install.sh" >&2
  exit 1
fi
case "$DOMAIN" in
  *example.com|*example.org|*example.net|"")
    echo "refusing placeholder domain: $DOMAIN" >&2
    exit 1
    ;;
esac
# Hostnames are written raw into relay.env and word-split into the launch
# command, so reject anything outside the DNS label shape here instead of
# failing late at service startup (a typo must never become an env-file
# injection or a silently split flag).
valid_host() {
  # One trailing FQDN dot is tolerated (the relay trims it); everything
  # else must be strict DNS label shape.
  h="${1%.}"
  case "$h" in
    ""|-*|.*|*.|*-|*-.*|*.-*|*..*|*[!A-Za-z0-9.-]*)
      return 1
      ;;
  esac
  return 0
}
if ! valid_host "$DOMAIN"; then
  echo "refusing malformed domain: $DOMAIN" >&2
  exit 1
fi
for h in "$MCP_HOST" "$RELAY_HOST"; do
  if [ -n "$h" ] && ! valid_host "$h"; then
    echo "refusing malformed host: $h" >&2
    exit 1
  fi
done
if [ -n "$MCP_PORT" ]; then
  case "$MCP_PORT" in
    *[!0-9]*|"")
      echo "refusing malformed edge port: $MCP_PORT" >&2
      exit 1
      ;;
  esac
fi

# --- transactional helpers ---------------------------------------------------
# backup_managed records the previous state of one managed file: existing
# content is copied to <dst>.ocliv-bak, non-existence is journaled in
# <dst>.ocliv-bak.had (0 = absent before install). restore_managed puts the
# previous state back exactly; cleanup_backups drops the sidecars after a
# successful install. Failures before backup_managed ran are no-ops in
# restore_managed.
backup_managed() {
  _dst="$1"
  if [ -f "$_dst" ]; then
    cp -p "$_dst" "$_dst.ocliv-bak"
    printf '1' > "$_dst.ocliv-bak.had"
  else
    printf '0' > "$_dst.ocliv-bak.had"
  fi
}
restore_managed() {
  _dst="$1"
  if [ ! -f "$_dst.ocliv-bak.had" ]; then
    return 0
  fi
  if [ "$(cat "$_dst.ocliv-bak.had")" = "1" ]; then
    mv -f "$_dst.ocliv-bak" "$_dst"
  else
    rm -f "$_dst"
  fi
  rm -f "$_dst.ocliv-bak" "$_dst.ocliv-bak.had"
}
cleanup_backups() {
  rm -f "$ENV_FILE.ocliv-bak" "$ENV_FILE.ocliv-bak.had"
  rm -f "$LAUNCHER.ocliv-bak" "$LAUNCHER.ocliv-bak.had"
  rm -f "$UNIT_FILE.ocliv-bak" "$UNIT_FILE.ocliv-bak.had"
}

cd "$SRC_DIR"
BIN_HAD_PREV=0
if [ -f "$BIN" ]; then
  BIN_HAD_PREV=1
fi
NEW_BIN="$BIN.new.$$"
STAGED_ENV="$ENV_FILE.new.$$"
STAGED_LAUNCHER="$LAUNCHER.new.$$"
# systemd-analyze verify rejects unit filenames with suffixes, so the
# staged unit lives under a temp dir with its proper unit name.
STAGE_DIR="$(dirname "$UNIT_FILE")/.ocliv-stage.$$"
STAGED_UNIT="$STAGE_DIR/ocliv-relay.service"
cleanup_staged() {
  rm -f "$NEW_BIN" "$STAGED_ENV" "$STAGED_LAUNCHER" "$STAGED_UNIT"
  rmdir -- "$STAGE_DIR" 2>/dev/null || true
}
trap cleanup_staged EXIT INT TERM
if ! go build -o "$NEW_BIN" ./cmd/ocliv 2>/dev/null; then
  echo "build failed in $SRC_DIR" >&2
  exit 1
fi
chmod 0755 "$NEW_BIN"
# Validate the candidate before it replaces anything live.
if ! "$NEW_BIN" relay --help >/dev/null 2>&1 && ! "$NEW_BIN" --help >/dev/null 2>&1; then
  echo "candidate binary failed --help preflight; installed binary untouched" >&2
  exit 1
fi

# Stage the env, launcher, and unit candidates next to their destinations
# (same directory, so the activation mv is atomic) and validate them
# BEFORE activation. Nothing installed changes until every candidate
# passes; a failure here leaves the previous install byte-identical.
mkdir -p "$DATA_DIR" "$ENV_DIR" "$(dirname "$LAUNCHER")" "$(dirname "$UNIT_FILE")" "$STAGE_DIR"
umask 077
{
  echo "# Ocliv relay environment (root-owned). Staging: OCLIV_DOMAIN=ocliv.test."
  echo "OCLIV_DOMAIN=$DOMAIN"
  if [ -n "$MCP_HOST" ]; then
    echo "OCLIV_MCP_HOST=$MCP_HOST"
  fi
  if [ -n "$MCP_PORT" ]; then
    echo "OCLIV_MCP_PORT=$MCP_PORT"
  fi
  if [ -n "$RELAY_HOST" ]; then
    echo "OCLIV_RELAY_HOST=$RELAY_HOST"
  fi
} > "$STAGED_ENV"
chmod 0600 "$STAGED_ENV"
cp packaging/systemd/ocliv-relay-launch.sh "$STAGED_LAUNCHER"
chmod 0755 "$STAGED_LAUNCHER"
cp packaging/systemd/ocliv-relay.service "$STAGED_UNIT"
chmod 0644 "$STAGED_UNIT"
# Pre-activation unit check. systemd-analyze verify also stats ExecStart,
# which cannot exist on a clean host before activation — there it reports
# a bogus failure, so the check only runs when the launcher is already
# present; the post-activation verify (with full rollback) is the
# authoritative gate in all cases.
if command -v systemd-analyze >/dev/null 2>&1 && [ -f "$LAUNCHER" ]; then
  if ! systemd-analyze verify "$STAGED_UNIT" 2>/dev/null; then
    echo "staged unit failed systemd-analyze verify; installed files untouched" >&2
    exit 1
  fi
fi
# The operator's Caddyfile is validated pre-activation too: a bad edge
# config must never be combined with a half-upgraded install, and the
# failure path must not leave the new binary behind (P0 regression).
if command -v caddy >/dev/null 2>&1 && [ -f "$CADDY_FILE" ]; then
  if ! caddy validate --config "$CADDY_FILE" --adapter caddyfile >/dev/null 2>&1; then
    echo "caddy validation failed; fix $CADDY_FILE before enabling (installed files untouched)" >&2
    exit 1
  fi
fi

# Commit point. From here on, any failure restores the previous state.
# Preserve a rollback candidate before replacing a working install. The
# first candidate wins across consecutive upgrades: re-running the
# installer must not overwrite the pre-upgrade binary with an already
# upgraded one, or the original rollback point is silently lost.
preserve_rollback() {
  if [ -f "$BIN" ] && [ ! -f "$BIN.prev" ]; then
    cp -p "$BIN" "$BIN.prev"
  fi
}
rollback_bin() {
  if [ -f "$BIN.prev" ]; then
    mv -f "$BIN.prev" "$BIN"
    echo "restored previous binary from $BIN.prev" >&2
  elif [ "$BIN_HAD_PREV" = "0" ]; then
    rm -f "$BIN"
    echo "removed newly installed binary (no previous install)" >&2
  fi
}
rollback_all() {
  rollback_bin
  restore_managed "$ENV_FILE"
  restore_managed "$LAUNCHER"
  restore_managed "$UNIT_FILE"
  # Re-read the restored files so the manager does not keep the rolled-
  # back config in memory. Best effort: the rollback itself already
  # succeeded; a reload failure is reported, not fatal.
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || echo "warning: daemon-reload after rollback failed" >&2
  fi
}

if ! id ocliv >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin ocliv
fi
chown ocliv:ocliv "$DATA_DIR"
chmod 0700 "$DATA_DIR"
chmod 0700 "$ENV_DIR"
umask 077
backup_managed "$ENV_FILE"
backup_managed "$LAUNCHER"
backup_managed "$UNIT_FILE"
preserve_rollback
mv "$NEW_BIN" "$BIN"
mv "$STAGED_ENV" "$ENV_FILE"
chmod 0600 "$ENV_FILE"
mv "$STAGED_LAUNCHER" "$LAUNCHER"
mv "$STAGED_UNIT" "$UNIT_FILE"
trap - EXIT INT TERM
cleanup_staged
if ! systemctl daemon-reload; then
  echo "daemon-reload failed; rolling back install" >&2
  rollback_all
  exit 1
fi

# Post-activation checks verify the installed unit/edge. Any failure
# restores the full previous state (binary, env, launcher, unit).
if command -v systemd-analyze >/dev/null 2>&1; then
  if ! systemd-analyze verify "$UNIT_FILE"; then
    echo "unit verification failed; rolling back install" >&2
    rollback_all
    exit 1
  fi
fi
if command -v caddy >/dev/null 2>&1 && [ -f "$CADDY_FILE" ]; then
  if ! caddy validate --config "$CADDY_FILE" --adapter caddyfile; then
    echo "caddy validation failed; rolling back install" >&2
    rollback_all
    exit 1
  fi
fi
cleanup_backups

echo "installed $BIN; env $ENV_FILE (0600); data dir $DATA_DIR"
if [ -f "$BIN.prev" ]; then
  echo "rollback candidate preserved at $BIN.prev (restore manually if the new binary misbehaves)"
fi
echo "next: edit $CADDY_FILE, enroll operator key, then: systemctl enable --now ocliv-relay"
