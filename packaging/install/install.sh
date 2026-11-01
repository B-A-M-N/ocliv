#!/bin/sh
# Ocliv relay install. Run as root on the relay host.
# Usage: DOMAIN=relay.example.org [MCP_HOST=relay.example.org] ./install.sh
# Idempotent: safe to re-run; never replaces the binary before the new one
# builds, and never starts the service (the operator enables it explicitly).
set -eu

SRC_DIR="${SRC_DIR:-/opt/ocliv}"
BIN="/usr/local/bin/ocliv"
LAUNCHER="/usr/local/bin/ocliv-relay-launch.sh"
DATA_DIR="/var/lib/ocliv"
ENV_DIR="/etc/ocliv"
ENV_FILE="$ENV_DIR/relay.env"
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

cd "$SRC_DIR"
NEW_BIN="$BIN.new.$$"
if ! go build -o "$NEW_BIN" ./cmd/ocliv 2>/dev/null; then
  rm -f "$NEW_BIN"
  echo "build failed in $SRC_DIR" >&2
  exit 1
fi
chmod 0755 "$NEW_BIN"
# Validate the candidate before it replaces anything live.
if ! "$NEW_BIN" relay --help >/dev/null 2>&1 && ! "$NEW_BIN" --help >/dev/null 2>&1; then
  rm -f "$NEW_BIN"
  echo "candidate binary failed --help preflight; installed binary untouched" >&2
  exit 1
fi
# Preserve a rollback candidate before replacing a working install.
if [ -f "$BIN" ]; then
  cp -p "$BIN" "$BIN.prev"
fi
mv "$NEW_BIN" "$BIN"
rollback_bin() {
  if [ -f "$BIN.prev" ]; then
    mv -f "$BIN.prev" "$BIN"
    echo "restored previous binary from $BIN.prev" >&2
  fi
}

if ! id ocliv >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin ocliv
fi
mkdir -p "$DATA_DIR"
chown ocliv:ocliv "$DATA_DIR"
chmod 0700 "$DATA_DIR"

mkdir -p "$ENV_DIR"
chmod 0700 "$ENV_DIR"
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
} > "$ENV_FILE.new.$$"
mv "$ENV_FILE.new.$$" "$ENV_FILE"
chmod 0600 "$ENV_FILE"

install -m 0755 packaging/systemd/ocliv-relay-launch.sh "$LAUNCHER"
install -m 0644 packaging/systemd/ocliv-relay.service /etc/systemd/system/ocliv-relay.service
systemctl daemon-reload

# Post-activation checks: the candidate was already validated before
# the move, so these verify the installed unit/edge. A unit failure
# after replacement restores the rollback candidate.
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify /etc/systemd/system/ocliv-relay.service || {
    echo "unit verification failed" >&2
    rollback_bin
    exit 1
  }
fi
if command -v caddy >/dev/null 2>&1 && [ -f /etc/caddy/Caddyfile ]; then
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile || {
    echo "caddy validation failed; fix /etc/caddy/Caddyfile before enabling" >&2
    exit 1
  }
fi

echo "installed $BIN; env $ENV_FILE (0600); data dir $DATA_DIR"
if [ -f "$BIN.prev" ]; then
  echo "rollback candidate preserved at $BIN.prev (restore manually if the new binary misbehaves)"
fi
echo "NOT YET QUALIFIED on a clean host until install/restore tests pass (Gate E open)."
echo "next: edit /etc/caddy/Caddyfile, enroll operator key, then: systemctl enable --now ocliv-relay"
