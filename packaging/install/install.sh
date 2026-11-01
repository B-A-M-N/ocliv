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

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi
if [ -z "$DOMAIN" ]; then
  echo "usage: DOMAIN=<public relay domain> [MCP_HOST=<exact mcp host>] $0" >&2
  echo "  staging example: DOMAIN=ocliv.test ./install.sh" >&2
  exit 1
fi
case "$DOMAIN" in
  *example.com|*example.org|*example.net|"")
    echo "refusing placeholder domain: $DOMAIN" >&2
    exit 1
    ;;
esac

cd "$SRC_DIR"
NEW_BIN="$BIN.new.$$"
if ! go build -o "$NEW_BIN" ./cmd/ocliv 2>/dev/null; then
  rm -f "$NEW_BIN"
  echo "build failed in $SRC_DIR" >&2
  exit 1
fi
chmod 0755 "$NEW_BIN"
mv "$NEW_BIN" "$BIN"

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
} > "$ENV_FILE.new.$$"
mv "$ENV_FILE.new.$$" "$ENV_FILE"
chmod 0600 "$ENV_FILE"

install -m 0755 packaging/systemd/ocliv-relay-launch.sh "$LAUNCHER"
install -m 0644 packaging/systemd/ocliv-relay.service /etc/systemd/system/ocliv-relay.service
systemctl daemon-reload

# Preflight: binary runs, unit parses, domain configured.
if ! "$BIN" relay --help >/dev/null 2>&1 && ! "$BIN" --help >/dev/null 2>&1; then
  echo "warning: installed binary failed --help preflight" >&2
fi
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify /etc/systemd/system/ocliv-relay.service || {
    echo "unit verification failed" >&2
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
echo "NOT YET QUALIFIED on a clean host until install/restore tests pass (Gate E open)."
echo "next: edit /etc/caddy/Caddyfile, enroll operator key, then: systemctl enable --now ocliv-relay"
