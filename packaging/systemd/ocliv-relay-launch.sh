#!/bin/sh
# Ocliv relay launcher for systemd. Adds --mcp-host only when the operator
# configured a non-empty OCLIV_MCP_HOST: passing an explicitly empty value
# would fail CLI validation and take down an otherwise healthy relay (P0-B).
# All other flags are fixed loopback-only by unit policy.
set -eu

BIN="${OCLIV_BIN:-/usr/local/bin/ocliv}"
LISTEN="${OCLIV_LISTEN:-127.0.0.1:8080}"
DATA_DIR="${OCLIV_DATA_DIR:-/var/lib/ocliv}"

if [ -z "${OCLIV_DOMAIN:-}" ]; then
  echo "ocliv-relay-launch: OCLIV_DOMAIN is unset (see /etc/ocliv/relay.env)" >&2
  exit 1
fi

# shellcheck disable=SC2086
if [ -n "${OCLIV_MCP_HOST:-}" ]; then
  exec "$BIN" relay serve --listen="$LISTEN" --data="$DATA_DIR" \
    --domain="$OCLIV_DOMAIN" --mcp-host="$OCLIV_MCP_HOST"
else
  exec "$BIN" relay serve --listen="$LISTEN" --data="$DATA_DIR" \
    --domain="$OCLIV_DOMAIN"
fi
