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
# --relay-host overrides the relay.<domain> control authority for public
# hostnames not named relay.<domain> (e.g. temporary *.ts.net Funnel
# ingress, where the funnel hostname must match the control authority
# as well as the MCP authority). Like --mcp-host, it is passed only
# when explicitly configured; an empty value would fail validation.
ARGS="relay serve --listen=$LISTEN --data=$DATA_DIR --domain=$OCLIV_DOMAIN"
if [ -n "${OCLIV_RELAY_HOST:-}" ]; then
  ARGS="$ARGS --relay-host=$OCLIV_RELAY_HOST"
fi
if [ -n "${OCLIV_MCP_HOST:-}" ]; then
  ARGS="$ARGS --mcp-host=$OCLIV_MCP_HOST"
fi
# Optional non-443 public edge port minted into route URLs (lab Caddy on
# 8444). The relay CLI rejects a port with no --mcp-host, so a stray
# OCLIV_MCP_PORT fails closed at startup instead of minting silently.
if [ -n "${OCLIV_MCP_PORT:-}" ]; then
  ARGS="$ARGS --mcp-port=$OCLIV_MCP_PORT"
fi
# shellcheck disable=SC2086
exec $BIN $ARGS
