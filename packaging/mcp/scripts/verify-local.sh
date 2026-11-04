#!/bin/sh
# verify-local.sh — Gate-1 style probe of a loopback MCP server.
# Usage: ./verify-local.sh [--token-file PATH] [base-url]
#   The bearer comes from --token-file (preferred, 0600), MCP_TOKEN_FILE,
#   or MCP_TOKEN set in the environment — never from an inline
#   `MCP_TOKEN=...` command assignment (shell history would persist it).
# Fails closed on any mismatch; prints nothing secret.
set -eu
TOKEN=""
BASE=""
for arg in "$@"; do
  case "$arg" in
    --token-file=*) TOKEN_FILE="${arg#--token-file=}";;
    --token-file) echo "--token-file needs =PATH" >&2; exit 1;;
    *) BASE="$arg";;
  esac
done
if [ -n "${TOKEN_FILE:-}" ]; then
  TOKEN="$(cat "$TOKEN_FILE")"
fi
if [ -z "$TOKEN" ] && [ -n "${MCP_TOKEN_FILE:-}" ]; then
  TOKEN="$(cat "$MCP_TOKEN_FILE")"
fi
if [ -z "$TOKEN" ]; then
  TOKEN="${MCP_TOKEN:?set MCP_TOKEN, MCP_TOKEN_FILE, or --token-file=PATH to the server's bearer token}"
fi
BASE="${BASE:-http://127.0.0.1:18766}"
JSON='Content-Type: application/json'

fail() { echo "FAIL: $1" >&2; exit 1; }

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" \
  -H "$JSON" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
[ "$code" = "401" ] || fail "missing token -> $code, want 401"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" \
  -H "Authorization: Bearer wrong" -H "$JSON" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
[ "$code" = "401" ] || fail "wrong token -> $code, want 401"

out=$(curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $TOKEN" \
  -H "$JSON" -d '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}')
echo "$out" | grep -q '"protocolVersion":"2026-07-28"' || fail "initialize: $out"

out=$(curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $TOKEN" \
  -H "$JSON" -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ping"}}')
echo "$out" | grep -q 'pong:' || fail "ping: $out"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" \
  -H "Authorization: Bearer $TOKEN" -H "$JSON" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}')
[ "$code" = "202" ] || fail "notification -> $code, want 202"

echo "PASS: local MCP verified ($BASE)"
