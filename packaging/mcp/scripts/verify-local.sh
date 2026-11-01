#!/bin/sh
# verify-local.sh — Gate-1 style probe of a loopback MCP server.
# Usage: MCP_TOKEN=<token> ./verify-local.sh [base-url]
# Fails closed on any mismatch; prints nothing secret.
set -eu
BASE="${1:-http://127.0.0.1:18766}"
TOKEN="${MCP_TOKEN:?set MCP_TOKEN to the server's bearer token}"
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
