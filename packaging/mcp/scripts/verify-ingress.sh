#!/bin/sh
# verify-ingress.sh — probe a published MCP route through the public edge.
# Usage: MCP_TOKEN=<token> [MCP_CACERT=<ca-bundle>] [EXPECTED_TOOL=<name>] ./verify-ingress.sh <route-url>
# Route URL shape: https://<relay-host>[:port]/r/<route-id>/mcp
# Checks: OAuth metadata resource binding, missing-token 401, invalid-token
# 401, and a valid-token JSON-RPC call. EXPECTED_TOOL defaults to "ping";
# when the default ping tool is absent the script falls back to probing
# tools/list. Fails closed on any mismatch; prints nothing secret. Uses
# system roots unless MCP_CACERT names a lab bundle (verification is
# never disabled).
set -eu
ROUTE="${1:?usage: MCP_TOKEN=<token> $0 <route-url>}"
TOKEN="${MCP_TOKEN:?set MCP_TOKEN to the upstream Bearer [REDACTED]}"
TOOL="${EXPECTED_TOOL:-ping}"
JSON='Content-Type: application/json'
CURL="curl -s"
if [ -n "${MCP_CACERT:-}" ]; then
  CURL="$CURL --cacert $MCP_CACERT"
fi

if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
elif command -v python3 >/dev/null 2>&1; then
  HAVE_JQ=0
else
  echo "FAIL: need jq or python3 for JSON parsing" >&2
  exit 2
fi

fail() { echo "FAIL: $1" >&2; exit 1; }
# Truncate untrusted output so logs stay small; never called with secrets.
short() { printf '%s' "$1" | cut -c1-500; }

# _json <document> <filter>: only the jq filters used below are supported
# by the python3 fallback (.a.b paths, has("k"), .result.tools[].name).
_json() {
  if [ "$HAVE_JQ" = "1" ]; then
    printf '%s' "$1" | jq -r "$2 // empty" 2>/dev/null || true
  else
    printf '%s' "$1" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
f = sys.argv[1]
if f.startswith("has("):
    key = f[5:-2].strip("\"")
    print("true" if isinstance(doc, dict) and key in doc else "false")
else:
    cur = doc
    try:
        for part in f.lstrip(".").split("."):
            if part == "tools[]":
                cur = cur["tools"]
                cur = "\n".join(str(t.get("name", "")) for t in cur)
                break
            cur = cur[part]
        if isinstance(cur, bool):
            print("true" if cur else "false")
        elif cur is None:
            print("")
        else:
            print(cur)
    except (KeyError, TypeError):
        pass
' "$2" || true
  fi
}

# _post <url> <data> <auth: yes|no>: print body, then "<http-code>" on last line.
_post() {
  if [ "${3:-no}" = "yes" ]; then
    $CURL -X POST "$1" -H "Authorization: Bearer $TOKEN" \
      -H "$JSON" -d "$2" -w '\n%{http_code}'
  else
    $CURL -X POST "$1" -H "$JSON" -d "$2" -w '\n%{http_code}'
  fi
}
_split() { # $1: _post output; sets _body and _code
  _code=$(printf '%s' "$1" | tail -n 1)
  _body=$(printf '%s' "$1" | sed '$d')
}
# _check_rpc <body> <want-id>: valid JSON-RPC 2.0 response with matching id
# and a result (no error). Sets _is_notfound when error is MethodNotFound.
_check_rpc() {
  [ "$(_json "$1" '.jsonrpc')" = "2.0" ] || return 1
  [ "$(_json "$1" '.id')" = "$2" ] || return 1
  if [ "$(_json "$1" 'has("error")')" = "true" ]; then
    if [ "$(_json "$1" '.error.code')" = "-32601" ]; then
      _is_notfound=1
    fi
    return 1
  fi
  [ "$(_json "$1" 'has("result")')" = "true" ] || return 1
  return 0
}

case "$ROUTE" in
  https://*/r/*/mcp) ;;
  *) fail "route URL must look like https://<host>[:port]/r/<route-id>/mcp" ;;
esac
HOST="$(echo "$ROUTE" | sed 's#^https://##; s#/r/.*##')"
RID="$(echo "$ROUTE" | sed 's#.*/r/##; s#/mcp$##')"
[ -n "$HOST" ] && [ -n "$RID" ] || fail "unparsable route URL"
META="https://$HOST/.well-known/oauth-protected-resource/r/$RID/mcp"

meta=$($CURL "$META") || fail "metadata unreachable"
[ "$(_json "$meta" '.resource')" = "$ROUTE" ] || fail "resource mismatch: $(short "$meta")"

# 1. Missing token must be rejected.
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"'"$TOOL"'"}}' no)"
[ "$_code" = "401" ] || fail "missing token -> $_code, want 401"

# 2. Wrong token must be rejected (same expectation as verify-local.sh).
_saved="$TOKEN"
TOKEN="wrong-token"
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"'"$TOOL"'"}}' yes)"
TOKEN="$_saved"
[ "$_code" = "401" ] || fail "invalid token -> $_code, want 401"

# 3. Valid token: JSON-RPC call, id echoed, result without error.
_is_notfound=0
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"'"$TOOL"'"}}' yes)"
if [ "$_code" != "200" ]; then
  fail "$TOOL over valid token -> HTTP $_code: $(short "$_body")"
fi
if _check_rpc "$_body" "2"; then
  if [ "$TOOL" = "ping" ] && [ -z "${EXPECTED_TOOL:-}" ]; then
    echo "$(_json "$_body" '.result')" | grep -q 'pong:' \
      || fail "ping result has no pong: $(short "$_body")"
  fi
  echo "PASS: ingress verified ($ROUTE, tool $TOOL)"
  exit 0
fi

# 4. Default-tool fallback: ping absent, but server lists tools fine.
if [ "$_is_notfound" = "1" ] && [ -z "${EXPECTED_TOOL:-}" ]; then
  _split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}' yes)"
  [ "$_code" = "200" ] || fail "tools/list -> HTTP $_code: $(short "$_body")"
  _check_rpc "$_body" "3" || fail "tools/list bad JSON-RPC: $(short "$_body")"
  [ -n "$(_json "$_body" '.result.tools[].name')" ] \
    || fail "tools/list returned no tools"
  echo "PASS: ingress verified ($ROUTE, via tools/list; no ping tool)"
  exit 0
fi
if [ "$_is_notfound" = "1" ]; then
  fail "tool '$TOOL' not found: $(short "$_body")"
fi
fail "$TOOL bad JSON-RPC response: $(short "$_body")"
