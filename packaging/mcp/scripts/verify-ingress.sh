#!/bin/sh
# verify-ingress.sh — probe a published MCP route through the public edge.
# Usage: OCLIV_SOURCE_REVISION=... OCLIV_ARTIFACT_SHA256=... OCLIV_RECEIPT_SIGNING_KEY=... ./verify-ingress.sh [--token-file=PATH] [--receipt=PATH] <route-url>
#   [MCP_CACERT=<ca-bundle>] [EXPECTED_TOOL=<name>]
#   The bearer comes from --token-file (preferred, 0600), MCP_TOKEN_FILE,
#   or MCP_TOKEN set in the environment — never from an inline
#   `MCP_TOKEN=...` command assignment (shell history would persist it).
# Route URL shape: https://<relay-host>[:port]/r/<route-id>/mcp
# Checks: OAuth metadata resource binding, missing-token 401, invalid-token
# 401, authenticated tools/list, and successful execution of a valid-token
# tool call. EXPECTED_TOOL defaults to "ping". Fails closed on any mismatch; prints nothing secret. Uses
# system roots unless MCP_CACERT names a lab bundle (verification is
# never disabled).
set -eu
TOKEN=""
ROUTE=""
RECEIPT=""
for arg in "$@"; do
  case "$arg" in
    --token-file=*) TOKEN_FILE="${arg#--token-file=}";;
    --token-file) echo "--token-file needs =PATH" >&2; exit 1;;
    --receipt=*) RECEIPT="${arg#--receipt=}";;
    *) ROUTE="$arg";;
  esac
done
ROUTE="${ROUTE:?usage: ./verify-ingress.sh [--token-file=PATH] <route-url>}"
if [ -n "${TOKEN_FILE:-}" ]; then
  TOKEN="$(cat "$TOKEN_FILE")"
fi
if [ -z "$TOKEN" ] && [ -n "${MCP_TOKEN_FILE:-}" ]; then
  TOKEN="$(cat "$MCP_TOKEN_FILE")"
fi
if [ -z "$TOKEN" ]; then
  TOKEN="${MCP_TOKEN:?set MCP_TOKEN, MCP_TOKEN_FILE, or --token-file=PATH to the upstream Bearer token}"
fi
TOOL="${EXPECTED_TOOL:-ping}"
JSON='Content-Type: application/json'
CURL="curl -sS --connect-timeout 5 --max-time 30"
_session_id=""
_protocol_version=""
_session_mode="uninitialized"
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
# A release receipt binds the public endpoint and qualification outcomes
# to exact source/artifact identities. The detached signature is made with
# an operator-controlled private key. Bearer tokens and response bodies
# are never written to either file.
write_receipt() {
  [ -n "$RECEIPT" ] || return 0
  SOURCE_REVISION="${OCLIV_SOURCE_REVISION:?set OCLIV_SOURCE_REVISION to the qualified source revision}"
  ARTIFACT_SHA256="${OCLIV_ARTIFACT_SHA256:?set OCLIV_ARTIFACT_SHA256 to the qualified binary SHA-256}"
  SIGNING_KEY="${OCLIV_RECEIPT_SIGNING_KEY:?set OCLIV_RECEIPT_SIGNING_KEY to the operator-held private key}"
  [ "${#ARTIFACT_SHA256}" -eq 64 ] || fail "artifact digest must be 64 hexadecimal characters"
  printf '%s' "$ARTIFACT_SHA256" | grep -Eq '^[0-9a-fA-F]{64}$' || fail "artifact digest must be hexadecimal"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required to sign a release receipt"
  [ -r "$SIGNING_KEY" ] || fail "receipt signing key is not readable"
  python3 - "$RECEIPT" "$ROUTE" "$TOOL" "$SOURCE_REVISION" "$ARTIFACT_SHA256" <<'PY'
import datetime, json, os, sys
path, route, tool, revision, digest = sys.argv[1:]
os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.fchmod(fd, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump({
        "route_url": route,
        "source_revision": revision,
        "artifact_sha256": digest.lower(),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "resource_discovery_verified": True,
        "authorization_server_discovery_verified": True,
        "missing_bearer_rejected": True,
        "invalid_bearer_rejected": True,
        "authenticated_tools_list_verified": True,
        "authenticated_tool_execution_verified": True,
        "tool": tool,
    }, f, sort_keys=True)
    f.write("\n")
PY
  openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$RECEIPT.sig" "$RECEIPT" \
    || fail "could not sign qualification receipt"
  chmod 600 "$RECEIPT.sig"
}
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
    if [ -n "${_session_id:-}" ]; then
      $CURL -i -X POST "$1" -H "Authorization: Bearer $TOKEN" -H "MCP-Session-Id: $_session_id" \
        -H "MCP-Protocol-Version: $_protocol_version" -H "Accept: application/json, text/event-stream" \
        -H "$JSON" -d "$2" -w '\n%{http_code}'
    elif [ -n "$_protocol_version" ]; then
      $CURL -i -X POST "$1" -H "Authorization: Bearer $TOKEN" \
        -H "MCP-Protocol-Version: $_protocol_version" -H "Accept: application/json, text/event-stream" \
        -H "$JSON" -d "$2" -w '\n%{http_code}'
    else
      $CURL -i -X POST "$1" -H "Authorization: Bearer $TOKEN" \
        -H "Accept: application/json, text/event-stream" -H "$JSON" -d "$2" -w '\n%{http_code}'
    fi
  else
    $CURL -i -X POST "$1" -H "Accept: application/json, text/event-stream" -H "$JSON" -d "$2" -w '\n%{http_code}'
  fi
}
_split() { # $1: _post output; sets _body and _code
  _code=$(printf '%s' "$1" | tail -n 1)
  _response=$(printf '%s' "$1" | sed '$d')
  _new_session_id=$(printf '%s\n' "$_response" | awk 'BEGIN{IGNORECASE=1} /^Mcp-Session-Id:/ {sub(/^[^:]*:[[:space:]]*/, ""); gsub(/[\r[:space:]]/, ""); value=$0} END{print value}')
  _new_protocol_version=$(printf '%s\n' "$_response" | awk 'BEGIN{IGNORECASE=1} /^Mcp-Protocol-Version:/ {sub(/^[^:]*:[[:space:]]*/, ""); gsub(/[\r[:space:]]/, ""); value=$0} END{print value}')
  if [ "$_session_mode" = "stateful" ] && [ -n "$_new_session_id" ] && [ "$_new_session_id" != "$_session_id" ]; then
    fail "MCP session ID changed during the qualified request sequence"
  fi
  if [ "$_session_mode" = "stateless" ] && [ -n "$_new_session_id" ]; then
    fail "MCP server introduced a session after stateless initialization"
  fi
  if [ -n "$_protocol_version" ] && [ -n "$_new_protocol_version" ] && [ "$_new_protocol_version" != "$_protocol_version" ]; then
    fail "MCP protocol version changed during the qualified request sequence"
  fi
  [ -z "$_new_session_id" ] || _session_id="$_new_session_id"
  _body=$(printf '%s\n' "$_response" | awk 'BEGIN{body=0} body {print} /^\r?$/ {body=1}')
  if printf '%s\n' "$_response" | grep -qi 'Content-Type:.*text/event-stream'; then
    _body=$(printf '%s' "$_body" | python3 -c 'import sys; s=sys.stdin.read(); events=s.split("\n\n"); print(next(("\n".join(x[5:].lstrip() for x in e.splitlines() if x.startswith("data:")) for e in events if any(x.startswith("data:") for x in e.splitlines())), ""))')
  fi
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
  [ "$(_json "$1" '.result.isError')" != "true" ] || return 1
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
AS_META="https://$HOST/.well-known/oauth-authorization-server/r/$RID/oauth"
AS_ISSUER="https://$HOST/r/$RID/oauth"

meta=$($CURL "$META") || fail "metadata unreachable"
[ "$(_json "$meta" '.resource')" = "$ROUTE" ] || fail "resource mismatch: $(short "$meta")"
asmeta=$($CURL "$AS_META") || fail "authorization-server metadata unreachable"
[ "$(_json "$asmeta" '.issuer')" = "$AS_ISSUER" ] || fail "authorization-server issuer mismatch: $(short "$asmeta")"

# 1. Missing token must be rejected by harmless tools/list.
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' no)"
[ "$_code" = "401" ] || fail "missing token -> $_code, want 401"

# 2. Wrong token must be rejected by the same harmless method.
_saved="$TOKEN"
TOKEN="wrong-token"
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' yes)"
TOKEN="$_saved"
[ "$_code" = "401" ] || fail "invalid token -> $_code, want 401"

# 3. Negotiate the MCP protocol/session before issuing authenticated calls.
# Stateless implementations may omit Mcp-Session-Id; stateful ones must
# retain and echo it on subsequent requests.
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ocliv-ingress-verifier","version":"1"}}}' yes)"
[ "$_code" = "200" ] || fail "initialize -> HTTP $_code: $(short "$_body")"
_check_rpc "$_body" "2" || fail "initialize returned bad JSON-RPC: $(short "$_body")"
_protocol_version="$(_json "$_body" '.result.protocolVersion')"
[ -n "$_protocol_version" ] || fail "initialize did not negotiate an MCP protocol version"
if [ -n "$_session_id" ]; then _session_mode="stateful"; else _session_mode="stateless"; fi
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","method":"notifications/initialized"}' yes)"
[ "$_code" = "200" ] || [ "$_code" = "202" ] || fail "initialized notification -> HTTP $_code"

# 4. Valid token must pass tools/list and expose the selected harmless tool.
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}' yes)"
[ "$_code" = "200" ] || fail "authenticated tools/list -> HTTP $_code: $(short "$_body")"
_check_rpc "$_body" "3" || fail "authenticated tools/list bad JSON-RPC: $(short "$_body")"
_tools="$(_json "$_body" '.result.tools[].name')"
[ -n "$_tools" ] || fail "authenticated tools/list returned no tools"
printf '%s\n' "$_tools" | grep -Fxq "$TOOL" || fail "selected tool '$TOOL' is absent from authenticated tools/list"

# 4. Valid token: execute a real harmless tool. A JSON-RPC result marked
#    isError is not successful execution and cannot produce a release receipt.
_is_notfound=0
_split "$(_post "$ROUTE" '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"'"$TOOL"'"}}' yes)"
if [ "$_code" != "200" ]; then
  fail "$TOOL over valid token -> HTTP $_code: $(short "$_body")"
fi
if _check_rpc "$_body" "4"; then
  if [ "$TOOL" = "ping" ] && [ -z "${EXPECTED_TOOL:-}" ]; then
    echo "$(_json "$_body" '.result')" | grep -q 'pong:' \
      || fail "ping result has no pong: $(short "$_body")"
  fi
  write_receipt
  echo "PASS: ingress verified ($ROUTE, tool $TOOL)"
  exit 0
fi

if [ "$_is_notfound" = "1" ]; then
  fail "tool '$TOOL' not found: $(short "$_body")"
fi
fail "$TOOL bad JSON-RPC response: $(short "$_body")"
