#!/usr/bin/env bash
# run-composed.sh — reproducible composed Ocliv -> Metis MCP demo.
#
# Publishes a real Metis MCP server through a loopback Ocliv relay (behind a
# local TLS edge standing in for Caddy) and proves the authenticated public
# route: discovery bound to the exact route URL, 15 metis_* tools with a
# valid audience-scoped JWT, 401 for a wrong-audience bearer, 401 for no
# bearer, and Metis's protocol-version rejection of 2025-06-18.
#
# Everything generated (keys, JWKS, resource binding, certificates, relay
# DB, logs) lives in a private 0700 temp dir outside the repo and is removed
# on exit unless KEEP_ARTIFACTS=1. No secret is ever printed. No repository
# is created or modified.
#
# The Locus inference leg (Metis Muse worker -> Locus gateway -> provider)
# is NOT exercised by this script and is always reported as NOT VERIFIED.
# Locus is an external, operator-gated dependency; this script never starts,
# stops, reconfigures, or writes to it.
#
# Exit codes: 0 all assertions passed, 1 any assertion or setup step failed,
# 2 missing prerequisite / bad environment.
#
# See tests/staging/composed/README.md for the runbook.

set -euo pipefail

umask 077

# ---------------------------------------------------------------- helpers

log()  { printf '%s\n' "$*"; }
note() { printf 'note: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

PASSES=0
FAILS=0

pass() { PASSES=$((PASSES + 1)); printf 'PASS  %s\n' "$*"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %s\n' "$*"; }

check_eq() { # label want got
  if [ "$2" = "$3" ]; then pass "$1 (got $3)"; else fail "$1 (want $2, got $3)"; fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

port_in_use() { # port -> 0 when something already listens on loopback
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

require_free_port() { # name port
  if port_in_use "$2"; then
    die "$1 port $2 is already in use on 127.0.0.1; choose another via its env var"
  fi
}

build_go() { # out pkg...
  local out="$1"; shift
  local blog="$WORK/build.log"
  if go build -o "$out" "$@" >"$blog" 2>&1; then
    return 0
  fi
  # A linked git worktree has .git as a plain file, so cmd/go cannot find a
  # VCS root for main packages. Normal checkouts never take this path.
  if grep -q 'obtaining VCS status\|buildvcs=false' "$blog"; then
    note "linked worktree detected; retrying go build with -buildvcs=false"
    if go build -buildvcs=false -o "$out" "$@" >"$blog" 2>&1; then
      return 0
    fi
  fi
  cat "$blog" >&2
  return 1
}

# ---------------------------------------------------------------- config

: "${METIS_BIN:=}"
: "${COMPOSED_TMP_ROOT:=${TMPDIR:-/tmp}}"
: "${EDGE_PORT:=19443}"      # public TLS edge (socat stand-in for Caddy)
: "${RELAY_PORT:=19470}"     # relay loopback listener
: "${HEALTH_PORT:=19471}"    # relay loopback health listener
: "${METIS_PORT:=19480}"     # Metis MCP loopback listener
: "${PUBLIC_HOST:=127.0.0.1}" # route/relay authority (lab only)
: "${DOMAIN:=ocliv.test}"    # relay --domain; placeholders example.com/net/org refused
: "${PUBLISH_NAME:=composed-demo}"
: "${PUBLISH_TTL:=15m}"
: "${ISSUER:=https://idp.example/oauth}"
: "${SCOPES:=metis:message metis:provision metis:input metis:stop}"
: "${STARTUP_WAIT_SECS:=30}"
: "${PUBLISH_WAIT_SECS:=60}"
: "${KEEP_ARTIFACTS:=0}"
: "${LOCUS_BASE_URL:=}"
: "${LOCUS_READONLY_PROBE:=0}"

[ -n "$METIS_BIN" ] || die "METIS_BIN is not set: point it at a Metis binary built from the Metis repo (see tests/staging/composed/README.md)"
[ -x "$METIS_BIN" ] || die "METIS_BIN is not an executable file: $METIS_BIN"

need_cmd go
need_cmd curl
need_cmd openssl
need_cmd socat
need_cmd python3

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
[ -f "$ROOT/go.mod" ] && [ -d "$ROOT/cmd/ocliv" ] || die "cannot locate the Ocliv repo root from $ROOT"
cd "$ROOT"

for p in "EDGE_PORT:$EDGE_PORT" "RELAY_PORT:$RELAY_PORT" "HEALTH_PORT:$HEALTH_PORT" "METIS_PORT:$METIS_PORT"; do
  require_free_port "${p%%:*}" "${p##*:}"
done

mkdir -p "$COMPOSED_TMP_ROOT"
WORK="$(mktemp -d "$COMPOSED_TMP_ROOT/composed-demo.XXXXXX")"
chmod 700 "$WORK"
mkdir -p "$WORK/home" "$WORK/metis-state" "$WORK/relay-data" "$WORK/idp"
chmod 700 "$WORK/home" "$WORK/metis-state" "$WORK/relay-data" "$WORK/idp"

PUBLISH_PID=""
EDGE_PID=""
RELAY_PID=""
METIS_PID=""

cleanup() {
  local st=$?
  trap - EXIT INT TERM
  set +e
  for p in "$PUBLISH_PID" "$EDGE_PID" "$RELAY_PID" "$METIS_PID"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null
  done
  sleep 0.5
  for p in "$PUBLISH_PID" "$EDGE_PID" "$RELAY_PID" "$METIS_PID"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null
  done
  if [ "$KEEP_ARTIFACTS" = "1" ]; then
    printf 'artifacts kept at %s\n' "$WORK" >&2
  else
    rm -rf "$WORK"
  fi
  exit "$st"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- build

log "== build =="
build_go "$WORK/ocliv" ./cmd/ocliv || die "ocliv build failed"
build_go "$WORK/metis-idp" ./tests/staging/metis-idp || die "metis-idp fixture build failed"
log "   ocliv + metis-idp built"

# ---------------------------------------------------------------- TLS edge material

log "== TLS edge material (lab CA, loopback SAN) =="
CA_PEM="$WORK/ca.pem"
(
  cd "$WORK"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca-key.pem -out ca.pem \
    -days 1 -subj "/CN=ocliv-composed-lab-ca" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr \
    -subj "/CN=$PUBLIC_HOST" >/dev/null 2>&1
  printf 'subjectAltName=IP:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    "$PUBLIC_HOST" > ext.cnf
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out server.pem -days 1 -extfile ext.cnf >/dev/null 2>&1
  cat server.pem server-key.pem > server-combined.pem
)
chmod 600 "$WORK"/*.pem
log "   CA + server certificate generated (1 day, SAN IP:$PUBLIC_HOST)"

"$WORK/metis-idp" genkey -dir "$WORK/idp" >"$WORK/idp/jwks.path"
JWKS_FILE="$(cat "$WORK/idp/jwks.path")"
[ -f "$JWKS_FILE" ] || die "metis-idp did not write a JWKS file"

# ---------------------------------------------------------------- Metis

log "== Metis MCP server (loopback :$METIS_PORT) =="
RESOURCE_FILE="$WORK/resource.txt"
: >"$RESOURCE_FILE"
chmod 600 "$RESOURCE_FILE"

(
  export HOME="$WORK/home"
  export XDG_CONFIG_HOME="$WORK/home/.config"
  export XDG_DATA_HOME="$WORK/home/.local/share"
  export METIS_MCP_ISSUER="$ISSUER"
  export METIS_MCP_JWKS_FILE="$JWKS_FILE"
  export METIS_MCP_RESOURCE_FILE="$RESOURCE_FILE"
  export METIS_STATE="$WORK/metis-state"
  export METIS_MCP_REMOTE_CAPABILITIES="admin,tasks,message"
  export MUSE_NO_AUTO_UPDATE=1
  exec "$METIS_BIN" mcp serve-http --listen "127.0.0.1:$METIS_PORT"
) >"$WORK/metis.log" 2>&1 &
METIS_PID=$!

metis_ready=0
for _ in $(seq 1 "$STARTUP_WAIT_SECS"); do
  if ! kill -0 "$METIS_PID" 2>/dev/null; then break; fi
  code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' -X POST \
    "http://127.0.0.1:$METIS_PORT/mcp" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' || true)"
  if [ "$code" != "000" ]; then metis_ready=1; break; fi
  sleep 1
done
[ "$metis_ready" = "1" ] || { cat "$WORK/metis.log" >&2; die "Metis did not become ready on 127.0.0.1:$METIS_PORT"; }
log "   Metis answering on http://127.0.0.1:$METIS_PORT/mcp"

# ---------------------------------------------------------------- relay + edge

log "== Ocliv relay (loopback :$RELAY_PORT) + TLS edge (:$EDGE_PORT) =="
(
  export HOME="$WORK/home"
  exec "$WORK/ocliv" relay serve \
    --listen="127.0.0.1:$RELAY_PORT" \
    --health-listen="127.0.0.1:$HEALTH_PORT" \
    --domain="$DOMAIN" \
    --relay-host="$PUBLIC_HOST" \
    --mcp-host="$PUBLIC_HOST" \
    --mcp-port="$EDGE_PORT" \
    --data="$WORK/relay-data"
) >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!

relay_ready=0
for _ in $(seq 1 "$STARTUP_WAIT_SECS"); do
  if ! kill -0 "$RELAY_PID" 2>/dev/null; then break; fi
  if [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HEALTH_PORT/health/live" || true)" = "200" ]; then
    relay_ready=1; break
  fi
  sleep 1
done
[ "$relay_ready" = "1" ] || { cat "$WORK/relay.log" >&2; die "relay health did not report ready on 127.0.0.1:$HEALTH_PORT"; }

socat "OPENSSL-LISTEN:$EDGE_PORT,reuseaddr,fork,cert=$WORK/server-combined.pem,verify=0" \
  "TCP:127.0.0.1:$RELAY_PORT" >"$WORK/edge.log" 2>&1 &
EDGE_PID=$!

edge_ready=0
for _ in $(seq 1 "$STARTUP_WAIT_SECS"); do
  code="$(curl -s -m 2 --cacert "$CA_PEM" -o /dev/null -w '%{http_code}' \
    "https://$PUBLIC_HOST:$EDGE_PORT/r/not-a-route/mcp" || true)"
  if [ "$code" != "000" ]; then edge_ready=1; break; fi
  sleep 1
done
[ "$edge_ready" = "1" ] || { cat "$WORK/edge.log" >&2; die "TLS edge did not answer on 127.0.0.1:$EDGE_PORT"; }
log "   relay ready; edge terminating TLS on https://$PUBLIC_HOST:$EDGE_PORT"

# ---------------------------------------------------------------- enroll + login

log "== enroll agent + login =="
export HOME="$WORK/home"
export OCLIV_CACERT="$CA_PEM"

"$WORK/ocliv" relay issue-enroll --data "$WORK/relay-data" --tenant composed >"$WORK/enroll.out" 2>&1 \
  || die "issue-enroll failed"
ENROLL_CODE="$(grep -o 'ocliv-enroll-[A-Za-z0-9._-]*' "$WORK/enroll.out" | head -1 || true)"
[ -n "$ENROLL_CODE" ] || die "could not read an enrollment code from issue-enroll output"
printf '%s' "$ENROLL_CODE" >"$WORK/code.txt"
chmod 600 "$WORK/code.txt"
unset ENROLL_CODE

"$WORK/ocliv" login --relay "https://$PUBLIC_HOST:$EDGE_PORT" --code-file "$WORK/code.txt" \
  >"$WORK/login.out" 2>&1 || { cat "$WORK/login.out" >&2; die "agent login failed"; }
log "   agent enrolled and logged in through the TLS edge"

# ---------------------------------------------------------------- publish

log "== publish Metis through the Ocliv route =="
export OCLIV_RELAY_URL="https://$PUBLIC_HOST:$EDGE_PORT"

"$WORK/ocliv" mcp publish \
  --local "http://127.0.0.1:$METIS_PORT/mcp" \
  --auth upstream-oauth \
  --name "$PUBLISH_NAME" \
  --ttl "$PUBLISH_TTL" \
  --resource-file "$RESOURCE_FILE" >"$WORK/publish.log" 2>&1 &
PUBLISH_PID=$!

ROUTE_URL=""
for _ in $(seq 1 "$PUBLISH_WAIT_SECS"); do
  ROUTE_URL="$(grep -E "^https://$PUBLIC_HOST:$EDGE_PORT/r/[^/]+/mcp$" "$WORK/publish.log" | tail -1 || true)"
  [ -n "$ROUTE_URL" ] && break
  if ! kill -0 "$PUBLISH_PID" 2>/dev/null; then break; fi
  sleep 1
done
if [ -z "$ROUTE_URL" ]; then
  cat "$WORK/publish.log" >&2
  die "publish did not print an active route URL"
fi
case "$ROUTE_URL" in
  "https://$PUBLIC_HOST:$EDGE_PORT/r/"*"/mcp") : ;;
  *) die "publish printed an unexpected route URL shape: $ROUTE_URL" ;;
esac
ROUTE_ID="${ROUTE_URL#https://$PUBLIC_HOST:$EDGE_PORT/r/}"
ROUTE_ID="${ROUTE_ID%/mcp}"
log "   published route: $ROUTE_URL"

if grep -q 'OAuth discovery verified' "$WORK/publish.log"; then
  pass "publish verified OAuth discovery (resource == route URL)"
else
  fail "publish did not report verified OAuth discovery"
fi
check_eq "resource binding handoff equals route URL" "$ROUTE_URL" "$(cat "$RESOURCE_FILE")"

# ---------------------------------------------------------------- tokens

mint() { # outfile aud scope
  "$WORK/metis-idp" token -privkey "$WORK/idp/key.pem" -iss "$ISSUER" -sub composed-operator \
    -aud "$2" -scope "$3" -exp 600 >"$1"
  chmod 600 "$1"
}

TOK_VALID="$WORK/tok-valid.jwt"
TOK_WRONG_AUD="$WORK/tok-wrong-aud.jwt"
mint "$TOK_VALID" "$ROUTE_URL" "$SCOPES"
mint "$TOK_WRONG_AUD" "https://$PUBLIC_HOST:$EDGE_PORT/r/wrong-route/mcp" "metis:message"

# Authorization header via a 0600 curl config file: the bearer never appears
# in curl's argv, and is never printed.
AUTH_VALID_CFG="$WORK/curl-auth-valid.cfg"
AUTH_WRONG_CFG="$WORK/curl-auth-wrong.cfg"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$TOK_VALID")" >"$AUTH_VALID_CFG"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$TOK_WRONG_AUD")" >"$AUTH_WRONG_CFG"
chmod 600 "$AUTH_VALID_CFG" "$AUTH_WRONG_CFG"

MCP_BODY='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

mcp_post() { # outfile authcfg|- protocol -> prints HTTP status
  local out="$1" cfg="$2" proto="$3"
  local args=(-sS -m 20 --cacert "$CA_PEM" -o "$out" -w '%{http_code}' -X POST "$ROUTE_URL"
    -H 'Content-Type: application/json'
    -H 'Accept: application/json, text/event-stream'
    -H "MCP-Protocol-Version: $proto"
    -d "$MCP_BODY")
  if [ "$cfg" != "-" ]; then args=(-K "$cfg" "${args[@]}"); fi
  curl "${args[@]}" || true
}

# ---------------------------------------------------------------- assertions

log ""
log "== assertions =="

# 1. RFC 9728 discovery names the exact published resource.
DISC_URL="https://$PUBLIC_HOST:$EDGE_PORT/.well-known/oauth-protected-resource/r/$ROUTE_ID/mcp"
DISC_CODE="$(curl -sS -m 20 --cacert "$CA_PEM" -o "$WORK/discovery.json" -w '%{http_code}' "$DISC_URL" || true)"
check_eq "protected-resource metadata answered 200" "200" "$DISC_CODE"
DISC_RESOURCE="$(python3 - "$WORK/discovery.json" <<'PY' || true
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("resource", ""))
except Exception:
    pass
PY
)"
check_eq "discovery advertises the published resource" "$ROUTE_URL" "$DISC_RESOURCE"

# 2. Authenticated tools/list returns the 15 metis_* tools.
CODE="$(mcp_post "$WORK/tools.json" "$AUTH_VALID_CFG" "2024-11-05")"
check_eq "tools/list with valid bearer answered 200" "200" "$CODE"
TOOL_LIST="$(python3 - "$WORK/tools.json" <<'PY' || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(",".join(sorted(t.get("name", "") for t in d.get("result", {}).get("tools", []))))
except Exception:
    pass
PY
)"
EXPECTED_TOOLS="metis_agents,metis_events,metis_muse_message,metis_muse_message_status,metis_projects,metis_provision,metis_reconcile,metis_report,metis_send,metis_session_stop,metis_status,metis_task_status,metis_tasks,metis_terminal,metis_terminal_input"
check_eq "tools/list returned exactly the 15 metis_* tools" "$EXPECTED_TOOLS" "$TOOL_LIST"

# 3. Wrong audience -> 401 (Metis validates aud == the resource Ocliv wrote).
CODE="$(mcp_post "$WORK/wrong-aud.json" "$AUTH_WRONG_CFG" "2024-11-05")"
check_eq "wrong-audience bearer rejected with 401" "401" "$CODE"

# 4. Missing bearer -> 401.
CODE="$(mcp_post "$WORK/no-auth.json" "-" "2024-11-05")"
check_eq "missing bearer rejected with 401" "401" "$CODE"

# 5. Metis protocol-version contract, observed through the published route.
CODE="$(mcp_post "$WORK/pv-2026.json" "$AUTH_VALID_CFG" "2026-07-28")"
check_eq "MCP-Protocol-Version 2026-07-28 answered 200" "200" "$CODE"
CODE="$(mcp_post "$WORK/pv-2025.json" "$AUTH_VALID_CFG" "2025-06-18")"
check_eq "MCP-Protocol-Version 2025-06-18 rejected with 400" "400" "$CODE"

# ---------------------------------------------------------------- Locus leg

log ""
if [ -n "$LOCUS_BASE_URL" ] && [ "$LOCUS_READONLY_PROBE" = "1" ]; then
  LCODE="$(curl -sS -m 10 -o "$WORK/locus-models.json" -w '%{http_code}' "${LOCUS_BASE_URL%/}/v1/models" || true)"
  if [ "$LCODE" = "200" ]; then
    pass "Locus read-only reachability (GET /v1/models -> 200)"
  else
    fail "Locus read-only reachability (GET /v1/models -> ${LCODE:-no response})"
  fi
  log "   Locus reachability is NOT inference proof: no Muse worker turn was run."
elif [ -n "$LOCUS_BASE_URL" ]; then
  log "   Locus endpoint supplied ($LOCUS_BASE_URL) but not probed (set LOCUS_READONLY_PROBE=1 for a read-only check)."
fi
log "Locus inference leg: NOT VERIFIED (operator-gated)"
log "   Metis's Muse worker was not started and no inference request was sent to Locus."
log "   Locus is not started, stopped, reconfigured, or written to by this script."

# ---------------------------------------------------------------- summary

log ""
log "== summary =="
log "public route : $ROUTE_URL"
log "metis tools  : 15"
log "assertions   : $PASSES passed, $FAILS failed"
log ""
log "Legs exercised by this run:"
log "  [x] Ocliv relay + TLS edge (socat lab stand-in for Caddy), loopback only"
log "  [x] Ocliv agent publish tunnel -> Metis MCP over loopback"
log "  [x] Metis JWT validation (iss/aud/scope) through the published route"
log "  [x] Authorization forwarded byte-identically (wrong-aud/missing -> 401)"
if [ -n "$LOCUS_BASE_URL" ]; then
  log "  [ ] Metis Muse worker -> Locus inference (endpoint configured, NOT exercised: NOT VERIFIED (operator-gated))"
else
  log "  [ ] Metis Muse worker -> Locus inference (NOT VERIFIED (operator-gated))"
fi
log "  [ ] Public DNS + ACME + real Caddy edge (NOT VERIFIED, operator-gated)"

if [ "$FAILS" -ne 0 ]; then
  log ""
  log "RESULT: FAIL ($FAILS assertion(s) failed)"
  exit 1
fi
log ""
log "RESULT: PASS"
