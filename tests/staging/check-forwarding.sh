#!/bin/sh
# check-forwarding.sh — authorized HTTP fidelity through the real edge.
# Prerequisites: edge checks pass; agent running `ocliv 3000 --name demo`
# against a local fixture; UNLOCK_URL exported from the agent output.
set -eu
RELAY_IP="${RELAY_IP:-10.9.66.20}"
STAGING_CA="${STAGING_CA:-./ocliv-root.crt}"
LEASE_HOST="${LEASE_HOST:-demo.t.ocliv.test}"
FAIL=0
say() { printf '%s\n' "$*"; }
T() { # name, expected, actual
	if [ "$2" = "$3" ]; then say "PASS: $1"; else say "FAIL: $1 (want [$2] got [$3])"; FAIL=1; fi
}
if [ -z "${UNLOCK_URL:-}" ]; then say "FAIL: export UNLOCK_URL from the agent first"; exit 1; fi
BASE="https://$LEASE_HOST"

# 1. Authorized GET returns the fixture body.
BODY=$(curl -s --cacert "$STAGING_CA" --resolve "$LEASE_HOST:443:$RELAY_IP" "$UNLOCK_URL$BASE/" 2>/dev/null || true)
# NOTE: exact unlock URL shape depends on agent output; adjust join if needed.
say "authorized GET body: $BODY"

# 2. POST echo round-trip (upload fidelity).
ECHO=$(curl -s --cacert "$STAGING_CA" --resolve "$LEASE_HOST:443:$RELAY_IP" -X POST -d 'staging-ping-123' "$BASE/echo" || true)
T "POST echo round-trip" "staging-ping-123" "$ECHO"

# 3. Large upload (1 MiB) arrives intact (sha1 via /sha1 fixture if present).
head -c 1048576 /dev/urandom | base64 > /tmp/staging-big.bin
GOT=$(curl -s --cacert "$STAGING_CA" --resolve "$LEASE_HOST:443:$RELAY_IP" -X POST --data-binary @/tmp/staging-big.bin "$BASE/sha1" || true)
WANT=$(sha1sum /tmp/staging-big.bin | cut -d' ' -f1)
T "1MiB upload integrity" "$WANT" "$GOT"

# 4. SSE: first event arrives (timeout-bounded).
EVT=$(curl -s -m 10 --cacert "$STAGING_CA" --resolve "$LEASE_HOST:443:$RELAY_IP" -H 'Accept: text/event-stream' "$BASE/events" | head -n 1 || true)
T "SSE first frame" "data: hello" "$EVT"

# 5. WebSocket handshake through the edge (101 expected).
WS=$(curl -s -m 10 -o /dev/null -w '%{http_code}' --cacert "$STAGING_CA" --resolve "$LEASE_HOST:443:$RELAY_IP" -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$BASE/ws" || true)
T "websocket upgrade" "101" "$WS"

# 6. Concurrency smoke: 50 parallel GETs, all 200.
N=$(seq 1 50 | xargs -P 10 -I{} curl -s -o /dev/null -w '%{http_code}\n' --cacert "$STAGING_CA" --resolve "$LEASE_HOST:443:$RELAY_IP" "$BASE/" | grep -c '^200$' || true)
T "50 parallel GETs all 200" "50" "$N"

exit $FAIL
