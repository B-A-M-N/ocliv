#!/bin/sh
# check-edge.sh — TLS trust, hostname routing, unauthorized denial.
# Usage: RELAY_IP=10.9.66.20 STAGING_CA=./ocliv-root.crt LEASE_HOST=demo.t.ocliv.test sh check-edge.sh
set -eu
RELAY_PORT="${RELAY_PORT:-443}"
RELAY_IP="${RELAY_IP:-10.9.66.20}"
STAGING_CA="${STAGING_CA:-./ocliv-root.crt}"
LEASE_HOST="${LEASE_HOST:-demo.t.ocliv.test}"
FAIL=0
say() { printf '%s\n' "$*"; }
check() { # name, expected-code, actual-code
	if [ "$2" = "$3" ]; then say "PASS: $1 ($3)"; else say "FAIL: $1 (want $2 got $3)"; FAIL=1; fi
}

# 1. Relay authority answers on HTTPS with the staging CA (challenge needs POST; 4xx proves TLS+route, not failure).
CODE=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$STAGING_CA" --resolve "relay.ocliv.test:${RELAY_PORT}:$RELAY_IP" "https://relay.ocliv.test:${RELAY_PORT}/v1/agent/challenge" || true)
[ "$CODE" = "400" ] || [ "$CODE" = "405" ] || [ "$CODE" = "415" ] || FAIL=1
say "relay challenge endpoint over trusted TLS: HTTP $CODE"

# 2. Untrusted client must fail closed (no --cacert, no -k).
if curl -s -o /dev/null -w '%{http_code}' --resolve "relay.ocliv.test:${RELAY_PORT}:$RELAY_IP" "https://relay.ocliv.test:${RELAY_PORT}/v1/agent/challenge" 2>/dev/null; then
	say "FAIL: untrusted TLS succeeded"; FAIL=1
else
	say "PASS: untrusted TLS refused"
fi

# 3. Unknown hostname fails closed without reaching the app.
CODE=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$STAGING_CA" --resolve "nope.t.ocliv.test:${RELAY_PORT}:$RELAY_IP" https://nope.t.ocliv.test:${RELAY_PORT}/ || true)
check "unknown tunnel host" "404" "$CODE"

# 4. Wrong SNI vs Host: SNI for relay authority, Host for unknown.
# Observed Caddy behavior: unmatched Host is absorbed at the edge as an
# empty 200 with NO `via` header (proxied relay responses always carry
# `via: 1.1 Caddy`). Either that or a relay-style 4xx both prove the
# request never reached a tunnel; a `via` header or non-empty body fails.
RESP=$(curl -s -D - -o /tmp/ocliv-edge-body.bin --cacert "$STAGING_CA" --resolve "relay.ocliv.test:${RELAY_PORT}:$RELAY_IP" --connect-to "evil.test:${RELAY_PORT}:$RELAY_IP:${RELAY_PORT}" https://relay.ocliv.test:${RELAY_PORT}/ -H 'Host: evil.test' || true)
CODE=$(printf '%s' "$RESP" | head -1)
if printf '%s' "$CODE" | grep -Eq ' (400|404|421) '; then
	say "PASS: mismatched authority rejected at relay ($CODE)"
elif printf '%s' "$CODE" | grep -Eq ' 200 ' && [ ! -s /tmp/ocliv-edge-body.bin ] && ! printf '%s' "$RESP" | grep -qi '^via:'; then
	say "PASS: mismatched authority absorbed at edge (empty 200, not forwarded)"
else
	say "FAIL: mismatched authority unexpected: $CODE"; FAIL=1
fi

# 5. Unauthorized visitor to a protected lease is denied (401/403) — run after `ocliv 3000 --name demo`.
CODE=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$STAGING_CA" --resolve "$LEASE_HOST:${RELAY_PORT}:$RELAY_IP" "https://$LEASE_HOST:${RELAY_PORT}/" || true)
check "unauthorized visitor denied" "401" "$CODE"

# 6. Relay data port is not reachable on the LAN/tailnet IP (loopback-only bind).
if curl -s -m 5 -o /dev/null "http://$RELAY_IP:8080/" 2>/dev/null; then
	say "FAIL: relay port 8080 reachable on tailnet IP"; FAIL=1
else
	say "PASS: relay port 8080 not reachable on tailnet IP"
fi

exit $FAIL
