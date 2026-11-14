#!/usr/bin/env bash
# Loopback end-to-end for the single-host edge contract — NO DNS, NO
# ACME, NO Tailscale, NO public exposure. It proves the edge actually
# RUNS (not just adapts): the relay boots behind Caddy with the
# single-host dispatch shape, and the control chain — challenge,
# enrollment exchange, authority gate, agent attach — completes over
# the edge with STRICT client verification (--cacert against Caddy's
# internal CA, never -k).
#
# What this does NOT prove, stated so it cannot be misquoted:
# - the internal CA is not a public trust anchor; a public ACME edge is
#   NOT VERIFIED here;
# - the MCP publication leg (/r/<route-id>/mcp) is NOT exercised: it
#   needs a local upstream with an auth profile, and none is available
#   on this host. The route-ingress authority gate IS probed;
# - loopback reachability is not external reachability.
#
# Differences from a public run, all deliberate:
# - the edge listens on 127.0.0.1:8443 via Caddy's internal CA;
# - the relay uses a free loopback port (default 18087), so the edge's
#   reverse_proxy is redirected to it in a SCRATCH COPY of
#   packaging/caddy/Caddyfile.single-host.local (one line; the
#   reviewed file is untouched). Port 8080 is not assumed free;
# - the ocliv CLI client legs run inside a throwaway container whose
#   own /etc/hosts maps the edge name (--add-host): the Go resolver
#   reads /etc/hosts, this box has no root to edit the real one, and
#   curl's --resolve has no CLI equivalent. The client HOME is the
#   isolated scratch dir, so the real ~/.config/ocliv is never touched.
#
# Requires: docker, go, curl, python3. Leaves nothing behind: the edge
# container is --rm, processes are torn down by explicit PID, scratch
# is a mktemp -d with an EXIT trap.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

EDGE_PORT="${OCLIV_LOOPBACK_EDGE_PORT:-8443}"
RELAY_PORT="${OCLIV_LOOPBACK_RELAY_PORT:-18087}"
HEALTH_PORT="${OCLIV_LOOPBACK_HEALTH_PORT:-18088}"
APP_PORT="${OCLIV_LOOPBACK_APP_PORT:-3999}"
EDGE_HOST="ocliv.local"
DOMAIN="ocliv.local"
image="${OCLIV_CADDY_IMAGE:-caddy:2-alpine}"
BIN="$work/ocliv"

fail=0
pass() { echo "PASS: $1"; }
bad()  { echo "FAIL: $1" >&2; fail=1; }

cleanup() {
	[ -n "${CLIENT_CID:-}" ] && docker kill "$CLIENT_CID" >/dev/null 2>&1 || true
	[ -n "${CADDY_CID:-}" ] && docker kill "$CADDY_CID" >/dev/null 2>&1 || true
	[ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap cleanup EXIT

# 1. Build the relay binary from THIS tree (a stale /tmp binary would
#    qualify yesterday's code).
echo "building ocliv from $repo_root ..."
if ! (cd "$repo_root" && go build -o "$BIN" ./cmd/ocliv); then
	echo "FAIL: build failed" >&2
	exit 1
fi

# 2. Scratch edge config: the reviewed single-host loopback variant
#    with its upstream redirected to this run's relay port.
caddyfile="$work/Caddyfile"
cp "$repo_root/packaging/caddy/Caddyfile.single-host.local" "$caddyfile"
python3 - "$caddyfile" "$RELAY_PORT" <<'PY'
import sys
p, port = sys.argv[1], sys.argv[2]
s = open(p).read()
old = "reverse_proxy 127.0.0.1:8080"
new = "reverse_proxy 127.0.0.1:%s" % port
assert old in s, "loopback edge upstream anchor not found"
open(p, "w").write(s.replace(old, new, 1))
PY
if command -v caddy >/dev/null 2>&1; then
	caddy validate --config "$caddyfile" --adapter caddyfile >/dev/null 2>&1 \
		&& pass "scratch edge config validates (caddy validate)" \
		|| bad "scratch edge config fails caddy validate"
fi

# 3. Relay: loopback only, single-host ingress armed for this host.
#    --relay-host is REQUIRED in the single-host shape: control,
#    unlock, and /r/<id>/mcp all share the ONE apex hostname, so the
#    control authority is the apex, not relay.<domain>. (Without it
#    every agent-path request 421s — found live on the first run of
#    this harness.)
mkdir -p "$work/data" "$work/home"
OCLIV_CACERT="$work/root.crt" HOME="$work/home" "$BIN" relay serve \
	--listen "127.0.0.1:$RELAY_PORT" --health-listen "127.0.0.1:$HEALTH_PORT" \
	--domain "$DOMAIN" --relay-host "$EDGE_HOST" \
	--mcp-host "$EDGE_HOST" --mcp-port "$EDGE_PORT" \
	--data "$work/data" >"$work/relay.log" 2>&1 &
RELAY_PID=$!
ready=""
for _ in $(seq 1 30); do
	if curl -sS -m 2 "http://127.0.0.1:$HEALTH_PORT/health/ready" >/dev/null 2>&1; then
		ready=1; break
	fi
	sleep 0.5
done
if [ -n "$ready" ]; then
	pass "relay health ready on 127.0.0.1:$HEALTH_PORT"
else
	bad "relay never became ready (see $work/relay.log)"; sed -n '1,20p' "$work/relay.log" >&2 || true; exit 1
fi

# 4. Edge: Caddy on the host network with the internal CA. The name is
#    not in any resolver, so every client uses --resolve (the same
#    no-/etc/hosts pattern the fixture documents); the readiness probe
#    therefore dials 127.0.0.1 and only asks whether the listener
#    answers — the contract checks below are the real assertions.
CADDY_CID="$(docker run -d --rm --network host \
	-v "$caddyfile:/etc/caddy/Caddyfile:ro" "$image" \
	caddy run --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null)"
# Extract the internal CA first: the readiness probe then verifies TLS
# strictly with it. No -k and no --no-check-certificate anywhere in
# this harness — an unverifiable probe proves nothing about trust.
root_seen=""
for _ in $(seq 1 40); do
	if docker cp "$CADDY_CID:/data/caddy/pki/authorities/local/root.crt" "$work/root.crt" >/dev/null 2>&1; then
		root_seen=1; break
	fi
	sleep 0.5
done
if [ -z "$root_seen" ]; then
	bad "could not extract the edge internal CA"; docker logs "$CADDY_CID" 2>&1 | sed -n '1,20p' >&2 || true; exit 1
fi
RESOLVE="--resolve $EDGE_HOST:$EDGE_PORT:127.0.0.1"
edge_up=""
for _ in $(seq 1 40); do
	if curl -sS -m 2 --cacert "$work/root.crt" $RESOLVE -o /dev/null \
		"https://$EDGE_HOST:$EDGE_PORT/" >/dev/null 2>&1; then
		edge_up=1; break
	fi
	sleep 0.5
done
if [ -z "$edge_up" ]; then
	bad "edge never answered on :$EDGE_PORT (strict TLS)"; docker logs "$CADDY_CID" 2>&1 | sed -n '1,20p' >&2 || true; exit 1
fi
pass "edge up on :$EDGE_PORT with the internal CA extracted for --cacert"

# 5. Control chain through the edge, strict TLS.
code="$(curl -sS -m 8 --cacert "$work/root.crt" $RESOLVE -o /dev/null \
	-w '%{http_code}' "https://$EDGE_HOST:$EDGE_PORT/v1/agent/challenge" || echo 000)"
case "$code" in
	4*) pass "challenge over the edge: relay answered HTTP $code (TLS + Host + proxy path live)" ;;
	*)  bad "challenge over the edge: HTTP $code (want a 4xx relay answer, not 000/5xx)" ;;
esac

# The authority gate has TWO layers, and both are checked. Outer
# (edge): a VISITOR-SMUGGLED Host header (valid TLS/SNI from the URL,
# wrong Host header) matches no Caddy site, so Caddy answers its
# unmatched-site signature (HTTP 200, EMPTY body) and never proxies —
# the relay answer cannot arrive because nothing was forwarded. Inner
# (relay): the same request DIRECTLY at the loopback relay must 421
# ("misdirected") before any handler runs — defense in depth for any
# other front. POST is the agent-path method (a GET on a foreign host
# falls through to the visitor/unlock path by design — see
# TestAgentPathsRequireRelayAuthority).
code="$(curl -sS -m 8 --http1.1 --cacert "$work/root.crt" $RESOLVE -o "$work/smuggled.body" \
	-w '%{http_code}' -X POST -H "Host: evil.test" \
	"https://$EDGE_HOST:$EDGE_PORT/v1/agent/challenge" || echo 000)"
if [ "$code" = "200" ] && [ ! -s "$work/smuggled.body" ]; then
	pass "smuggled wrong Host: edge matched no site and proxied nothing (empty 200)"
else
	bad "smuggled wrong Host returned $code with a non-empty body; the edge forwarded it"
	echo "  body (first 200 bytes): $(head -c 200 "$work/smuggled.body" 2>/dev/null || echo '<none>')" >&2
fi
code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' -X POST -H "Host: evil.test" \
	"http://127.0.0.1:$RELAY_PORT/v1/agent/challenge" || echo 000)"
[ "$code" = "421" ] && pass "same smuggled Host at the relay itself: 421 before any handler" \
	|| bad "direct relay returned $code for a foreign Host, want 421 (inner gate)"

# Route-shaped path on the right host: unknown route is non-disclosing
# (404/401), never 421 and never a proxy error.
code="$(curl -sS -m 8 --cacert "$work/root.crt" $RESOLVE -o /dev/null \
	-w '%{http_code}' "https://$EDGE_HOST:$EDGE_PORT/r/ocliv-no-such-route/mcp" || echo 000)"
case "$code" in
	404|401) pass "unknown /r/<id>/mcp is non-disclosing (HTTP $code)" ;;
	*) bad "unknown route returned $code, want 404 or 401" ;;
esac

# A client WITHOUT the CA must fail closed (never -k anywhere here).
# --resolve stays so the failure is TLS verification, not DNS.
if curl -sS -m 8 $RESOLVE -o /dev/null "https://$EDGE_HOST:$EDGE_PORT/v1/agent/challenge" >/dev/null 2>&1; then
	bad "edge accepted a client with no CA trust (verification not enforced)"
else
	pass "client without the internal CA fails TLS (closed by default)"
fi

# 6. CLIENT container: the ocliv CLI resolves the relay name through
#    the system resolver, and loopback-only names have no record (curl
#    could --resolve; the Go client cannot). Rather than write the
#    host's /etc/hosts (root) or weaken verification, the client legs
#    run inside a throwaway container whose OWN /etc/hosts carries the
#    mapping (--add-host) on the host network. Nothing outside it
#    changes.
CLIENT_IMAGE="${OCLIV_LOOPBACK_CLIENT_IMAGE:-debian:bookworm-slim}"
CLIENT_CID="$(docker run -d --rm --network host \
	--add-host "$EDGE_HOST:127.0.0.1" \
	-v "$work:/w" -w /w "$CLIENT_IMAGE" sleep 600)"
client() { docker exec -i -e HOME=/w/home -e OCLIV_CACERT=/w/root.crt \
	"$CLIENT_CID" /w/ocliv "$@"; }

# Enrollment through the edge: the exchange itself proves
#    DNS-less name -> Caddy -> loopback relay with strict TLS. The code
#    is a single-use secret: held in a variable only, never printed,
#    never written to disk.
enroll_code="$("$BIN" relay issue-enroll --data "$work/data" --tenant home | tail -n1)"
login_out="$(printf '%s\n' "$enroll_code" | \
	client login --relay "https://$EDGE_HOST:$EDGE_PORT" --code-file - \
	--cacert /w/root.crt 2>&1)" || {
	bad "enrollment exchange through the edge failed: $login_out"; exit 1
}
pass "enrollment exchange completed through the edge (login exit 0)"
unset enroll_code

# 7. Relay doctor is a PUBLIC-shape check by design: it dials
#    https://<relay-host>/ — port 443, no edge-port awareness. A
#    loopback edge on 8443 therefore can never satisfy it, and forcing
#    a pass would mean weakening the check. The equivalent oracle for
#    this run is the strict-TLS control-path probe in step 5 plus the
#    enrollment exchange below, both of which went THROUGH the edge.
#    doctor stays the public-qualification oracle.

# 8. Agent attach through the edge (outbound WSS + yamux, strict TLS).
#    The attach runs bounded (timeout 18) and logs into the scratch dir
#    so its own output is the diagnosis oracle, not a guess.
python3 -m http.server "$APP_PORT" --bind 127.0.0.1 >"$work/app.log" 2>&1 &
APP_PID=$!
docker exec -d -e HOME=/w/home -e OCLIV_CACERT=/w/root.crt "$CLIENT_CID" \
	sh -c "timeout 18 /w/ocliv $APP_PORT > /w/attach.log 2>&1" || true
sleep 10
status_out="$(client status --json 2>&1 || true)"
# The single-tunnel projection carries "status":"ACTIVE" at the top
# level (verified against the live shape, not a guessed field name).
if echo "$status_out" | grep -q '"status":"ACTIVE"' && echo "$status_out" | grep -q 'route'; then
	pass "agent attach ACTIVE through the edge (lease live, WSS + yamux + strict TLS)"
	echo "  $(echo "$status_out" | tr ',' '\n' | grep -E 'lease_id|url|generation' | tr '\n' ' ')"
else
	bad "agent attach not ACTIVE through the edge"
	echo "  status: $(echo "$status_out" | sed -n '1,6p')" >&2
	echo "  attach log: $(sed -n '1,10p' "$work/attach.log" 2>/dev/null || echo '<none>')" >&2
fi
kill "$APP_PID" 2>/dev/null || true

echo
echo "NOT exercised here (recorded, not hidden): the MCP publication"
echo "leg (/r/<id>/mcp with a real upstream and auth profile), public"
echo "ACME trust, and external reachability. Those stay NOT VERIFIED"
echo "until a public host runs them — see"
echo "docs/qualification/PERMANENT-EDGE-2026-11-13.md."

if [ "$fail" -ne 0 ]; then
	echo "single-host loopback run: FAIL" >&2
	exit 1
fi
echo "single-host loopback run: OK (strict-TLS control chain through the edge)"