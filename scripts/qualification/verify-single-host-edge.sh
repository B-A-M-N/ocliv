#!/usr/bin/env bash
# Verifies the permanent single-host edge CONTRACT from the adapter alone
# (no server, no ACME order, no network). This is a configuration proof:
# it says what the edge binds and PROVES the ACME challenge is pinned to
# TLS-ALPN-01 on 443 (HTTP-01 explicitly disabled) — the retired
# "no challenge override" check was vacuous, because Caddy enables
# HTTP-01 by default and the adapted JSON simply does not show it.
# It also pins the tempting-looking port-80 "fix" that must NOT be
# applied, and carries two negative controls so nothing here passes
# vacuously.
#
# It proves nothing about whether any host's 443 is externally reachable.
# That stays NOT VERIFIED until an external client actually connects.
#
# Requires: docker, python3.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
caddyfile="$repo_root/packaging/caddy/Caddyfile.single-host"
image="${OCLIV_CADDY_IMAGE:-caddy:2-alpine}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ ! -f "$caddyfile" ]; then
	echo "FAIL: $caddyfile not found" >&2
	exit 1
fi

# Placeholders must be set for adapt; values are throwaway test names.
export OCLIV_HOST="${OCLIV_HOST:-relay.example.org}"
export OCLIV_ACME_EMAIL="${OCLIV_ACME_EMAIL:-ops@example.org}"

adapt() { # $1 = caddyfile path, $2 = optional OCLIV_HTTP_PORT
	if [ -n "${2:-}" ]; then export OCLIV_HTTP_PORT="$2"; else unset OCLIV_HTTP_PORT || true; fi
	# stderr is not captured: Caddy's "unnecessary header_up" advisories
	# are informational, and hiding them would hide real adapt errors too.
	docker run --rm \
		-e OCLIV_HOST -e OCLIV_ACME_EMAIL ${OCLIV_HTTP_PORT:+-e OCLIV_HTTP_PORT} \
		-v "$1:/etc/caddy/Caddyfile:ro" "$image" \
		caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile
}

cp "$caddyfile" "$work/Caddyfile"
current="$(adapt "$work/Caddyfile" "" | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)))')"

fail=0
check() { # $1 = label, $2 = python expression over json `d`
	if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
ok=bool($2)
sys.exit(0 if ok else 1)
" "$current"; then
		echo "PASS: $1"
	else
		echo "FAIL: $1" >&2
		fail=1
	fi
}

check "exactly one HTTP server" "len(d['apps']['http']['servers'])==1"
check "that server listens on 443 alone" "d['apps']['http']['servers']['srv0']['listen']==[':443']"
check "no http_port override" "'http_port' not in d['apps']['http']"
# The issuer must be explicit (module + contact email) AND must pin
# the challenge. Caddy enables HTTP-01 and TLS-ALPN-01 by default, so
# the ABSENCE of a challenges field is not evidence of anything: with
# the default set the issuer still attempts HTTP-01 over port 80
# first. Only an explicit challenges.http.disabled is proof this edge
# never needs :80. assert_http01_disabled returns False for both an
# absent challenges field and an enabled http challenge, so the
# default-config issuer fails this check.
check "ACME issuer is explicit with the contact email" \
	"all(i.get('module')=='acme' and i.get('email')=='ops@example.org' for i in d['apps']['tls']['automation']['policies'][0]['issuers'])"
check "HTTP-01 challenge is EXPLICITLY disabled on every issuer (pins TLS-ALPN-01 on 443)" \
	"all(i.get('challenges',{}).get('http',{}).get('disabled') is True for i in d['apps']['tls']['automation']['policies'][0]['issuers'])"
check "reverse proxy targets the loopback relay" \
	"d['apps']['http']['servers']['srv0']['routes'][0]['handle'][0]['routes'][0]['handle'][0]['upstreams']==[{'dial':'127.0.0.1:8080'}]"
check "X-Forwarded-Host is stripped, not forwarded" \
	"d['apps']['http']['servers']['srv0']['routes'][0]['handle'][0]['routes'][0]['handle'][0]['headers']['request']['delete']==['X-Forwarded-Host']"

# Negative control 1 (vacuity guard): adapt the SAME file with
# disable_http_challenge removed — the pre-correction template. Its
# issuer carries NO challenges field at all, which is exactly why the
# retired "no challenge override" check proved nothing (it passed on
# both configs). The explicit-disable check above MUST fail on this
# variant, or it is vacuous too.
cp "$work/Caddyfile" "$work/no-pin"
python3 - "$work/no-pin" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = '			disable_http_challenge\n'
assert old in s, 'disable_http_challenge anchor not found'
open(p, 'w').write(s.replace(old, ''))
PY
nopin="$(adapt "$work/no-pin" "" | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)))')"
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
iss=d['apps']['tls']['automation']['policies'][0]['issuers']
def disabled(i):
    c=i.get('challenges',{}).get('http',{})
    return c.get('disabled') is True
# The variant MUST NOT be proven disabled: absent challenges means the
# default set (HTTP-01 + TLS-ALPN-01) is live.
sys.exit(1 if any(disabled(i) for i in iss) else 0)
" "$nopin"; then
	echo "PASS: without disable_http_challenge the issuer is NOT proven HTTP-01-free (the check is not vacuous)"
else
	echo "FAIL: the explicit-disable check passes even on the unpinned template; it proves nothing" >&2
	fail=1
fi

# Negative control 2 (the documented trap): adding the global
# http_port "fix" for a busy :80 can no longer flip THIS edge to
# HTTP-01 — the pin wins — but it still writes an inert
# challenges.http.alternate_port and an app-level http_port, i.e. it
# changes nothing useful while looking like a fix. On an edge WITHOUT
# the pin the same line switches the issuer to HTTP-01 on the alternate
# port. Either way it is a do-not-do; this pins that the pin survives.
cp "$work/Caddyfile" "$work/http-port"
python3 - "$work/http-port" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = '{\n	auto_https disable_redirects\n}'
new = '{\n	http_port {$OCLIV_HTTP_PORT:80}\n	auto_https disable_redirects\n}'
assert old in s, 'single-host global block anchor not found'
open(p, 'w').write(s.replace(old, new))
PY
moved="$(adapt "$work/http-port" 8080 | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)))')"
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
iss=d['apps']['tls']['automation']['policies'][0]['issuers']
def disabled(i):
    return i.get('challenges',{}).get('http',{}).get('disabled') is True
sys.exit(0 if d['apps']['http'].get('http_port')==8080 and all(disabled(i) for i in iss) else 1)
" "$moved"; then
	echo "PASS: global http_port stays inert on the pinned edge (app-level port appears, the HTTP-01 disable survives)"
else
	echo "FAIL: http_port overrode the challenge pin; the edge is no longer proven :80-free" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	echo "single-host edge contract: FAIL" >&2
	exit 1
fi
echo "single-host edge contract: OK (443 alone, HTTP-01 explicitly disabled, loopback upstream)"