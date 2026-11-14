#!/usr/bin/env bash
# Verifies the permanent single-host edge CONTRACT from the adapter alone
# (no server, no ACME order, no network). This is a configuration proof:
# it says what the edge binds and which ACME challenge it uses, and it
# pins the tempting-looking port-80 "fix" that must NOT be applied.
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
check "ACME issuers carry no challenge override (default: TLS-ALPN-01 on 443)" \
	"all('challenges' not in i for i in d['apps']['tls']['automation']['policies'][0]['issuers'])"
check "reverse proxy targets the loopback relay" \
	"d['apps']['http']['servers']['srv0']['routes'][0]['handle'][0]['routes'][0]['handle'][0]['upstreams']==[{'dial':'127.0.0.1:8080'}]"
check "X-Forwarded-Host is stripped, not forwarded" \
	"d['apps']['http']['servers']['srv0']['routes'][0]['handle'][0]['routes'][0]['handle'][0]['headers']['request']['delete']==['X-Forwarded-Host']"

# The negative control: adding the "fix" for a busy :80 switches the
# issuer to HTTP-01 on an alternate port. This pins WHY the checked-in
# file must not be changed that way.
python3 - "$work/Caddyfile" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = '{\n\tauto_https disable_redirects\n}'
new = '{\n\thttp_port {$OCLIV_HTTP_PORT:80}\n\tauto_https disable_redirects\n}'
assert old in s, 'single-host global block anchor not found'
open(p, 'w').write(s.replace(old, new))
PY
moved="$(adapt "$work/Caddyfile" 8080 | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)))')"
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
iss=d['apps']['tls']['automation']['policies'][0]['issuers']
def port(i):
    p=i.get('challenges',{}).get('http',{}).get('alternate_port')
    return str(p) if p is not None else None
sys.exit(0 if any(port(i)=='8080' for i in iss) else 1)
" "$moved"; then
	echo "PASS: global http_port would force HTTP-01 on an alternate port (documented do-not-do)"
else
	echo "FAIL: http_port no longer forces HTTP-01; this script's warning is stale" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	echo "single-host edge contract: FAIL" >&2
	exit 1
fi
echo "single-host edge contract: OK (443 alone, TLS-ALPN-01, loopback upstream)"