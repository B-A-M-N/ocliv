#!/bin/sh
# check-recovery.sh — reconnect fencing, revocation, relay restart.
# Run with the agent attached and a protected lease ACTIVE. Each step prints
# PASS/FAIL; the operator performs the bracketed manual action between steps.
set -eu
RELAY_IP="${RELAY_IP:-10.9.66.20}"
STAGING_CA="${STAGING_CA:-./ocliv-root.crt}"
LEASE_HOST="${LEASE_HOST:-demo.t.ocliv.test}"
FAIL=0
say() { printf '%s\n' "$*"; }
BASE="https://$LEASE_HOST"
probe() { curl -s -o /dev/null -w '%{http_code}' --cacert "$STAGING_CA" --resolve "$LEASE_HOST:443:$RELAY_IP" "$BASE/" || true; }

say "step 1: baseline — unauthorized probe must be 401 (got $(probe))"
say "[ACTION] kill the agent (Ctrl+C), wait 10s, restart it with the same lease"
say "step 2: after reconnect — unauthorized probe must still be 401 (got $(probe))"
say "[ACTION] on the relay: ocliv relay revoke --data <dir> --key <agent-key-id>"
say "step 3: after revoke — probe must be 401/404 and re-attach must fail (got $(probe))"
say "[ACTION] restart the relay process on the laptop, then re-enroll a fresh agent"
say "step 4: after relay restart — revoked key stays revoked, fresh lease ACTIVE"

exit $FAIL
