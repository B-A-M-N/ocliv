# Ocliv relay — operator notes

## Trusted edge contract (D08)

The relay derives the public scheme from its direct ingress: TLS is
authoritative, and `X-Forwarded-Proto` is honored only from loopback
(the local TLS edge). A remote plaintext sender can never upgrade
itself to `https`. The edge proxy MUST terminate TLS and MUST strip
any inbound `X-Forwarded-Proto` / `X-Forwarded-For` / `X-Forwarded-Host`
headers before forwarding to the relay on loopback; the relay treats
loopback `X-Forwarded-Proto` as the local edge's assertion.

## Enrollment codes (B05, A07, H07)

Mint with `ocliv relay issue-enroll --data DIR --tenant NAME`. Codes are
single-use and time-boxed. Never pass a code via argv; use `--code-file`
or stdin. A second `ocliv login` over an existing enrollment is refused
before touching the network so the fresh code is not burned; destruction
of local credentials is explicit via `ocliv logout`, after which the
operator must revoke the relay-side key (below).

## Compromised-key takedown (C10, B09, H04)

There is no in-band operator endpoint; the procedure is direct database
revocation on the relay host, identical in effect to the agent-signed
revoke handler, plus an explicit audit row:

```sql
UPDATE access_tokens   SET revoked_at='<now>' WHERE lease_id='<lease>' AND revoked_at IS NULL;
UPDATE visitor_sessions SET revoked_at='<now>' WHERE lease_id='<lease>' AND revoked_at IS NULL;
UPDATE leases SET token_generation=token_generation+1 WHERE id='<lease>';
UPDATE leases SET status='REVOKED' WHERE id='<lease>';
UPDATE agent_keys SET status='revoked' WHERE id='<key>';
INSERT INTO audit_events(time, actor, tenant_id, lease_id, category, result, detail)
VALUES('<now>', 'operator', '', '<lease>', 'takedown', 'ok', 'compromised key revoked by operator');
```

Effect: new visitor requests — including `--public` requests, which skip
visitor authentication but are still gated on live `ACTIVE` status by the
router — and every later attach/resume with the key are denied immediately
without a relay restart (per-request checks read `revoked_at`,
`token_generation`, lease status, and key status from the database).
The `REVOKED` status update is what stops a public tunnel: without it the
lease still reads `ACTIVE` and public traffic keeps flowing.
Already-established in-flight streams on the live agent session drain
naturally; killing them immediately requires a relay restart. Bound all
leases with TTLs so the worst case is time-boxed.

## Restart semantics (P1 — fail-closed session invalidation)

The visitor-session HMAC key is random per relay instance unless
explicitly configured, so a relay restart intentionally invalidates
persisted browser session cookies: stored verifiers stop matching and
visitors reauthenticate (redeem a fresh share link). This is fail-closed
by design, not a rotation service.

Lease rows are durable: restart runs `reconcileBoot`, which moves
`ACTIVE` leases to `RECONNECTING` (bounded by the reconnect grace) and
expires lapsed TTLs. Agents reconnect and resume live leases; nothing
resurrects `CLOSED`/`REVOKED`/`EXPIRED` rows. Revocations, token
generation bumps, and audit history all survive restarts — restore from
an older backup can still resurrect revoked identities (H06), so treat
backups as point-in-time copies, never as revocation truth.

## Backup and restore (H06 — not yet provided)

No backup/restore procedure ships in v1. Copying `ocliv.db` while the
relay runs is untested; stop the relay first. Restore from backup has no
automated test. Do not represent single-node operation as highly
available (H09).

## Private staging lab (tailnet, no VPS)

Proves private multi-machine behavior only. Public DNS, ACME/DNS-01,
and public internet reachability stay NOT VERIFIED.

Prerequisites: Tailscale on all machines; Caddy on the relay laptop;
this repo's `ocliv` binary copied to the laptop (no Go toolchain needed
there: `GOOS=linux GOARCH=amd64 go build -o ocliv-linux-amd64 ./cmd/ocliv`).

### Role 1 — relay laptop (here: 10.9.66.20)

```
mkdir -p "$HOME/ocliv-lab" && chmod 700 "$HOME/ocliv-lab"
./ocliv relay serve --listen=127.0.0.1:8080 --domain=ocliv.test --data="$HOME/ocliv-lab"
```

In another terminal, stage Caddy with [Caddyfile.tailnet](/home/bamn/ocliv/packaging/caddy/Caddyfile.tailnet)
(bound to the laptop's Tailscale IP, `tls internal`), then `sudo caddy
validate --config /etc/caddy/Caddyfile.tailnet --adapter caddyfile` and
start/reload Caddy. Mint enrollment codes with `./ocliv relay
issue-enroll --data="$HOME/ocliv-lab" --tenant=lab`. Relay stays on
loopback; only Caddy listens on the tailnet IP.

### Role 2 — agent PC

Trust the lab CA root only (copy the public `root.crt` from the
laptop's Caddy data dir; never the CA key), then resolve and verify:

```
echo "<laptop-ip> relay.ocliv.test demo.t.ocliv.test" | sudo tee -a /etc/hosts
curl -v https://relay.ocliv.test/v1/agent/challenge   # TLS must verify; 4xx is fine
./ocliv login --relay https://relay.ocliv.test --code-file -   # code on stdin
python3 -m http.server 3000 --bind 127.0.0.1 &                  # fixture app only
./ocliv 3000 --name demo --ttl 30m
```

The tunnel must report PROTECTED. It must not claim public reachability.

### Role 3 — independent visitor (third tailnet device)

```
curl -i --cacert ./ocliv-root.crt \
  --resolve demo.t.ocliv.test:443:<laptop-ip> \
  https://demo.t.ocliv.test/
```

Expect 401/302 with zero hits on the local app. Authorized access uses
the unlock link from the agent output, in a browser trusting the lab CA
and resolving `demo.t.ocliv.test`. Run the checks in
[tests/staging](/home/bamn/ocliv/tests/staging/README.md):
`check-edge.sh`, then `check-forwarding.sh` (needs `UNLOCK_URL`
exported), then `check-recovery.sh`.

### Teardown

`update-ca-certificates --fresh` after removing the lab CA file;
revert `/etc/hosts`; `ocliv relay revoke` + stop relay/Caddy. Staging
trust is lab-only and must not linger.
