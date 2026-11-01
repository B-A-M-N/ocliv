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

## Compromised-key takedown (C10, B09, H04, P0-A)

Use the supported operator commands on the relay host (no Server
construction, no restart required):

```sh
ocliv relay keys list --data /var/lib/ocliv
ocliv relay revoke-key --key-id key-XXXX --reason "compromised" --data /var/lib/ocliv
ocliv relay tenants suspend --tenant TENANT --reason "abuse" --data /var/lib/ocliv
ocliv relay tenants unsuspend --tenant TENANT --data /var/lib/ocliv
```

One coordinated transaction marks the key revoked, terminally revokes
all its live leases and visitor credentials, tombstones affected
publications, and records the audit row. Effect: new visitor requests —
including `--public` requests, which skip visitor authentication but are
still gated on live `ACTIVE` status by the router — and every later
challenge/connect/allocate/resume with the key are denied; suspension
additionally denies enrollment for the tenant. Keys stay revoked on
unsuspend: restoring service requires explicit re-enrollment, never a
silent resurrection of old authority.

Forwarding termination: the in-process path evicts live sessions at
commit, and per-request admission evicts on the next denied request; a
CLI-driven revocation without a local Server converges through the
relay's 5s supervise revalidation. Bound all leases with TTLs so the
worst case stays time-boxed.

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

## Publication management (P0-D — durable identities)

A publication (`route_id`) is the stable public endpoint; a lease is the
transient tunnel attachment behind it. Manage the publication, not the
lease:

```sh
ocliv mcp list                              # every publication you own
ocliv mcp list --name dev-tools             # one label
ocliv mcp unpublish --publication-id ROUTE  # revoke exactly this route
ocliv mcp unpublish --lease LEASE           # legacy lease administration
```

`unpublish --publication-id` deletes only that route (already-gone is
OK); it never closes a lease or touches sibling publications.
`mcp list` is a routing hint, not liveness: ACTIVE comes from relay
admission, verified with `mcp doctor`.

Key rotation does not transfer publications (fail-closed): a newly
enrolled replacement key owns nothing. Re-enroll, then republish under
the replacement key; the old key's routes stay tombstoned under the old
key. Revoking a key denies its management plane (list/delete return
403) and tombstones its publications — revival requires a fresh
authorized publish, never a resume.

## Local readiness probing (Domain A)

Apps that do not answer usefully at `/` get an explicit probe contract
instead of a silent always-ready assumption:

```sh
ocliv 3000 --probe-path /healthz --probe-status 200
```

The path must be an origin-form loopback path (no query, no `..`,
validated before any network use); the status is one expected code
100–599, or `0`/omitted for any HTTP response. The contract is part of
the tunnel's deployment identity: changing it allocates a fresh lease
rather than resuming the old one, and every reconnect re-probes the
same contract. `ocliv status` shows the recorded contract (`Probe:`),
and `ocliv doctor` judges the local target against it — override with
`doctor --probe-path/--probe-status` only to test a different contract,
never to claim reachability.

## Backup and restore (H06, P0-E)

```sh
ocliv relay backup --data /var/lib/ocliv --out /root/ocliv-snap.db
systemctl stop ocliv-relay
ocliv relay restore --data /var/lib/ocliv --in /root/ocliv-snap.db --relay-stopped
systemctl start ocliv-relay
```

`backup` is a consistent online snapshot (VACUUM INTO, owner-only);
`restore` is explicitly offline and fail-closed:

- The relay must be stopped first; without `--relay-stopped` restore
  refuses, and an active writer on the live database also refuses.
- The backup must pass integrity_check and open through the current
  schema (older snapshots migrate forward in a scratch copy; newer
  schemas refuse).
- Revocation never rolls back: every revoked key, suspended tenant,
  revoked lease, and tombstoned publication in the live database must
  already be revoked/absent in the backup, or restore refuses and
  names the resurrected identity.
- `--reset-authority` is the explicit escape hatch: it installs the
  backup, then revokes every key, lease, token, session, and
  publication in it. Nothing restored is trusted until the operator
  re-enrolls. The restore (and reset) is audited in the new database.

The restored image takes effect at the next relay start; a running
relay keeps its pre-restore handle until restart. Writes between
restore and restart are lost — stop first, restore, start.

Do not represent single-node operation as highly available (H09).

## Public single-host deployment (production ingress)

One public relay serves all publishers; publishers need no DNS, ports,
or certificates of their own. On a host with a public IP and a domain
you control:

1. DNS: one `A`/`AAAA` record for the relay hostname (e.g.
   `relay.hosting.test` → public IP). No wildcard needed for
   single-host MCP ingress.
2. Relay env `/etc/ocliv/relay.env` (root-owned, `0600`):
   `OCLIV_DOMAIN=hosting.test`,
   `OCLIV_MCP_HOST=relay.hosting.test`
   (plus `OCLIV_RELAY_HOST=` only when the public control hostname is
   not `relay.<domain>`). Reserved `example.*` hostnames refuse startup.
   Generate, don't hand-write: `ocliv relay init --domain hosting.test
   --mcp-host relay.hosting.test --acme-email ops@hosting.test
   --out ./ocliv-relay-deploy` renders `relay.env`, the edge
   `Caddyfile`, the unit, and `dns-records.txt` from the reviewed
   packaging sources (placeholders refuse before anything is written;
   re-runs are idempotent, conflicting re-runs fail closed).
3. Edge: install `packaging/caddy/Caddyfile.single-host` with
   `OCLIV_HOST`/`OCLIV_ACME_EMAIL` set, then
   `caddy validate --config Caddyfile.single-host --adapter caddyfile`
   before `systemctl reload caddy`. Caddy terminates ACME TLS and
   forwards to `127.0.0.1:8080`; the relay never binds publicly.
4. Relay: `systemctl enable --now ocliv-relay` (uses
   `packaging/systemd/ocliv-relay.service` + launcher, fixed
   loopback `--listen`, explicit `--domain`, conditional `--mcp-host`).
5. Enroll: `ocliv relay issue-enroll --data /var/lib/ocliv --tenant NAME`
   on the relay host; publishers `ocliv login` against
   `https://relay.hosting.test`.

Failure is loud, not silent: missing/placeholder domain or host, a
port without `--mcp-host`, a non-loopback `--listen`, or an
unreachable Caddy upstream each refuse startup or reload. A route is
production-ready only when an independent machine outside the relay's
network reaches it over normal public DNS with default TLS
verification — tailnet or loopback success never counts.

### Temporary public proving via Tailscale Funnel (lab-only edge)

Proves the relay path over the real public internet without a domain
or open ports. Funnel is a throwaway edge, not a product dependency:
it terminates public TLS itself, so SNI/Host consistency at the
Funnel→Caddy hop stays NOT VERIFIED (proven once in
[Gate 3](/home/bamn/ocliv/docs/qualification/GATE3-PUBLIC-FUNNEL.md);
relay-side exact-Host checks still enforced and PASS).

Rule: Funnel runs **on the relay host** — it publishes that machine's
loopback listener. `tailscale up`/`login` only joins the tailnet;
`tailscale funnel <port>` is a separate per-machine serve config.
Connecting your account on machine A and running funnel there exposes
machine A, never the relay on machine B. Moving the public test to a
new relay host means running funnel there.

On the relay host (needs the `tailscale` CLI installed and funnel
allowed for the tailnet):

```
./caddy run --config packaging/caddy/Caddyfile.funnel --adapter caddyfile
tailscale funnel 18081            # publishes THIS host's :18081
tailscale funnel status           # note the exact *.ts.net hostname
```

Run the relay with `--relay-host/--mcp-host` set to that exact funnel
hostname, then publish/verify from an independent public client with
default TLS verification (no `-k`). Teardown with
`tailscale funnel reset` — public exposure must not linger.

`tailscale: command not found` means the CLI is not installed for that
user/host — install Tailscale there; nothing in Ocliv substitutes for it.

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
(bound to the laptop's Tailscale IP, `tls internal`). `STAGING_BIND` has
no default and Caddy refuses to adapt without it — export the laptop's
Tailscale IPv4 first (`export STAGING_BIND=$(tailscale ip -4)`), then
`sudo -E caddy validate --config /etc/caddy/Caddyfile.tailnet --adapter
caddyfile` and start/reload Caddy. Mint enrollment codes with `./ocliv relay
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
