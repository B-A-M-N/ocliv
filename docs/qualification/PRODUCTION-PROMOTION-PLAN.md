# Production promotion and rollback procedure — `95cc66c`

**Status: PREPARED, NOT EXECUTED.** Execution is BLOCKED — the designated
relay host (Raspberry Pi, `10.9.66.170`, tailnet `100.95.10.57`) is
unreachable: no LAN path (ARP FAILED) and Tailscale reports it offline
(last seen 13h+). The qualification gates that this procedure depends on
HAVE passed, so the plan is written; every step below remains
operator-gated where it requires root, physical access, or an approval
decision.

This promotion carries the managed-authorization work through schema
**V11 (forward-only)**, so the rollback must restore **binary AND database
together**. A binary-only rollback leaves the relay DOWN.

## What this promotion carries

| Artifact | Value |
|---|---|
| Source commit | `95cc66c` (with `26ac95a`, `48cf7d5`, `6472ff8`, `7883cfd` already in history) |
| Binary digest | `804127863c9ae8c87bebcc13de2b6ffbf3c33542834b1c58e317e82c7ec118c4` (arm64 build — see step 3) |
| Schema reached on open | V11 (forward-only) |
| Behavioral change | the managed MCP challenge now advertises `resource_metadata` (RFC 9728 §5.1) instead of the unparsable `resource_uri`; refresh tokens rotate with an atomic burn; publication identity is durable per name; cross-key ownership conflicts are terminal |

## The four facts this plan must respect

### 1. Schema V11 is forward-only

`internal/store/store.go`: `currentSchema = 11`, and `case v > currentSchema`
**fails closed** — a binary built before V11 refuses a database already at
V11. Proven at the current schema by
`TestOpenIdempotentAndDowngradeRefused` (it opens a DB — which migrates to
11 — then stamps 99 and asserts the next `Open` fails).

**Consequence:** a binary-only rollback (restore the old binary, keep the
V11 database) leaves the relay unable to start. Rollback is **both
artifacts or nothing**.

### 2. SQLite WAL-safe backup is a VACUUM INTO image

`ocliv relay backup --data /var/lib/ocliv --out FILE` produces a consistent
snapshot (a `VACUUM INTO` image, owner-only permissions) —
`internal/cli/cli_relay.go:687`. VACUUM INTO is the documented WAL-safe
way to snapshot a database in WAL mode: it captures a consistent image
without stopping the writer.

Attach a **content checksum sidecar** to the backup so tampering or a
truncated copy is detectable before it is relied on
(`PRAGMA integrity_check` validates allocated pages only, so it is a
floor, not proof).

### 3. The issuer key lives in the DATABASE, not the binary

`authz_issuer_key` (single row, `id=1`, columns `kid`/`priv`) is read by
`LoadIssuer` and created on first use if absent. `RotateIssuer`
**replaces it in place**, and tokens signed by a retired key fail closed
at admission.

**Consequences for promotion and rollback:**

- The signing key travels with the database. Restoring an older database
  restores that snapshot's key, so **tokens issued after the snapshot was
  taken can still verify** (the key is unchanged and their grants/clients
  may still be valid in the restored image) — restoring is NOT a reliable
  way to invalidate them. To actually cut authority you must either
  revoke the affected clients/grants/tokens in the restored database, or
  run `--reset-authority` (which now also retires the managed OAuth
  signing key, so every managed token fails closed). Treat a plain
  restore as preserving, not revoking, post-backup authority.
- Do NOT rotate the issuer key as part of this promotion. Rotation is a
  deliberate operation that invalidates all live access tokens
  immediately (grant rows survive, so clients can renew — but only after
  operator approval, because the pairing credential is single-use).
- A brand-new database generates a NEW issuer key on first use, so a
  fresh install also invalidates any previously issued tokens.

### 4. Issuer-key retention and client identity survive the rollback

`authz_clients` and `authz_grants` live in the same database as the
issuer key, so a paired binary+database rollback restores clients,
grants, revocations, and the signing key as one consistent unit. There is
no separate state to restore, and no key material outside the database.

## Procedure

### Step 0 — Verify the live relay before touching anything (read-only)

Run from a session that can reach the Pi:

```
sudo systemctl status ocliv-relay
sudo journalctl -u ocliv-relay -n 50 --no-pager
curl -fsS http://127.0.0.1:18080/health/live && echo
curl -fsS http://127.0.0.1:18080/health/ready && echo
sha256sum /usr/local/bin/ocliv
sudo sqlite3 /var/lib/ocliv/ocliv.db 'SELECT MAX(v) FROM schema_version;'
```

Record every value. **A pre-V11 live database migrates on the FIRST open by
the new binary** — the same `relay backup` command in step 1 opens the
database read-only, so confirm the current `schema_version` first and take
the backup from the SAME database state you recorded.

Expected at the time this plan was written (last verified production
state): relay active, binary `0d47481f2e2b7cbff4df57a713f0e39849be92cd85deabd5f256be07a00d0b1`,
health 200/200. If the recorded values differ, STOP and reconcile first.

### Step 1 — WAL-safe backup (before any binary change)

```
sudo -n /usr/local/bin/ocliv relay backup --data /var/lib/ocliv --out /var/lib/ocliv/ocliv.db.bak-20261113-095500
sudo sha256sum /var/lib/ocliv/ocliv.db.bak-20261113-095500 | sudo tee /var/lib/ocliv/ocliv.db.bak-20261113-095500.sha256
sudo chmod 600 /var/lib/ocliv/ocliv.db.bak-20261113-095500*
```

Use a literal timestamped filename (shell variables do not survive nested
sudo quoting and produce stray `ocliv.db-.backup` files). Keep the sidecar
with the image. The data directory is root/ocliv-only, so these need root —
do not loosen its permissions to make it agent-readable.

### Step 2 — Build and stage the candidate (off-Pi, on the build host)

```
cd <clean clone at 95cc66c>      # no uncommitted changes
GOOS=linux GOARCH=arm64 go build -o /tmp/ocliv-new ./cmd/ocliv
sha256sum /tmp/ocliv-new
# The ARM64 digest WILL differ from the amd64 qualification digest above.
# Record the arm64 digest as the promotion artifact; do not reuse it.
scp /tmp/ocliv-new piindasky:/tmp/ocliv-new
```

Stage to `/tmp`, **never over the live binary**.

### Step 3 — Install and restart (operator approval required)

Record the rollback pair BEFORE installing:

```
sudo cp -a /usr/local/bin/ocliv /usr/local/bin/ocliv.bak-20261113-095500
sudo sha256sum /usr/local/bin/ocliv.bak-20261113-095500
sudo install -o root -g root -m 0755 /tmp/ocliv-new /usr/local/bin/ocliv.new
sudo sha256sum /usr/local/bin/ocliv.new
sudo mv /usr/local/bin/ocliv.new /usr/local/bin/ocliv
sudo systemctl restart ocliv-relay
sudo journalctl -u ocliv-relay -n 30 --no-pager
```

The first open migrates the production database to V11 **in place**. This
is the point of no easy return: from here, only the paired rollback below
works.

### Step 4 — Post-deploy verification

```
curl -fsS http://127.0.0.1:18080/health/live  && echo    # expect ok
curl -fsS http://127.0.0.1:18080/health/ready && echo    # expect ok
sha256sum /usr/local/bin/ocliv                          # matches step 3
sudo sqlite3 /var/lib/ocliv/ocliv.db 'SELECT MAX(v) FROM schema_version;'   # expect 11
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://<public-host>/r/<route-id>/mcp               # expect 401 (NOT 421, NOT 404)
curl -sS https://<public-host>/.well-known/oauth-protected-resource/r/<route-id>/mcp | head -3
```

The 401 must carry the **new** challenge:

```
WWW-Authenticate: Bearer resource_metadata="https://<public-host>/.well-known/oauth-protected-resource/r/<route-id>/mcp"
```

If it still carries `resource_uri=`, the old binary is still running.
Then confirm a published route still serves end to end (tools/call) before
declaring the promotion complete.

## Rollback (paired — binary AND database)

**Do NOT hand-copy the database with `cp -a`.** A raw `cp -a` bypasses the
restore-time rollback guard, so it can silently resurrect revoked agent
keys, terminal leases, tombstoned publications, AND managed OAuth clients/
grants/tokens that were revoked after the snapshot. Use the application's
guarded restore, which refuses a restore that would roll any of that
authority backward (unless you explicitly pass `--reset-authority`):

```
sudo systemctl stop ocliv-relay
sudo /usr/local/bin/ocliv relay restore --data /var/lib/ocliv   --in /var/lib/ocliv/ocliv.db.bak-20261113-095500 --relay-stopped
# paired binary rollback (no live schema dependency on the binary path):
sudo cp -a /usr/local/bin/ocliv.bak-20261113-095500 /usr/local/bin/ocliv
sudo systemctl start ocliv-relay
curl -fsS http://127.0.0.1:18080/health/live  && echo
curl -fsS http://127.0.0.1:18080/health/ready && echo
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://<public-host>/r/<route-id>/mcp               # expect 401
```

**Never do a binary-only rollback** — the pre-V11 binary refuses a V11
database (`case v > currentSchema` fails closed) and the relay stays DOWN.
Restore both, or neither.

**After a paired rollback, tell the operator what to expect:** the
restored database brings back the snapshot's signing key AND the
snapshot's clients/grants. Tokens issued after the backup moment were
signed by that same key, so **they may still verify and remain usable** —
a plain restore does not revoke them. If the goal is to cut authority,
either revoke the affected managed clients/grants/tokens after the
restore, or restore with `--reset-authority` (which retires the managed
signing key and revokes managed clients/grants, forcing re-registration
and re-approval).

## Explicit non-goals during this promotion

- No production migration, schema change, or binary replacement was
  performed during qualification. `/var/lib/ocliv` was never used as a
  staging database; qualification ran against an isolated staging DB in
  `/tmp` with its own HOME dirs and a loopback-bound relay.
- Rotating the issuer key is NOT part of this promotion (it invalidates
  every live access token on purpose).
- No second proxy or gateway is introduced; the Caddy/Pi-hole/Tailscale
  topology is unchanged.

## Gate status this plan rests on

All passed at `95cc66c` (go1.26.10): build, vet, gofmt, `git diff --check`;
`go test ./internal/... -count=1` green (18 packages); integration suite
green (248s, 420s cap); race green on relay/agent/cli/authz/limits/apperr/
protocol; and the 37/37 isolated staging qualification with the official
Python MCP SDK 1.28.1 over trusted HTTPS — full flow, tools/list,
tools/call, refresh rotation, refresh-replay rejection, token revocation,
same-key restart, cross-key takeover refusal, unpublish with durable grant
retirement, and no unauthorized upstream executions.