# Production promotion runbook — qualified candidate `2089516`

**Status: QUALIFIED IN ISOLATED PI STAGING, AWAITING OPERATOR APPROVAL.**
This is the promotion package for the remediated Ocliv candidate. It rests on
a **passing, reproducible isolated qualification** of the exact ARM64 artifact
on PiInDaSky. **No production change has been made.** Every privileged step is
an explicit operator gate. Do not execute until you choose to promote.

---

## 1. Qualified artifact (immutable)

| Field | Value |
|---|---|
| Source commit | `2089516da0180dee0ee95b6c915335e6cdf572c4` |
| Branch | `master` |
| Go toolchain | go1.26.10 linux/amd64 |
| Build config | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w"` |
| **ARM64 SHA-256** | **`65ed20b21eddb40b3cdf3fbb60388dc7deb81066fec6dda9c0142043727b8a53`** |
| Binary size | 13,500,578 bytes (static aarch64, stripped) |
| Schema reached on open | **V11** (forward-only) |

This candidate supersedes `19d46d8` / `1ceaaff4…` and `f2d2bec` /
`fe48fb96…`: it adds the 2026-11-15 rereview corrections (issuer rotation
persistence, strict authz flag parsing, read-only restore preflight,
clean-host service rollback, autoEnroll relay-identity verification,
read-only inventory commands). Earlier binaries must not be deployed.
Provenance: `docs/qualification/pi-staging/PROVENANCE.txt`.

Build (off-Pi, on the build host, from a clean checkout of `19d46d8`):
```
cd <clean clone at 19d46d8>
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /tmp/ocliv-arm64 ./cmd/ocliv
sha256sum /tmp/ocliv-arm64    # MUST equal 65ed20b2... above
```

---

## 2. Isolated Pi qualification result — **29 PASS / 0 FAIL** (re-run on the `2089516` / `65ed20b2…` artifact)

Executed on PiInDaSky against the real ARM64 binary, **loopback only**, in an
owner-only staging dir (`~/ocliv-stage`, 0700), a **separate SQLite DB**, and
**independently allocated loopback ports** (28080 relay / 28085 health /
28099 harmless MCP upstream). Production untouched. Reproduce with
`~/ocliv-stage/pi_qual.py`.

| Area | Checks | Result |
|---|---|---|
| A: startup, schema, health | 2 managed routes active; **schema V11**; health live | PASS |
| A2: restart persistence | route survives relay restart (401 durable publication) | PASS |
| B: managed OAuth happy path | DCR → authorize consent → approve → consent → **authorization code** → **access+refresh token** → tools/list → tools/call executes exactly once → **relay-minted identity injected, external bearer stripped** | PASS |
| C: refresh rotation | new pair issued; **old refresh-token replay rejected (400)** | PASS |
| D: security boundaries | no-bearer/forged/tampered all **401 + zero upstream executions**; spoofed identity headers stripped (relay-minted kept); cross-route authorize/code/revoke all refused without destroying legitimate state; **malformed trailing JSON refused**; consent challenge replay rejected | PASS |
| E: recovery rehearsal (staging only) | guarded backup; **managed revocation rollback refused** (`restore would resurrect ... authz-grant:...`); **reset-authority invalidates managed clients/grants and deletes the signing key** (`ik 0`) | PASS |

### Security-boundary detail (the point of the remediation)
- **Cross-route client**: route-A client id refused at route-B authorize (400).
- **Cross-route code**: route-A authorization code refused at route-B token
  (400), and the legitimate route-A code is **not destroyed** (redeems 200).
- **Cross-route revocation**: token revoked at route-B returns RFC 7009 200
  **with no durable poison**; the token remains valid at route-A until a
  legitimate route-A revocation (the jti is not consumed by route-B).
- **Identity headers**: visitor-supplied `X-Ocliv-Upstream-Sub` / `X-Ocliv-Route`
  are stripped; the upstream sees only relay-minted values (client + route),
  and the external `Authorization` never reaches the upstream.

---

## 3. Schema compatibility

- **V11 is forward-only.** A binary older than V11 **refuses** a V11 database
  (`case v > currentSchema` fails closed). Confirmed by
  `TestOpenIdempotentAndDowngradeRefused`. `relay restore` migrates its
  scratch copy to V11 before installing, so **no old-binary paired rollback
  exists** — recovery is roll-forward (§5).
- The candidate opens a fresh DB at **V11**. The **live production DB schema
  version is NOT YET CONFIRMED** (read was denied; `sqlite3` absent; DB is
  root-only). **This is a hard pre-promotion gate** (Step 0 below).
- **Legacy-client compatibility:** schema V11 binds each managed OAuth client
  to a `(tenant_id, route_id)` with **empty-string defaults for legacy rows**.
  The new source **intentionally refuses unbound (empty) registrations**
  (fail-closed, `TestLegacyUnboundClientFailsClosed`). Consequence: after
  upgrading, **pre-existing managed OAuth clients with empty tenant/route may
  need re-registration and operator re-approval.** Inventory live managed
  clients before promoting.

---

## 4. Promotion procedure (operator-gated at each privileged step)

### Step 0 — Read-only pre-flight + **confirm live schema version (HARD GATE)**
```
ssh bamn@10.9.66.170
sudo systemctl status ocliv-relay --no-pager
curl -fsS http://127.0.0.1:18080/health/live && echo
curl -fsS http://127.0.0.1:18080/health/ready && echo
sha256sum /usr/local/bin/ocliv        # expect 0d47481f... (pre-remediation)
# HARD GATE — live DB schema. `relay doctor` does NOT report schema version
# and `sqlite3` is not installed on the Pi, so use a genuinely read-only
# Python query (uri mode=ro; store.Open is NEVER called, so no migration):
sudo python3 - <<'PYQ'
import sqlite3
db = sqlite3.connect("file:/var/lib/ocliv/ocliv.db?mode=ro", uri=True)
print("schema_version:", db.execute(
    "SELECT MAX(v) FROM schema_version").fetchone()[0])
tables = {r[0] for r in db.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}
if "authz_clients" in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(authz_clients)")}
    if {"tenant_id", "route_id"} <= cols:
        n = db.execute(
            "SELECT COUNT(*) FROM authz_clients "
            "WHERE tenant_id='' OR route_id=''").fetchone()[0]
        print("unbound_managed_clients:", n)
    else:
        print("managed_client_scope_columns: absent")
db.close()
PYQ
#   - If live schema < V11: the candidate migrates forward on first open. OK.
#   - If live schema > V11 (impossible on prod today) or unreadable: STOP.
# Inventory managed clients (identify legacy empty-tenant/route rows).
# Tolerate an absent authz_clients table: the pre-V8 production binary (V7)
# predates managed authorization, so there may be nothing to inventory.
sudo python3 - <<'PYQ'
import sqlite3
db = sqlite3.connect("file:/var/lib/ocliv/ocliv.db?mode=ro", uri=True)
tables = {r[0] for r in db.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}
if "authz_clients" in tables:
    for row in db.execute(
            "SELECT id, tenant_id, route_id, revoked_at FROM authz_clients"):
        print(row)
else:
    print("authz_clients: absent (pre-managed-authorization schema)")
db.close()
PYQ
```
**Record every value. If the recorded binary differs from `0d47481f...`, STOP
and reconcile first.** Legacy managed clients (empty tenant/route) must be
noted for post-upgrade re-registration.

### Step 1 — WAL-safe backup (operator, root)
```
TS=$(date -u +%Y%m%d-%H%M%S)
sudo /usr/local/bin/ocliv relay backup --data /var/lib/ocliv --out /var/lib/ocliv/ocliv.db.bak-$TS
sudo sha256sum /var/lib/ocliv/ocliv.db.bak-$TS | sudo tee /var/lib/ocliv/ocliv.db.bak-$TS.sha256
sudo chmod 600 /var/lib/ocliv/ocliv.db.bak-$TS*
```

### Step 2 — Build + stage the candidate (build host; digest MUST match §1)
```
# already built; verify the digest before transfer:
sha256sum /tmp/ocliv-arm64    # == 65ed20b2...
scp /tmp/ocliv-arm64 bamn@10.9.66.170:/tmp/ocliv-new
ssh bamn@10.9.66.170 'sha256sum /tmp/ocliv-new'   # confirm 65ed20b2... on the Pi
```

### Step 3 — Install + restart (**operator approval required** — point of no easy return)
```
TS=<same timestamp as Step 1>
sudo cp -a /usr/local/bin/ocliv /usr/local/bin/ocliv.bak-$TS
sudo sha256sum /usr/local/bin/ocliv.bak-$TS
sudo install -o root -g root -m 0755 /tmp/ocliv-new /usr/local/bin/ocliv.new
sudo sha256sum /usr/local/bin/ocliv.new        # == 65ed20b2...
sudo mv /usr/local/bin/ocliv.new /usr/local/bin/ocliv
sudo systemctl restart ocliv-relay
sudo journalctl -u ocliv-relay -n 30 --no-pager
```
The first open migrates the production DB **in place** to V11. From here the
upgrade is **forward-only**: recovery is roll-forward with the candidate binary
(§5) — there is no rollback to the old executable once the DB reaches V11.

### Step 4 — Post-deploy verification
```
curl -fsS http://127.0.0.1:18080/health/live && echo     # ok
curl -fsS http://127.0.0.1:18080/health/ready && echo    # ok
sha256sum /usr/local/bin/ocliv                           # 65ed20b2...
sudo python3 - <<'PYQ'
import sqlite3
db = sqlite3.connect("file:/var/lib/ocliv/ocliv.db?mode=ro", uri=True)
print("schema_version:", db.execute(
    "SELECT MAX(v) FROM schema_version").fetchone()[0])
db.close()
PYQ
# live route still protected (expect 401 with resource_metadata challenge):
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://<public-host>/r/<route-id>/mcp                # expect 401 (NOT 421/404)
# confirm a full authorized tools/call through the public edge from an
# off-LAN client, and that unauthorized requests cause ZERO upstream executions.
# Legacy managed clients with empty tenant/route: re-register + re-approve.
```

---

## 5. Recovery (**forward-only — roll-forward, NOT binary rollback**)

This upgrade is **forward-only**: `restore` runs `store.Open` on the backup,
which migrates the scratch copy forward to **V11 before installing it**. Any
binary older than V11 refuses a V11 database (`case v > currentSchema` fails
closed). Therefore **rolling back to the old binary is NOT possible after the
candidate opens the production DB** — there is no paired binary+database
rollback to the pre-upgrade state.

**Recovery = roll forward with the candidate binary:**

```
sudo systemctl stop ocliv-relay
# Use the application's GUARDED restore — NEVER hand-copy the DB with cp:
sudo /usr/local/bin/ocliv relay restore --data /var/lib/ocliv \
  --in /var/lib/ocliv/ocliv.db.bak-$TS --relay-stopped
sudo systemctl start ocliv-relay
curl -fsS http://127.0.0.1:18080/health/live && echo
```

- The guarded restore enforces revocation monotonicity: a live-revoked key,
  lease, publication, **managed client, managed grant (keyed by the full
  tenant/route/client tuple)**, or managed token jti that reads active in the
  backup is **refused** (unless `--reset-authority` is passed).
- **Token-validity truth:** restoring the DB restores its signing key, so
  tokens issued after the backup may **still verify** (a plain restore does
  not revoke them). To actually cut authority, revoke the affected managed
  clients/grants after restore, or restore with `--reset-authority` (which
  retires the managed signing key and revokes managed clients/grants, forcing
  re-registration).
- If the candidate itself is corrupt, reinstall the known-good candidate
  binary (`65ed20b2...`) over the bad one; the V11 DB stays valid. The only
  way back to the old binary is a full redeploy of the pre-upgrade image from
  backups taken in Step 1/Step 3 BEFORE the candidate ever opened the DB —
  and even then the guarded restore will refuse if post-backup revocations
  exist.

**Recovery-point tradeoff (explicit):** forward recovery restores
*availability*, not necessarily every post-backup change. The guard prevents
known authority from rolling backward (revoked keys/leases/publications/
managed clients/grants/tokens stay revoked), and `--reset-authority` is the
fail-closed escape hatch — but **neither preserves grants, sessions,
publications, or other state created after the backup**. Those are forward
data loss by the operator's explicit choice of restore point. Plan the backup
cadence accordingly.

**Do not** reinstall the old binary after the DB has reached V11 (it will
fail closed and the relay stays DOWN), and **never `cp -a` an older DB into
production** — it bypasses the rollback guard and can resurrect revoked
managed clients/grants/tokens.

---

## 6. Operator approval gates (explicit)

Promotion is **NOT authorized** until the operator confirms each gate:
1. **Pre-flight recorded** (binary `0d47481f...`, health ok/ok, **live schema
   version confirmed ≤ V11**, managed-client inventory taken).
2. **Backup taken + checksum sidecar written** (Step 1).
3. **Candidate digest verified** as `65ed20b2...` on the Pi (Step 2).
4. **Install + restart** (Step 3) — the operator runs this deliberately.
5. **Post-deploy checks green** (Step 4), including a full authorized
   `tools/call` through the **real public edge from an off-LAN client**.
6. **Recovery path rehearsed** and understood (§5: forward-only, roll-forward with the candidate binary — no old-binary rollback is possible once the DB reaches V11).

---

## 7. NOT VERIFIED (out of isolated-loopback scope)

- **Public-edge / off-LAN reachability** and a real `tools/call` through the
  public HTTPS edge — loopback/tailnet staging cannot prove this; it is a
  post-promotion, off-LAN check (Step 4 / gate 5).
- **Live production DB schema version** (root-only; not yet read).
- **ChatGPT registration** and any provider-IdP OAuth.

---

*Qualified 2026-11-14 on PiInDaSky (10.9.66.170), isolated loopback staging.*
*Candidate `2089516`, ARM64 `65ed20b2...`, 29/29 checks green (re-qualified on the promotion artifact; rereview deltas exercised).*
