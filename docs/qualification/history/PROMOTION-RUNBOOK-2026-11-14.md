# Production promotion runbook — qualified candidate `7674c4b`

**Status: HOLD — production schema/identity preflight and explicit operator approval are still required.**
This runbook now names the clean-source ARM64 candidate that passed the
isolated Pi staging qualification. It includes the publication-rebind,
read-only inventory, named-profile, managed-stdio session, lease-renewal, and
ingress-verifier corrections. Production has not been changed. The root-only
production database schema and route/identity records remain unread.

**Source-state boundary (2026-11-16):** the exact ARM64 artifact below was
built from clean commit `7674c4b4881b2824f6dc204206f51a46d4ff6ec4` and
qualified on PiInDaSky in an isolated loopback stage. The source gate passed
`go test ./...`, `go test -race ./internal/...`, `go vet ./...`, and all 86
Skybridge tests. Production remains unchanged and on HOLD pending the
operator-only gates below.

---

## 1. Qualified artifact (immutable)

| Field | Value |
|---|---|
| Source commit | `7674c4b4881b2824f6dc204206f51a46d4ff6ec4` (`test(cli): avoid stdout race during active publishers`) |
| Branch | `fix/production-review-2026-11-15` |
| Go toolchain | go1.26.10 linux/amd64 |
| Build config | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w"` |
| **ARM64 SHA-256** | **`e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5`** |
| Binary size | 13,697,186 bytes (static aarch64, stripped) |
| Schema reached on open | **V11** (forward-only) |

This candidate includes the publication-recovery, OAuth, doctor, stream
cancellation, systemd, Caddy, setup, DCR quota, and qualification changes in
its source history. It supersedes `efe3a8e` / `aef41e6…`, `d9ea67b` /
`7f438b63…`, `2089516` / `65ed20b2…`, `19d46d8` /
`1ceaaff4…`, and `f2d2bec` / `fe48fb96…`. Earlier binaries must not be
deployed. Exact build and Pi qualification evidence:
`docs/qualification/PI-ISOLATED-RESULT-2026-11-16.md` and
`docs/qualification/pi-staging/PROVENANCE.txt`.

Build (off-Pi, on the build host, from a clean checkout of the exact qualified source commit):
```
cd <clean clone at 7674c4b4881b2824f6dc204206f51a46d4ff6ec4>
RELEASE_DIR="$HOME/releases/ocliv/7674c4b"
mkdir -p "$RELEASE_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o "$RELEASE_DIR/ocliv-arm64" ./cmd/ocliv
printf '%s  %s\n' 'e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5' "$RELEASE_DIR/ocliv-arm64" | sha256sum --check
```

---

## 2. Isolated Pi qualification result — **29 PASS / 0 FAIL** on the clean-source `7674c4b` / `e5cd410b…` artifact

Executed on PiInDaSky against the real ARM64 binary, **loopback only**, in an
owner-only staging dir (`~/ocliv-stage`, 0700), a **separate SQLite DB**, and
**independently allocated loopback ports** (28080 relay / 28085 health /
28099 harmless MCP upstream). Production untouched. Reproduce with
`/home/bamn/ocliv-stage/stage-7674c4b-20261116-recorded/qualify-pi-isolated.py`.

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

### Step 0 — Read-only pre-flight + production inventory (HARD GATE)
```
ssh bamn@10.9.66.170
sudo systemctl status ocliv-relay --no-pager
curl -fsS http://127.0.0.1:18080/health/live && echo
curl -fsS http://127.0.0.1:18080/health/ready && echo
sha256sum /usr/local/bin/ocliv        # expect 0d47481f... (pre-remediation)

# Read-only schema-aware inventory. Does not call store.Open or migrate.
sudo python3 - <<'PYQ'
import sqlite3

path = "file:/var/lib/ocliv/ocliv.db?mode=ro"
db = sqlite3.connect(path, uri=True)
db.execute("PRAGMA query_only=ON")

def columns(table):
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}

tables = {row[0] for row in db.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}

print("=== SCHEMA ===")
if "schema_version" not in tables:
    raise SystemExit("STOP: schema_version table missing")
version = db.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]
print("schema_version:", version)
if version is None or version > 11:
    raise SystemExit("STOP: unsupported schema")

print("=== MANAGED CLIENTS ===")
if "authz_clients" not in tables:
    print("authz_clients: absent")
else:
    cols = columns("authz_clients")
    print("columns:", sorted(cols))
    fields = [
        name for name in ("id", "tenant_id", "route_id", "revoked_at")
        if name in cols
    ]
    if fields:
        for row in db.execute("SELECT " + ", ".join(fields) + " FROM authz_clients"):
            print(dict(zip(fields, row)))
    else:
        print("authz_clients: no recognized columns")
    if {"tenant_id", "route_id"} <= cols:
        query = (
            "SELECT COUNT(*) FROM authz_clients "
            "WHERE tenant_id='' OR tenant_id IS NULL "
            "OR route_id='' OR route_id IS NULL"
        )
        count = db.execute(query).fetchone()[0]
        print("unbound_clients:", count)
    else:
        print("client_binding_columns: PRE_V11")

print("=== PUBLISHER IDENTITIES ===")
if "agent_keys" not in tables:
    print("agent_keys: absent")
else:
    cols = columns("agent_keys")
    fields = [name for name in ("id", "tenant_id", "status", "revoked_at") if name in cols]
    print("columns:", sorted(cols))
    if fields:
        for row in db.execute("SELECT " + ", ".join(fields) + " FROM agent_keys"):
            print(dict(zip(fields, row)))
    else:
        print("agent_keys: no recognized identity/status columns")

print("=== TENANTS ===")
if "tenants" not in tables:
    print("tenants: absent")
else:
    cols = columns("tenants")
    fields = [name for name in ("id", "status", "suspended_at") if name in cols]
    print("columns:", sorted(cols))
    if fields:
        for row in db.execute("SELECT " + ", ".join(fields) + " FROM tenants"):
            print(dict(zip(fields, row)))
    else:
        print("tenants: no recognized identity/status columns")

print("=== PUBLICATIONS ===")
for table in ("mcp_publications", "mcp_routes"):
    if table not in tables:
        print(table, "absent")
        continue
    cols = columns(table)
    fields = [
        name for name in (
            "route_id", "tenant_id", "owner_key_id", "external_host",
            "profile", "pub_name", "lease_id", "verified_at", "revoked_at",
        ) if name in cols
    ]
    print(table, "columns:", sorted(cols))
    if fields:
        for row in db.execute("SELECT " + ", ".join(fields) + " FROM " + table):
            print(dict(zip(fields, row)))
    else:
        print(table, "no recognized columns")

print("=== LEASES ===")
if "leases" in tables:
    cols = columns("leases")
    fields = [
        name for name in (
            "id", "tenant_id", "agent_key_id", "hostname", "status",
            "expires_at",
        ) if name in cols
    ]
    if fields:
        for row in db.execute("SELECT " + ", ".join(fields) + " FROM leases"):
            print(dict(zip(fields, row)))
    else:
        print("leases: no recognized columns")
db.close()
PYQ
```

The query handles pre-V11 `authz_clients` layouts and absent publication or
managed-auth tables. It prints identity and ownership metadata only; it does
not select signing keys, password hashes, bearer credentials, enrollment
verifiers, or pairing credentials. Record the full output. If the schema is
unreadable, newer than V11, or the known route ownership is ambiguous, STOP.
Do not delete historical publication records based on an HTTP 404.

### Step 1 — WAL-safe backup (operator, root)
```
TS=$(date -u +%Y%m%d-%H%M%S)
sudo /usr/local/bin/ocliv relay backup --data /var/lib/ocliv --out /var/lib/ocliv/ocliv.db.bak-$TS
# Ocliv creates and verifies the .sha256 sidecar itself; do not overwrite it.
sudo /usr/local/bin/ocliv relay validate-backup --in /var/lib/ocliv/ocliv.db.bak-$TS
# Optional independent evidence goes to a distinct path, never the .sha256 sidecar.
sudo sha256sum /var/lib/ocliv/ocliv.db.bak-$TS | sudo tee /var/lib/ocliv/ocliv.db.bak-$TS.external.sha256
sudo chmod 600 /var/lib/ocliv/ocliv.db.bak-$TS*
```
Proceed to Step 2 and binary replacement only after `relay validate-backup`
has succeeded. Preserve both the database snapshot and Ocliv-generated sidecar.

### Step 2 — Build + stage the candidate (build host; digest MUST match §1)
```
# already built; verify the digest before transfer:
sha256sum "$RELEASE_DIR/ocliv-arm64"    # == e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5
ssh bamn@10.9.66.170 'install -d -m 0700 /home/bamn/ocliv-stage/candidates/7674c4b'
scp "$RELEASE_DIR/ocliv-arm64" bamn@10.9.66.170:/home/bamn/ocliv-stage/candidates/7674c4b/ocliv-arm64
ssh bamn@10.9.66.170 'chmod 0600 /home/bamn/ocliv-stage/candidates/7674c4b/ocliv-arm64 && sha256sum /home/bamn/ocliv-stage/candidates/7674c4b/ocliv-arm64'
```

### Step 3 — Install + restart (**operator approval required** — point of no easy return)
```
TS=<same timestamp as Step 1>
sudo cp -a /usr/local/bin/ocliv /usr/local/bin/ocliv.bak-$TS
sudo sha256sum /usr/local/bin/ocliv.bak-$TS
sudo install -o root -g root -m 0755 /home/bamn/ocliv-stage/candidates/7674c4b/ocliv-arm64 /usr/local/bin/ocliv.new
sudo sha256sum /usr/local/bin/ocliv.new        # == e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5
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
sha256sum /usr/local/bin/ocliv                           # e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5
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
  binary (`e5cd410b…`) over the bad one; the V11 DB stays valid. The only
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

## 6. Separate operator decisions (explicit)

These approvals are independent; one does not imply the other.

| Decision | Required authorization |
|---|---|
| Advance production DB to V11 | Explicit operator approval after Step 0 inventory, validated Step 1 backup, exact candidate digest check, and acceptance of forward-only recovery and possible post-backup state loss. |
| Establish or restore public MCP publication | Separate approval naming the intended service/upstream and public exposure. Preserve an eligible existing route ID and owner; do not infer approval from migration approval. |

Do not issue a production enrollment code, install a publisher unit, bind a
new route, or expose a service until the publication decision is approved.

## 7. V11 migration approval gates (explicit)

The V11 migration is **NOT authorized** until the operator confirms each gate:
1. **Pre-flight recorded** (binary `0d47481f...`, health ok/ok, **live schema
   version confirmed ≤ V11**, managed-client and publication/lease ownership
   inventory taken).
2. **Backup taken + checksum sidecar written** (Step 1).
3. **Candidate digest verified** as `e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5` on the Pi (Step 2).
4. **Explicit migration approval** after reviewing the inventory, backup
   recovery point, and forward-only V11 consequences.
5. **Install + restart** (Step 3) — the operator runs this deliberately.
6. **Post-deploy health/schema checks green** (Step 4).
7. **Recovery path understood** (§5: forward-only, roll-forward with the
   candidate binary — no old-binary rollback is possible once the DB reaches
   V11).

## 8. Separate publication approval (not granted)

Migration approval does not authorize publisher enrollment, publisher-unit
installation, route rebinding, or public MCP exposure. Before those actions,
the operator must separately name and approve the intended service/upstream,
publisher host/account, and public route. First use the Step 0 inventory to
decide whether to recover the known route ID or create a new publication.
Verify only the intended publisher unit is installed for that service; do not
enable both unit variants for the same publication. Keep this approval separate
from the V11 migration decision.

## 9. NOT VERIFIED (out of isolated-loopback scope)

- **Public-edge / off-LAN reachability** and a real `tools/call` through the
  public HTTPS edge — loopback/tailnet staging cannot prove this; it is a
  post-promotion, off-LAN check (Step 4 / gate 5).
- **Live production DB schema version** (root-only; not yet read).
- **ChatGPT registration** and any provider-IdP OAuth.

---

*Qualified 2026-11-16 on PiInDaSky (10.9.66.170), isolated loopback staging.*
*Candidate `7674c4b`, ARM64 `e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5`, 29/29 isolated Pi checks green. Production remains HOLD pending root-only preflight and explicit promotion approval.*
