# Managed authorization — external qualification results (2026-11-12)

Run against the **ISOLATED staging stack only**. The production Pi relay was
not deployed to, not restarted, and not written to.

## 1. Topology and isolation

| Piece | Where | Evidence |
|---|---|---|
| Staging relay | pop-os, `127.0.0.1:18085` (control) + `127.0.0.1:18086` (health) | `ss -ltn` shows **loopback only** — the project's "no public relay listener" non-negotiable holds |
| Staging DB | pop-os, `/home/bamn/.hermes/cache/scratch/staging/data/ocliv.db` (0600, inside a 0700 dir) | separate file, separate dir; **not** `/var/lib/ocliv` |
| TLS edge | pop-os `100.77.54.48:18443` (tailnet IP), self-signed cert | the only public listener; terminates TLS and forwards to `127.0.0.1:18085` |
| Publisher | Pi `10.9.66.170`, user unit `ocliv-staging-publish` | `--relay https://pop-os.tail8d285a.ts.net:18443` → resolves to pop-os; the route registered in the **staging** DB proves it |
| Harmless upstream | Pi, stdio `upstream.py` → `ocliv-staging-adapter` | returns a single `ping` tool; no side effects |
| Operator CLI | pop-os, `/tmp/ocliv-staging authz … --data <staging dir>` | runs against the staging DB only |

**Production isolation, proven:** the Pi's production relay still runs the
2026-11-11 binary (sha256 `0d47481f2e2b7cbff34df57a713f0e39849be92cd85deabd5f256be07a00d0b1`),
its health is `live=200 ready=200`, and `/var/lib/ocliv` is root-owned and
**unreadable** to the staging operator — the staging work never reached it.

**Rollback (demonstrated, not hypothetical):** stop the Pi user units
`ocliv-staging-publish` / `ocliv-staging-adapter` / `ocliv-staging-edge` /
`ocliv-staging-relay`; kill the pop-os staging relay (`127.0.0.1:18085`) and
the edge proxy (`100.77.54.48:18443`); remove
`/home/bamn/.hermes/cache/scratch/staging/` (2.8 MB data + 20 KB edge) and the
Pi's `~/ocliv-staging/`. Nothing outside those paths is touched.

## 2. Build under test

```
relay+agent : d38c3e89a3734f49e65b26c14f9b3313bf78f5c62b067f33985d5423c0d9fc66  /tmp/ocliv-staging
arm64 agent : 1d9c200d46d448bb45dba2454e06c5b6c5d8e7391023eaa107f041797d54ad93  ocliv-staging/ocliv-new (Pi)
route       : 8tiVen6x2ckCO1jIrX5gKQ  profile=managed-oauth  verified_at set
tenant      : tenant-enr-1794484103596471316
```

Relay DB migrated `schema_version 10 → 11` automatically at startup; the
staging relay reports `live=200 ready=200`.

## 3. Results — 41/41 checks PASS

### Part 1 — flow, denial paths, revocation (30/30)

| # | Check | Result |
|---|---|---|
| G1 | route-scoped PRM served | 200, `resource` = the route's canonical URL |
| G2 | route-scoped AS metadata served | 200, `issuer` = `…/r/<id>/oauth` |
| G3 | no bearer denied | 401 |
| G4 | ordinary OAuth client completes the full flow | DCR → authorize → approve → consent POST → PKCE token |
| G5 | every issued token carries a jti | `jti=rR-xvCAOkXFjdsF4L-ZwOA` |
| G6 | token audience bound to the canonical resource | `aud=['…/r/<id>/mcp']` |
| G7 | authorized client reaches the MCP route | 200 |
| G8 | `tools/list` returns the harmless upstream's tool | 200, `ping` |
| G9 | **no credential in the authorize URL** | no `Location`, no pairing material |
| G10 | the credential is not in the consent page | the page carries the field **name** only |
| G11 | operator approval issues a credential | `pair_…` |
| G12 | **approval alone yields no code** | consent is separate from approval |
| G13 | consent POST with the credential issues a code | 302 |
| G14 | the consent challenge is one-time | replay → 400 |
| G15 | a consumed credential cannot complete a second consent | 403 |
| N1 | tampered bearer | 401 |
| N2 | missing bearer | 401 |
| N3 | authorization-code replay | 400 `invalid_grant` ("already used") |
| N4 | wrong PKCE verifier | 400 `invalid_grant` ("PKCE verification failed") |
| N5 | foreign resource on authorize | 400 `invalid_target` |
| N6 | foreign resource on token | 400 `invalid_target` |
| N7 | missing resource on authorize | 400 |
| G16 | RFC 7009 revoke | 200 |
| G17 | the revoked token is denied on the **next** request | 401 |
| G18 | an unrelated client's token still works | 200 |
| G19 | invalid token revoke | 200 (RFC 7009 §2.2) |
| G20 | the operator can revoke a client grant | exit 0 |
| G21 | a revoked client's **existing** token is denied | 401 |
| G22 | a revoked client cannot redeem a previously issued code | 400 |
| G23 | revoking one client leaves other clients working | 200 |

### Part 1 addendum — a FRESH code from a revoked client (2/2)

| # | Check | Result |
|---|---|---|
| A1 | a revoked client cannot redeem a **never-redeemed** code | 400 `invalid_grant` — *"client is not approved for this route"* (the revocation is the reason, not "already used") |
| A2 | the rejected code is burned (fail-closed) | `consumed_at=2026-11-12T18:54:47Z` — a failed redemption is never retried, exactly like a failed PKCE exchange |

### Part 2 — the ordering-sensitive pair (9/9)

Run order: **publisher restart (§3.8) first, key rotation (§3.9) second**,
with the rotation token minted *fresh after* the restart.

| # | Check | Result |
|---|---|---|
| P1 | starting state: a live token works before the restart | 200 |
| P2 | the publisher restarted and is active | active |
| P3 | **the route id is stable across the publisher restart** | `8tiVen6x2ckCO1jIrX5gKQ` (unchanged) |
| P4 | the **pre-restart** token still works (approval survived) | 200 |
| P5 | exactly one active grant before and after | before=1 after=1 |
| P6 | starting state: a fresh post-restart token works before the rotation | 200 |
| P7 | the issuer key rotated | `kid sXVJUgBAmHrDaI6_DX82Qg` |
| P8 | the pre-rotation token is refused **immediately**, no relay restart | 401 |
| P9 | a token minted after the rotation works with the new key | 200 |

## 4. Bugs this run found and fixed (red → green)

| # | Defect | Evidence | Disposition |
|---|---|---|---|
| F1 | `mcp publish --auth ocliv-managed` sent the CLI auth name as the ingress profile, so route creation failed closed with `400 unknown ingress profile` | live publish log: *"route registration failed (relay … status 400): unknown ingress profile"*; the other two names coincide, which is why only managed mode broke | **FIXED** — `mcpIngressProfile()` maps `ocliv-managed` → `managed-oauth`; regression `TestMCPIngressProfileMapping` |
| F2 | a managed publication was left **unverified** by the lease reclaim and the route rebind, so a publisher restart left the route 404 and every token dead (there is no upstream discovery to re-verify a relay-terminated route) | live: publication `verified_at` NULL after the reclaim → route 404; `TestManagedAuthzReclaimKeepsRouteServing` fails red (`post-reclaim call status=404`) | **FIXED** — `verified_at` is preserved for the managed profile in both the reclaim carry-over and the route rebind; green after; live P3/P4 prove it |
| F3 | the SQLStore test schema lagged the store schema (missing `tenant_id`/`route_id`/`pairing_expires_at`/`consented_at`/`resource`) | `SQL logic error: table authz_clients has no column named tenant_id` | **FIXED** — test schema brought to the v11 shape |
| F4 | `TestMCPPortAliasArgs` demanded that `mcp publish --auth fixture-anonymous` be **accepted**, contradicting the standing invariant that an anonymous fixture can never back a public route | test failure + `mcp publish --auth fixture-anonymous is disabled: …` | **FIXED** — the test now asserts the refusal (which is itself the proof that the explicit `--auth` was preserved) and the preserved `cfg.auth` |
| F5 | `mcp publish --auth ocliv-managed` accepted `--strict-discovery`, `--dev-allow-unverified-discovery` and `--resource-file`, which imply an upstream that does not exist | `mcp publish --auth ocliv-managed takes no --strict-discovery: the relay is the Authorization Server, not an upstream` | **FIXED** (in-tree, covered by CLI tests) |

## 5. Gates

| Gate | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `gofmt -l internal/ tests/` | clean |
| `go test ./internal/... -count=1` | 19/19 packages green |
| `go test -count=1 ./tests/integration/` | green (331 s) |
| `go test -race` relay/agent/config/cli/mcp/authz | green (one unreproduced timing flake in `TestNoisyFailingChild`, 3/3 green on re-run) |

**The documented integration cap (`-timeout 280s`) is now too tight**: the
green suite takes 331 s, so the gate fails on a healthy tree. Raise it to
`-timeout 420s`.

## 6. Not qualified (explicitly out of scope / operator-gated)

* **ChatGPT registration** — the managed flow requires an operator-mediated
  consent and a single-use credential per authorization; an unattended client
  cannot complete it. Not qualified, not claimed.
* **Production deployment** — the managed mode was **not** deployed to the Pi
  production relay. The production binary and DB are untouched.
* **Public-internet reachability** — the edge used here is a self-signed TLS
  terminator on a tailnet IP, not a public ACME/Caddy edge.
* **Key-rotation effect on already-issued tokens of *other* tenants/routes** —
  out of scope here; revocation isolation is covered by the unit/integration
  tests.
