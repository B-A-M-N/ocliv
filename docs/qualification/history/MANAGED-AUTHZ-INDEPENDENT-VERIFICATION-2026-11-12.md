# Managed authorization — independent external verification (2026-11-12)

Independent re-run of the 2026-11-12 managed-auth security-correction round
against REAL public HTTPS, executed separately from the earlier staging run
(`MANAGED-AUTHZ-RESULTS-2026-11-12.md`). This run's purpose is the check the
earlier run did not contain: the discriminating P0-1 observation — an
**ACTIVE and already-consented** grant must still not issue a code on its own.

Scope: staging only. The production Pi relay was not deployed to, not
restarted, and not written to.

## 1. Provenance (recorded before the run)

```
HEAD                : d3d283e (docs) — remediation committed at 17f2100
working-tree drift  : internal/store/store.go (one-line removal of a dead
                      consented_at column left in schemaV11 by the concurrent
                      session's commit; no Go code reads it)
binary             : sha256 7e319846c0ea37b3a0d2633960738a12e89b6e03797a186e22c824c832b0ed4e
staging DB         : /tmp/ocliv-qual/data2 (fresh, schema_version 11, 0700 dir)
```

## 2. Topology and isolation

| Piece | Where | Note |
|---|---|---|
| Public edge | `https://pop-os.tail8d285a.ts.net` (Tailscale funnel, publicly-trusted cert) | curl `ssl_verify_result=0` on every request |
| Staging relay | `127.0.0.1:18082` (behind the existing funnel mapping), health `127.0.0.1:18092` | loopback only; the funnel config was NOT modified |
| Staging DB | fresh dir, V11 verified at startup | never `/var/lib/ocliv` |
| Harmless upstream | `127.0.0.1:18999` (single `qual_ping` tool, execution counter) | zero-execution oracles |
| Publisher keys | 3 enrolled: owner key, plus two second keys for the cross-key test | one second key initially landed in a different tenant (see §5) |

The funnel's existing `/` → `127.0.0.1:18082` mapping was already dead; this
run bound the relay to that backend so the public 443 path served the staging
relay directly (the documented "direct relay on funnel backend port" pattern).
No serve/funnel config was added or changed.

## 3. Flow over public HTTPS (all via the public FQDN)

| # | Check | Result |
|---|-------|--------|
| V1 | publish via the bare alias (`ocliv mcp 18999` → managed default) | route registered, `verified_at` set |
| V2 | no-bearer `tools/list` on the public route | 401, zero upstream executions |
| V3 | DCR (loopback redirect) | 201, client id minted |
| V4 | authorize, registered-but-unapproved | 200 consent page, no `Location`, form action = `https://pop-os.tail8d285a.ts.net/r/<id>/oauth/consent`, no credential in the page |
| V5 | `authz approve` | one single-use credential (1h expiry) |
| V6 | consent POST to the form's OWN action URL | 302, `code` + `iss` + `state` |
| V7 | token exchange (resource + 43-char verifier) | Bearer, `expires_in 3600` |
| V8 | `tools/list` with the bearer | 200, exactly the fixture's tool |
| V9 | `tools/call` | 200, `pong:ocliv-qual-1`; upstream executions = 1 |

**V10 — the discriminating P0-1 check.** After V6 completed (grant ACTIVE,
credential consumed), a SECOND authorize with standard parameters only:

```
HTTP/2 200   (consent page — NO Location, NO code)
```

The discarded `ConsentedAt`-latch design would have returned 302 with a code
here. Only the per-transaction consent model holds. Completing a fresh
credential transaction then minted a code, so the boundary is per-transaction,
not a lockout.

## 4. Negative paths (each with a zero-execution oracle)

| # | Case | Result |
|---|------|--------|
| N1 | no bearer | 401 |
| N2 | tampered bearer | 401 |
| N3 | code replay | 400 `invalid_grant` (already used) |
| N9 | replayed consumed credential (fresh challenge) | 403 |
| N11 | token exchange with a 5-char verifier on a FRESH code | 400 `invalid_grant — code verifier must be 43-128 characters` |

Upstream executions after all negatives: still 1.

## 5. Reclaim boundaries

**Same-key restart (publisher restart):** publisher restarted with a fresh
agent data dir and the same key + same name → new lease id
(`lse-GDum52Dmq-X6IUHxLf0W9A`), the SAME route id
(`0p1GozvfleEDsW6WoFTz7w`, still verified), the pre-restart token still 200
(`pong:ocliv-qual-2`), and one `lease_reclaim ok` audit row. With the
publisher stopped in between, the route correctly returned 503.

**Cross-key, same tenant (the P0-2 boundary):** a second key enrolled into
the SAME tenant attempted the same hostname:

- no lease was created for it; the original lease stayed ACTIVE and bound,
- the original route + token kept serving (200), grants and publications
  unchanged, zero new upstream executions,
- 7 durable audit rows: `lease_reclaim denied — "named host held by a
  different agent key in this tenant"`, each paired with the attach-level
  conflict denial.

**Methodology note (honest):** the first cross-key attempt was INVALID — my
`--tenant` flag used the space form instead of `--tenant=`, so the relay
auto-minted a second tenant and the refusal observed was the cross-tenant
branch, not the owner-key branch. I detected this from the `agent_keys`
tenant ids, corrected the enrollment, and re-ran. The 7 denied rows above are
from the corrected same-tenant attempt. A mid-run read that briefly reported
zero denied rows was a stale WAL snapshot read; the final durable query
confirms both the attach-level and the owner-key rows.

## 6. Durable final state

```
leases:   1 (owner key, ACTIVE, same hostname)
route:    0p1GozvfleEDsW6WoFTz7w / managed-oauth / verified
grants:   1 active, credential consumed
codes:    2/2 consumed      consents: 4/4 consumed
audit:    lease_reclaim: 1 ok + 7 denied; mcp_path: 2 denied; enrollment: ok
schema:   11 (no dead consented_at column)
```

## 7. Not qualified here

- ChatGPT registration / any unattended client (operator-mediated per-consent
  flow by design).
- Production deployment: NOT PERFORMED. The Pi relay, its DB, and its
  services were untouched.
- Scale, refresh tokens (none exist — see the runbook's known limits), and
  the provider-IdP path.
