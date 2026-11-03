# Chaos Engineering — Executed Batch Report (Stage 5)

Revision: `98b7660` (extends `24fe3e8`, `143b9af`, `50f2d8e`, plus
`fd58cf8`, `721a47a`, `fe98c69`/`727b7fb`, `8e288c4`, `b6dda49`,
`34f095d`, `2ff2ad9`).
Scope: local-only fault injection. No live services touched, no pushes,
no credential or infrastructure changes. Tree clean at commit.

## Experiment matrix

| ID | Fault | Target | Outcome |
|----|-------|--------|---------|
| E5 | Relay restart after nonce use | `relay.consumeMgmtNonce` | PASS |
| E1 | 8 overlapping refresh runs | `setup.RefreshDynDNS` | PASS |
| E2 | Restore write fails during rollback | `setup.installManagedFile` | FAIL→FIXED |
| E3 | Rollback into unwritable destination | `setup.RollbackInstalled` | PASS |
| C1 | Install fail + restore fail, then operator recovery | bootstrap rollback chain | PASS |
| C2 | Replay with stale timestamp | route skew check | PASS |
| D1 | Cleartext LAN relay URL | `config.CheckRelayTLS` | PASS |
| D2 | Unresolvable relay hostname | `cli.performEnroll` | PASS |
| D3 | TLS impostor (loopback) | enrollment handshake | PASS |
| D4 | Cleartext via hosts-DNS to live LAN impostor (10.9.66.20) | enrollment | PASS |
| D5 | HTTPS via hosts-DNS to live LAN impostor (10.9.66.20) | enrollment | PASS |
| D6 | Live dynv6 error shapes (bogus token) | `setup.UpdateDynv6` | PARTIAL |
| F1 | Bounded fuzz campaign (4 targets, ~270s) | `lease`, `proxy` parsers | PASS |

Evidence: `internal/relay/relay_chaos_nonce_test.go`,
`internal/setup/bootstrap_chaos_test.go`,
`internal/setup/refresh_chaos_test.go`,
`internal/cli/cli_dns_chaos_test.go`; D4/D5 impostor log showed zero
connections/POSTs; laptop left clean (no listener, files, or strays).
D6: `401 invalid authentication token`, auth-first ordering observed live.

## Defect register

- **FIXED (P1): silent backup destruction on failed validation restore.**
  `installManagedFile` discarded the restore error and deleted the
  backup. Now loud, backup preserved. Red→green proven.
- **ACCEPTED RISK:** backup restore can resurrect consumed management
  nonces; blast radius bounded by 5-min signed-timestamp skew.
- **RESIDUAL (unverified):** whether dynv6 ever returns errors as
  HTTP-200-with-text. Auth-first ordering blocks probing without a valid
  token. No code change: refresh self-heals on next run.

## Prior coverage re-verified (not re-proven here)

Goroutine-bounded reconnects, per-tunnel lease separation, 11
restore-rollback refusal cases, stale-timestamp rejection,
`busy_timeout`, bounded backoff + typed permanent-failure retry
classification.

## Requalification

`go build`, `go vet`, `gofmt -l`, `git diff --check` clean.
`go test ./internal/...` 18/18 green; `-race` on touched packages;
`go test ./tests/integration/` green (204s).

## Control-plane honesty + unit validation

| ID | Fault | Target | Outcome |
|----|-------|--------|---------|
| P7 | `doctor`/`status` with no enrollment | CLI truthfulness | PASS |
| P8 | `systemd-analyze verify` on refresh units | shipped timer/service | PASS* |

P7: real `ocliv doctor` run against a clean HOME reports `✗ enrollment`,
`? unverified` states, exits 5 — no false success. `status` reports
"no active tunnel", exit 0. The compiled-default relay probe correctly
shows DNS failure as unverified, not verified.

P8: `systemd-analyze verify` passes on syntax; the binary-missing
warning is expected on a non-installed host. No `ConditionPathExists`
added deliberately: the unit's stated philosophy is fail-loud, and the
timer only runs when the operator enables it. Consistent with E1 (the
timer's `OnUnitActiveSec` also prevents overlap by construction).

| C3 | 16-way concurrent route create | route admission loop | PASS |
| R1 | Abnormal health-listener death | `startHealthListener` | FIXED |

C3: 16 simultaneous signed creates for the same logical publication
all returned 200 with the identical route_id; exactly one DB row.
The INSERT...SELECT/ON CONFLICT convergence claim is now proven
(`relay_chaos_routes_test.go`, race-clean).
R1: runtime `Serve` errors were discarded (`_ =`), so a dead
loopback monitor was invisible until the next external probe. Now
logged to stderr; graceful shutdown stays quiet. Liveness was already
covered by `TestStartHealthListenerBindAndShutdown`; the abnormal-death
path has no deterministic unit seam without structural churn and is
inspection-verified (`fe98c69`).

## Finding A2 — unbounded audit_events growth: FIXED (Stage 6)

Mechanism confirmed by source: `store.DB.Audit` INSERTs on every
denial/edge event (rate-limit denials, no-route, auth failures,
revocations) and no code path ever DELETEs or prunes `audit_events`.
Growth is throttled by the pre-auth/admission rate limiters but never
reclaimed — months of probing fill disk and bloat backups.
No global janitor exists (sweeps are per-session/nonce-local).

Fix: operator-visible 90-day retention (`store.AuditRetention`,
documented in `docs/OPERATOR.md` under "Audit retention").
`DB.PruneAuditEvents` (idempotent single-statement DELETE, schemaV6
index on `audit_events(time)`) runs in `reconcileBoot`, fail-closed
like every other boot persistence step. Authority-safe: revocation
state lives in leases/agent_keys (`revoked_at`), never in audit rows —
verified `relay_backup.go` never SELECTs `audit_events` for restore
validation, so pruning cannot resurrect access.

Red→green: `TestPruneAuditEventsKeepsRecentEvidence`
(`internal/store/store_audit_retention_test.go`) and
`TestReconcileBootPrunesStaleAuditEvents`
(`internal/relay/relay_audit_retention_test.go`); `go vet` red
(undefined method) before, green after. Full `internal/...`,
`-race` on store/relay, and integration suite green post-fix.

Adjacent check: never-reading SSE visitors hold a stream by design,
but converge via lease TTL + the 5s revocation sweep
(`supervise`), so no unbounded-hold defect.

## P9 — setup planner honesty probe (live dry-run)

`ocliv setup --auto --dry-run` against the real network correctly
classified this host (`nat-ipv4-needs-forward`, CGNAT false, direct
false, inbound UNKNOWN), refused to claim provisionability, demanded
port-forwarding plus external verification, and required the dynv6
token via env/file — never inline. Exit 4, no state written. PASS.

F1: `FuzzLeaseTransition` (6.2M execs/75s), `FuzzLeaseFenceMonotonic`
(4.7M/60s), `FuzzCheckRequestSyntax` (3.2M/75s),
`FuzzCheckUpgradeSyntax` (2.6M/60s) — ~16.8M execs, zero crashes,
tree clean (interesting inputs stayed in build cache).

## NOT EXECUTED (needs operator/second machine)

Soak, scaled resource pressure, cross-machine partition/TLS-SNI chaos,
public-edge faults, provider OAuth, dynv6 zone claim (browser signup).
