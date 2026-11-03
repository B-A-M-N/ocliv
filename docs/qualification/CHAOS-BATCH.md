# Chaos Engineering — Executed Batch Report (Stage 5)

Revision: `24fe3e8` (extends `143b9af`, `50f2d8e`).
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

## NOT EXECUTED (needs operator/second machine)

Soak, scaled resource pressure, cross-machine partition/TLS-SNI chaos,
public-edge faults, provider OAuth, dynv6 zone claim (browser signup).
