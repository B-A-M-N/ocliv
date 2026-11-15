

### 2026-11-15 rereview — operational-correctness corrections (branch rereview-2026-11-15)

Scope: the 2026-11-15 rereview findings, implemented on the dedicated branch
(rebased from `b28e548`); the frozen `19d46d8` candidate and production
services were NOT touched. Every finding was reproduced failing-first where
practical, corrected with the smallest coherent edit, and verified.

- **P1-1 issuer rotation false success: FIXED** (`f72e00e`). `RotateIssuer`
  uses INSERT … ON CONFLICT inside a transaction and verifies persistence
  (exactly one row, matching kid/priv) before returning. Regressions:
  `TestRotateIssuerCreatesMissingIssuer` (red: persisted kid ≠ returned kid).
- **P1-3 strict authz flag parsing: FIXED** (`f72e00e`). `parseAuthzFlags`
  rejects unknown/misspelled flags, missing values, duplicates, empty
  values, and positional args; `--json` takes no value; `--client` required
  strictly. `TestAuthzInvalidFlagsNeverCreateDatabase` proves invalid flags
  never create a database; `TestAuthzRotateKeyTargetsExplicitDatabase`
  proves the explicit `--data` is honored and a misspelled flag never falls
  back to the default.
- **P1-4 restore preflight purity: FIXED** (`898d92f`). `openRevocations`
  no longer calls `store.Open` on the live database; `openReadOnly`
  (mode=ro, no create) reads the schema version and refuses unknown/newer
  schemas without migrating. `store.SchemaVersion` exported for this
  purpose. Regression:
  `TestRejectedRestoreDoesNotMigrateLiveDatabase` (v7 marker stays 7 after
  a refused restore; contents unchanged). Red-before established by
  construction (the pre-fix code demonstrably called `store.Open` on the
  live path); the safe revert to prove it dynamically was rejected as an
  irreversible-discard risk and not attempted.
- **P1-2 clean-host rollback: FIXED** (`92970a2`). `ServiceState` +
  per-run `startedUnits` tracking; rollback reverses only what the run
  actually did, before file rollback. `RollbackDataDir` refuses (and names
  the path) when a newly created data dir has become nonempty — generated
  authorization state is never recursively deleted. Regressions:
  `TestRollbackDataDirRefusesNonemptyNewDir`,
  `TestRollbackStopsRelayWeStartedNotPreexisting`, etc.
- **P1-5 autoEnroll identity verification: FIXED** (`70b2ad3`). An existing
  key must match the requested relay authority (scheme+host); a different
  relay or a missing relay_url fails closed with an actionable message; the
  key is never replaced. Regressions:
  `TestAutoEnrollRejectsDifferentRelay`,
  `TestAutoEnrollKeyWithoutRelayConfigBlocked`.
- **P2-6 read-only inspection: FIXED** (`a94664f`). `authz pending/list`
  use `authzOpenReadOnly` (no create, no migrate, newer-schema refusal);
  mutating commands keep the mutation-capable open. Regressions:
  `TestAuthzListDoesNotCreateDatabase`,
  `TestAuthzPendingDoesNotMigrateDatabase`,
  `TestAuthzReadOnlyDoesNotChangeDatabaseBytes`;
  `TestAuthzCommandSetClosed` updated to the read-only contract.
- **P2-7 dead SQL helpers: FIXED** (`22d6439`). `ListCodes` (broken columns,
  no callers) and `ListClients` (inconsistent revoked_at scan, no callers)
  removed; neither was in the `Store` interface. No new abstraction added.
- **P2-9 docs reconciliation: FIXED** (`cb192ca`). AGENTS.md gained an
  authoritative current-behavior block (mcp PORT default, stdio
  managed-auth-only, upstream OAuth separate, single-host without
  Tailscale, forward-only V11 recovery, superseded promotion plan, off-LAN
  NOT VERIFIED); the bundled `ocliv-operate` skill mirrors it. Historical
  audit sections keep their dated context.
- **P2-8 backup interruption handling: DEFERRED** with reasons. The two
  crash windows (checksum sidecar publication; rename→sidecar cleanup in
  `installValidated`) are durability-hardening targets, not observed
  defects. The forward-only recovery contract is unaffected; adding a
  second restore mechanism or weakening the guard is out of scope for this
  pass. File-level fsyncs and atomic renames already bound the exposure;
  a targeted crash-injection suite should be added when the promotion
  candidate is re-cut (the artifact changes anyway).

Gates on the branch: `go build ./...`, `go vet ./...`, `gofmt -l internal/
tests/` clean; `go test ./internal/... -count=1` green (19 packages);
`go test -race` green for authz/cli/relay/setup/store; full integration
suite green (252.8s, 420s cap).

### 2026-11-15 rereview artifact qualification — candidate realigned to 2089516

The release review accepted `2089516` as the next candidate's source with
promotion on HOLD. This pass built the matching artifact and re-ran the
bounded qualification on the actual promotion binary. Prior binaries
(`1ceaaff4…` from `19d46d8`, `fe48fb96…` from `f2d2bec`) are SUPERSEDED for
promotion.

- **New qualified artifact: `65ed20b21eddb40b3cdf3fbb60388dc7deb81066fec6dda9c0142043727b8a53`**
  from `2089516` (go1.26.10, same build config, 13,500,578 bytes). Digest
  verified on the Pi. Runbook + provenance re-pointed.
- **29/29 Pi staging checks: PASS** on the new binary (fresh clean slate;
  Phase E guard emits the composite grant key).
- **Rereview deltas exercised on the artifact:** `authz rotate-key` on an
  empty table persists exactly one issuer row and the reported kid matches;
  a second rotation replaces it (still one row); `authz list`/`pending` on a
  database-less data dir fail closed without creating a database.
- **Cross-version recovery re-proven with this binary:** production binary
  (`0d47481f…`) creates V7 → candidate opens/migrates to V11 and serves →
  old binary refuses V11 (`unknown state schema version`) → candidate
  guarded-restores the V7 backup to V11 and it serves. Production
  `ocliv-relay` stayed `active` throughout; no production mutation.
- **P2-8 (backup interruption safety) remains DEFERRED** — the operator must
  accept the existing recovery procedure as-is; the forward-only contract is
  unchanged. Operator gates (root schema read, off-LAN baseline, explicit
  approval) still outstanding.
