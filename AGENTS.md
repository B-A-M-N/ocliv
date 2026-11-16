

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

### 2026-11-15 post-rereview safety corrections (working tree)

- Legacy MCP doctor probes now retain session and protocol headers; managed
  mode requires a valid MCP tools/list reply. SSE probe replies are read
  incrementally.
- Lease renewal is opt-in for supervised MCP publishers, schedules from the
  authoritative remaining expiry, and requires a 60-second minimum publish
  TTL. Admission expiry uses a generation/status/expiry CAS. Existing streams
  recheck current lease state at the old expiry and survive a real renewal.
- The stale ChatGPT plugin ZIP embedding the retired
  `pop-os.tail8d285a.ts.net` route was moved under the ignored local
  `packaging/mcp/dist/superseded/` archive and removed from the deployable
  filename. Release builds now require an exact endpoint and a fresh,
  secret-free ingress qualification receipt proving both metadata
  documents, negative bearer checks, authenticated `tools/list`, and
  authenticated tool execution. No current public endpoint is qualified;
  release remains on HOLD.
- Backup snapshots carry an embedded format marker, so deleting a new-format
  checksum sidecar cannot make the backup look legacy. Management calls
  return transport errors separately from HTTP statuses. Publisher units now
  allow only the required state paths and share the `OCLIV_RESOURCE_FILE`
  name.
- Upstream-OAuth publish proves `tools/list` with an optional local-only
  `OCLIV_UPSTREAM_MCP_TOKEN`, then probes missing and invalid bearer
  rejection. The explicit `--accept-unverified-upstream-auth` override
  cannot waive protocol verification and labels the route NOT VERIFIED.
- The ingress receipt now requires authenticated `tools/list` and a real
  authenticated tool call; `tools/list` alone cannot certify execution.
- The Streamable HTTP adapter has isolated children per session and official
  Go MCP SDK interoperability tests. Public `mcp publish --stdio` is
  supported with `--auth ocliv-managed` and an explicit `--name`, which
  keeps the route stable across the adapter's ephemeral listener ports.
  Production publication qualification remains a separate release gate.
- Quiet-stream response writes are bounded and the default tests are fast.
  The 45/90/180-second endurance run is opt-in locally and has a named manual
  GitHub Actions job at `.github/workflows/long-stream-endurance.yml`.
  Full public ChatGPT acceptance, off-LAN reachability, and production
  promotion remain NOT VERIFIED/HOLD.

Current working-tree source gates (2026-11-15): `go test ./... -count=1 -timeout=420s` PASS (integration package 270.8s); `go test -race ./internal/mcp ./internal/cli ./internal/relay` PASS; `go build ./...`, `go vet ./...`, `gofmt -l internal tests`, and `git diff --check` PASS.
`npm run check` in `packaging/mcp/skybridge` PASS (typecheck, five Node test
files, and production build; PostHog telemetry flush was blocked by restricted
DNS and did not fail the build). The current 45/90/180-second endurance run
also PASSED in 316.0s. These are source checks only; they do not qualify a
public endpoint or the frozen production artifact.

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

### 2026-11-15 clean-source candidate qualification — `d9ea67b`

The post-rereview publishing and qualification fixes are committed in
`599996a` and `d9ea67b`. A clean detached checkout of
`d9ea67b8578ded3b3af25e296acdd1d7d0e0e126` produced the ARM64 staging
candidate `7f438b63dd083f34831b133b169707f4d5f479e6aaef7f7894cb4b25e4afc695`
(13,631,650 bytes). Go VCS stamping was disabled because the Go probe ran
`git status` from `/home/bamn` instead of the detached worktree; the clean
source commit and exact build command are in the promotion runbook and
artifact provenance.

The matching Pi artifact passed **29/29 isolated staging checks** with a
fresh staging DB and identity. The relay restart, managed OAuth/tool path,
security boundaries, and guarded restore rehearsal passed. The qualification
log is retained under
`/home/bamn/ocliv-stage/stage-d9ea67b-20261115/qualification.log`.
Production is still HOLD: root-only schema/identity preflight, explicit
promotion approval, off-LAN acceptance, and live ChatGPT acceptance remain
outstanding. No production mutation was performed.

### 2026-11-16 isolated Pi qualification — current candidate `efe3a8e`

The later isolated qualification supersedes the `d9ea67b` candidate above.
Clean commit `efe3a8e972d48d7f9b1a111da31325a0e3a7842a` produced ARM64
artifact `aef41e6acb06273f56e812d8785f148c29bcedb095e9e2b38aadba167246d08c`
(13,697,186 bytes), qualified 29/29 on a fresh isolated Pi relay/database.
The current `fc44a0b` tip adds only the qualification result document; its
separate build was verified byte-identical. The promotion runbook and
`docs/qualification/pi-staging/PROVENANCE.txt` now name the exact qualified
artifact and stage it under `/home/bamn/ocliv-stage`, not `/tmp`.

The result proves isolated loopback behavior only. Clean-host installation,
off-LAN access, ChatGPT acceptance, and a 24-hour soak remain NOT VERIFIED.
The production schema and owner inventory and explicit migration/publication
approvals remain outstanding; no production mutation was performed.

The current uncommitted source includes DCR eviction and qualification-script
corrections made after that artifact was qualified. The `efe3a8e` artifact is
therefore the last qualified binary, not a release of the current worktree;
freeze, rebuild, and requalify before promotion.
