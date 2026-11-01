# Ocliv — Remediation Final Report (Phase 6)

Source audit: independent 89-invariant falsification audit (61 PASS, 16
VIOLATION, 6 CONFLICT, 6 NOT VERIFIED, 7 remediation-introduced defects).
Baseline details in `/tmp/audit_report.md` (session record, SEQ 9934);
spec companions: `ocliv_invariants_and_exceptions_v1.md`,
`ocliv_production_spec_v1.md`, `ocliv_anti_spec.md` (110 clauses).

## 1. Outcome and readiness

**NOT READY for production.** All 16 violations and 7 remediation defects
are fixed with regression tests; all 6 conflicts are resolved; full
`build/vet/test/race` gates are green. Production readiness is still
blocked on real external-network qualification (Section 8), which this
remediation was explicitly forbidden from performing.

Final dispositions: **82 PASS · 1 VIOLATION (H10, narrowed) · 6 NOT
VERIFIED (unchanged, deployment-owned)** = 89.

## 2. Before/after matrix

Evidence key: I=integration (`tests/integration`), U=unit, G=gates
(`build/vet/test/race` all green, integration 70s, race 80s).

A-series: A01 PASS→PASS(G) · A02 PASS→PASS(G) · A03 PASS→PASS(G) ·
A04 PASS→PASS(G) · A05 PASS→PASS(G) · A06 PASS→PASS(G) ·
**A07 VIOLATION→PASS** (U: `TestLoginRejectsPlaintextRelay`,
`TestLoginMergesConfig`, TTY-gated share tests; Group 4) ·
A08 PASS→PASS(G) · A09 PASS→PASS(G).

B-series: B01 NOT VERIFIED→NOT VERIFIED (edge TLS, needs staging) ·
**B02 VIOLATION→PASS** (U: plaintext-login reject, `wsBaseFor` downgrade
refusals; `CheckRelayTLS` loopback-only http; Group 3) ·
B03 PASS→PASS(G) · B04 PASS→PASS(G) · B05 PASS→PASS(G) ·
B06 PASS→PASS(G) · B07 PASS→PASS(G) · B08 PASS→PASS(G) ·
**B09 VIOLATION→PASS** (I: store-fault fail-closed, `TestOperatorTakedown`,
revoked-key resume denial; Group 1+7) ·
**B10 VIOLATION→PASS** (I: `TestHandshakeVersionEnforced`; Group 3/5) ·
B11 NOT VERIFIED→NOT VERIFIED (needs staging).

C-series: C01 PASS→PASS(G) · C02 PASS→PASS(G) · C03 PASS→PASS(G) ·
**C04 VIOLATION→PASS** (I: `/headers` echo asserts relay-credential
absence, dynamic strip via `access.HeaderName`; Group 3) ·
C05 PASS→PASS(G) · C06 PASS*→PASS(G, timing note stands) ·
**C07 VIOLATION→PASS** (I: `TestSingleUseTokenNoDoubleSpend` + concurrent
double-spend fencing; atomic consume; Group 1) ·
C08 PASS→PASS(G) · C09 PASS→PASS(G) ·
**C10 VIOLATION→PASS** (I: `TestRevokeTerminatesAccess/InflightStream/WebSocket`,
`TestOperatorTakedown`, rotate-resume `TestHeaderTokenAuth`; evictLease;
Group 2+7) · C11 PASS*→PASS(G) · C12 PASS→PASS(G).

D-series: D01 PASS→PASS(G) · D02 NOT VERIFIED→NOT VERIFIED (SNI/deploy) ·
D03 PASS→PASS(G) · D04 PASS→PASS(G) · D05 PASS→PASS(G) ·
D06 PASS→PASS(G) · D07 PASS→PASS(G) ·
**D08 VIOLATION→PASS** (U+I: loopback-gated `publicScheme`, scheme tests;
edge contract in `docs/OPERATOR.md`; Group 3) ·
D09 PASS→PASS(G) · D10 PASS→PASS(G) · D11 PASS→PASS(G).

E-series: **E01 CONFLICT→PASS under amendment** (`docs/PROTOCOL.md`;
`CheckRequestSyntax` + `CheckUpgradeSyntax`; I: `TestRequestSmugglingVectors`;
Group 5) · E02 PASS*→PASS (hardened, Group 5) · E03 PASS→PASS(G) ·
E04 PASS*→PASS (Set-Cookie newline split; Group 5) ·
E05 PASS*→PASS (response-path bounds; Group 5) · E06 PASS→PASS(G) ·
E07 PASS*→PASS (cookie normalization; Group 5) · E08 PASS→PASS(G) ·
E09 PASS*→PASS (same cookie fix; Group 5) · E10 PASS→PASS(G) ·
E11 PASS→PASS(G) · **E12 VIOLATION→PASS** (I: `TestTrailersRejected`,
announced-trailer 502 via parsed trailer set; Group 5) ·
E13 PASS→PASS(G) · E14 PASS→PASS(G) · E15 PASS→PASS(G).

F-series: F01 PASS→PASS(G) · F02 PASS→PASS(G) · F03 PASS→PASS(G) ·
F04 PASS→PASS(G) · F05 PASS→PASS(G) ·
**F06 CONFLICT→PASS** (server-side `Ready` gate for new leases,
agent-probe trust documented; I: lifecycle/boot tests; Group 4) ·
**F07 VIOLATION→PASS** (I: `TestClosedResumeIsTerminal`, revoke
termination suite; Group 2) · F08 PASS→PASS(G) ·
**F09 CONFLICT→PASS** (typed WS close codes 4401/4409/4429 + agent
`closeCode` mapping + challenge-status classification U:
`TestChallengeDenialClassification`, I: `TestAgentExitsOnTerminalDeny`;
Group 4+7) · F10 PASS→PASS(G) · F11 PASS→PASS(G) ·
**F12 CONFLICT→PASS** (unparseable timestamps fail closed + audit, store
fault fail-closed; I: `TestCorruptLeaseRowFailClosed`; Group 1) ·
F13 PASS→PASS(G).

G-series: **G01 VIOLATION→PASS** (`MaxHeaderBytes` wired to `http.Server`;
Group 6) · G02 PASS→PASS(G) · G03 PASS→PASS(G) ·
**G04 VIOLATION→PASS** (I: `TestWSMaxLifetimeEnforced`, `AfterFunc`
lifetime timer + bridge-loop checks; Group 2) · G05 PASS→PASS(G) ·
**G06 VIOLATION→PASS by construction** (`ReadTimeout` 5m + `IdleTimeout`
2m on the relay server; `WriteTimeout` deliberately unset — SSE streams
never terminate; no dedicated slow-trickle test exists, carried as a
minor residual) ·
**G07 CONFLICT→PASS** (per-IP pre-auth limiter 1000/min on
challenge/enroll/unlock/redeem with 429+audit, I:
`TestPreAuthFloodFailsClosed`; takedown half → operator procedure,
`docs/OPERATOR.md` + I: `TestOperatorTakedown`; Group 6+7) ·
**G08 VIOLATION→PASS** (throttle idle-eviction + sweep-before-deny +
4096 key cap; nonce expiry sweep + 4096 cap + 429; `NonceEntries` /
`ThrottleKeys` gauges in `Snapshot`; U: `TestThrottleBoundsKeys`, I:
`TestNonceTableBounded/SweepReclaims`; Group 6).

H-series: H01 PASS→PASS(G, deploy half still external) ·
H02 NOT VERIFIED→NOT VERIFIED · H03 PASS→PASS(G) · H04 PASS→PASS(G,
operator-audit gap noted for manual SQL) ·
**H05 VIOLATION→PASS** (doctor clock/health findings marked unverified
unless checked; U: doctor tests; Group 4) ·
H06 NOT VERIFIED→NOT VERIFIED ·
**H07 CONFLICT→PASS** (migration already idempotent
`CREATE TABLE IF NOT EXISTS` + `INSERT OR IGNORE` + unknown-version
reject; login-over-enrollment refused pre-network, U:
`TestLoginRefusesOverwriteBeforeNetwork`; downgrade = explicit reject;
Group 7) · H08 NOT VERIFIED→NOT VERIFIED · H09 PASS→PASS(G) ·
**H10 VIOLATION→VIOLATION (narrowed)**: adversarial + chaos + race
evidence landed and green; fuzz, load/soak, restore, external-client,
and adverse-network tiers still missing, so the invariant as stated is
unsatisfied.

## 3. Conflict dispositions

- E01: genuine platform constraint (Go normalizes TE+CL before handlers).
  Resolved as an **authorized amendment**: deterministic single-parser
  path permitted, documented in `docs/PROTOCOL.md`; everything else
  still rejected (400s).
- F06: underspecified trust placement. Resolved: server enforces
  `Ready` for new leases; agent-probe trust is documented, not assumed.
- F09: incorrect interpretation (substring matching). Resolved: typed
  denial codes end-to-end (WS close codes + challenge HTTP statuses).
- F12: genuine fail-open bug masquerading as ambiguity. Resolved:
  fail closed + audit, no exception.
- G07: genuinely two-sided (abuse controls vs. takedown path). Resolved:
  pre-auth limiter in code; takedown as a documented, tested operator
  procedure (no new endpoint per minimal-change rule).
- H07: conditionally applicable (idempotency held; overwrite/downgrade
  did not). Resolved: refused-overwrite + explicit downgrade reject;
  no migration format change needed.

## 4. Root causes of the seven remediation-introduced defects

- R1 (fence lost update): read-modify-write without a generation guard.
  Fix: `WHERE generation=?` atomic fence + `reconcileBoot` + expiry checks.
- R2 (all denies identical 4400): untyped denial channel. Fix: typed
  4401/4409/4429 plus challenge-status classification into `isPermanent`.
- R3 (probe followed redirects): default client policy. Fix: no-redirect
  probe client (precedent already in tree).
- R4 (TTL left sessions attached): mark-without-sweep. Fix: TTL eviction
  (`evictLease`, budget drop), head-wait TTL bound, in-flight TTL aborts.
- R5 (boot sweep missed RECONNECTING+past-TTL): incomplete predicate.
  Fix: sweep covers both states (Group 2 `reconcileBoot`).
- R6 (login truncated config): whole-file rewrite. Fix: `mergeRelayURL`
  preserving existing keys.
- R7 (dead constants): references rotted. Fix: deleted; no live constant
  is unreferenced (verified by grep + build).

## 5. Code changes and regression evidence

Groups 1–5 (prior turns, all green at each gate): dispatch atomicity
(`relay_session.go` fence/`reconcileBoot`, `relay_public.go` route + atomic
consume, `relay.go` CONNECT guard; `atomicity_test.go`), kill-switch
(`evictLease`, TTL eviction/aborts, WS lifetime; `revoke_test.go`),
edge trust (`publicScheme` loopback gate, `CheckRelayTLS`, dynamic header
strip; `relay_scheme_test.go`, `tunnel_test.go`), probe/CLI honesty
(no-redirect probe, readiness gate, typed closes, `--code-file`,
`mergeRelayURL`, TTY share, doctor honesty; agent/cli/doctor unit tests),
protocol strictness (Set-Cookie split, trailer 502, `CheckUpgradeSyntax`,
version gate; `protocol_test.go`).

Groups 6–7 (this session): `internal/limits/limits.go` (caps
`MaxThrottleKeys`/`MaxNonceEntries`/`PreAuthBurst`, idle eviction,
sweep-before-deny, `Keys()`); `internal/relay/relay.go` + `relay_helpers.go`
(`preAuth` field, `checkPreAuth` 429+audit); `relay_connect.go`
(challenge/pre-auth gate, nonce sweep-then-cap); `relay_agent.go`
(unlock/redeem gates); `internal/metrics/metrics.go`
(`PreAuthRejects`/`NonceEntries`/`ThrottleKeys` + exposition);
`internal/cli/cli_commands.go` (server `ReadTimeout`/`IdleTimeout`/
`MaxHeaderBytes`, login refuse-if-enrolled, init edge-contract line);
`internal/agent/agent.go` (challenge-status classification);
`docs/PROTOCOL.md` + `docs/OPERATOR.md` (new: E01 amendment, edge
contract, takedown procedure, backup gap).

New regression tests: `limits_test.go::TestThrottleBoundsKeys`,
`relay_limits_test.go` (nonce bound/sweep, pre-auth flood),
`cli_test.go::TestLoginRefusesOverwriteBeforeNetwork`,
`agent_test.go::TestChallengeDenialClassification`,
`revoke_test.go::TestOperatorTakedown`,
`adversarial_test.go::TestHeaderTokenAuth` (resume-aware after C10
eviction — expectation corrected with justification, core assertions
preserved). Negative controls: throttle test failed pre-fix
(`throttle admitted past hard key cap`); login test failed pre-fix
(second login hit network); takedown test exposed the F09 challenge
gap (runner never exited) which was then fixed.

Gates (final, this tree): `go build ./...` ✓, `go vet ./...` ✓,
`go test ./...` ✓ (incl. integration 70s), `go test -race ./...` ✓
(incl. integration 80s). One in-flight regression was caught and fixed
by these gates: rotate-evict (Group 2) vs `TestHeaderTokenAuth`
immediacy — resolved per C10 without weakening the invariant.

## 6. Anti-spec ledger reconciliation (110 clauses)

No reversals. Changed behaviors and their clauses: kill-switch eviction
serves "no silently continuing protected traffic when authorization
cannot be validated"; challenge classification serves "no indefinite
retry of permanently invalid credentials" (the pre-fix infinite retry
on revoked keys violated it); no-redirect probe serves "no
redirect-following engine"; caps/gauges/timeouts serve "no unbounded
buffering/queues" and "no memory growth proportional to unlimited
request sizes"; login refuse serves "no silent modification of the
user's…" credentials; loopback-gated scheme + documented edge contract
keep "no security feature that only exists in configuration but is not
enforced" satisfied (enforcement is live, docs state operator duty).
New docs add no features (no new endpoints, services, or dependencies).

## 7. New and retired risks

Retired: relay-credential leak (C04), origin spoof (D08), key without
revocation (B09), token double-spend (C07), untyped permanent denies
(R2/F09), redirect-following probe (R3), config truncation (R6), silent
key overwrite + burned codes (H07), unbounded nonce/throttle maps
(G08), undead WS sessions (G04), unthrottled pre-auth (G07).

New/remaining (accepted, documented): brief 503 window on rotate while
the agent resumes (~250ms–1s, test-encoded); pre-auth limit is generous
(1000/min — hard caps do the real bounding); `WriteTimeout` unset for
SSE (slow-reader residual on finite bodies); operator takedown leaves
in-flight streams to drain (restart for immediacy); challenge
permanence keys off HTTP status (a relay bug returning 5xx for bad
creds would retry under backoff — safe direction); `docs/OPERATOR.md`
SQL must track the revoke handler (drift risk — the takedown test
mirrors the statements); no dedicated slow-trickle test (G06 by
construction).

## 8. Unresolved external qualification and readiness criteria

NOT VERIFIED (unchanged, need staging/live infra — never touched):
B01/B11 (TLS edge/DNS/ACME), D02 (SNI), H02 (least-privilege unit),
H06 (backup/restore — no procedure ships, see `docs/OPERATOR.md`),
H08 (release provenance). H10 needs fuzz, load/soak, restore,
external-client, and adverse-network tiers. Deployment artifacts still
absent: in-tree Caddyfile, systemd unit (dirs exist, empty).

## 9. Qualification addendum — isolated fuzzing (post-freeze, test-only)

`internal/proxy/proxy_fuzz_test.go` (new file, no production change):
`FuzzCheckRequestSyntax` and `FuzzCheckUpgradeSyntax` assert panic-freedom
and determinism over fuzzer-controlled method/URI/TE/CL/Upgrade/Connection
fields, seeded with the smuggling/upgrade vectors from the audit.
Runs against the frozen candidate: 3,876,398 execs (90s) and 2,791,511
execs (90s) respectively, zero crashes, zero nondeterministic verdicts.
`go test` seed-corpus runs stay green. Intent/state-machine fuzzing
(`LeaseIntent` validation, `allocateOrResume` transitions) still needs a
DB-backed harness and is not covered here.

Restore-primitive spike (throwaway, H06 scoping, not a deliverable):
an offline file copy of a seeded `ocliv.db` reopens via `store.Open`
with schema intact and rows continuous
(`PASS: offline copy reopens, schema + rows continuous`).
This validates only the copy-and-reopen primitive behind
`docs/OPERATOR.md` — not online backup, not restore automation, not
live-session continuity. No tree changes remain from the spike
(removed; `go build ./...` green after).

Ready when: staging reachability + DNS/ACME + public-client flows pass;
adverse-network/chaos passes off-loopback; load/soak + restore
evidenced; fuzz targets land; Caddyfile/systemd/backup shipped; H10
tiers complete. Until then: **do not expose publicly; do not declare
production ready.** No push, publish, deploy, or live-infra change was
made in this remediation.
