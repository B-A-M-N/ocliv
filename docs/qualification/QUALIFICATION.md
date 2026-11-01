# Ocliv — Local Qualification Record (Gate A + Phase 1/2)

Date (UTC): 2026-10-31. Tree: `/home/bamn/ocliv` (baseline commit
`6035104` landed after this gate; post-baseline changes remain
uncommitted — H08 release provenance still open for them). Toolchain:
go1.26.10 (`toolchain go1.26.10` in go.mod). No pushes, no live-infra
changes.

## Refactor map (behavior-preserving; Finding 7)

The rows below cite original file locations at qualification time. The
decomposition moved code verbatim (or method-preserving) without changing
observable behavior; full gates were re-run after each move:

- `relay_session.go` → `relay_leases.go` (durable) + `relay_sessions.go`
  (live registry) + `relay_registry.go` (`sessionRegistry` ownership).
- `relay_agent.go` → `relay_access.go` (visitor) + `relay_mgmt.go`
  (signed agent management, revocation).
- `relay.go` authority/enrollment → `relay_authority.go` /
  `relay_enrollment.go`; `Server` is now construction + route wiring only.
- Agent `Runner.once` → `agent_handshake.go`
  (`fetchChallenge`/`buildHandshake`/`dialAttach`); error strings unchanged.
- Behavioral changes after the moves (with red/green evidence) are tracked
  as new rows below: strict relay authority (MCP P0-1), generation-fenced
  `markReconnecting` (Finding 1), upload-idle head deadline (Finding 2),
  MCP header pins + no-downgrade test (MCP P0-4/M14).

## Defect → fix → test traceability

| # | Defect | Enforcement (file:function) | Regression test | Falsification (pre-fix result) | Disposition |
|---|--------|---------------------------|-----------------|-------------------------------|-------------|
| P0-1 | Operator takedown left public tunnel live | `relay_public.go:route` (non-ACTIVE denied) + `docs/OPERATOR.md` (`REVOKED` step) | `TestOperatorTakedownPublicLease` | FAIL pre-doc-fix: public 200 after takedown | PASS |
| P0-2 | Signed revoke reported success on DB failure | `relay_agent.go:revokeLease` (tx + row check, 500 unless committed) | `TestRevokeLeaseFailsClosed` | Compile-red pre-fix (no error return existed) | PASS |
| P0-3 | Unknown resume ID bypassed readiness | `relay_session.go:allocateOrResume` (`!intent.Ready` denies all creation) + `relay_connect.go` TTL bound (10y) | `TestUnknownResumeIDCannotBypassReadiness`, `TestOversizedTTLRejected` | FAIL / FAIL in isolated checkout | PASS |
| P1-1 | Revoke/expiry race in token consume | `relay_public.go:checkVisitorToken` (predicate re-checks revoked_at, expiry, uses) + `checkCookieSession` (predicate-checked refresh) | `TestRevokeDuringUseDeniesAfterCommit` | FAIL pre-fix in isolated checkout: 10–15 post-revoke successes; PASS post-fix incl. `-race` | PASS |
| P1-2 | Swallowed lease-save errors; shutdown used file only | `agent_serve.go:saveLease` returns error, attach fails loudly; `cli.go:shutdownLeaseID` (memory first) | `TestSaveLeaseErrorSurfaced`, `TestShutdownLeaseIDPrefersMemory` | Compile-red pre-fix (void signature; no helper) | PASS |
| P1-3 | SQLite FKs declared but unenforced | `store.go:Open` (`PRAGMA foreign_keys=ON` + verify, fail closed) | `TestForeignKeysEnforced` | FAIL pre-fix in isolated checkout (orphan accepted) | PASS |
| P1-4 | Status conflated attach with routability | `relay_agent.go` status case (`route_live`, `live_generation`); `cli_commands.go:renderStatus` (Route line; never claims external reachability) | `TestRenderStatusDistinguishesRoute`, `TestLeaseStatusReflectsRouteLiveness` | FAIL pre-fix (no route signal) | PASS |
| Vuln | 20 stdlib vulns (go1.25.9) | `go.mod` toolchain go1.26.10 | `govulncheck ./...` | 20 affected pre-pin | PASS: 0 called vulns |
| F1 | Stale detach could overwrite a newer ACTIVE generation (no generation predicate in `markReconnecting`) | `relay_sessions.go:markReconnecting` (CAS `WHERE id=? AND generation=? AND status=ACTIVE`, error propagation; timer armed only on won transition) | `TestStaleDisconnectCannotDowngradeNewGeneration`, `TestMarkReconnectingPropagatesDBErrors` | Defect confirmed by source review (predicate absent) | PASS |
| F2 | Head deadline fired mid-upload (socket + coordinator), false 504 on slow valid uploads | `relay_http.go`: no socket arming in `awaitHead`; enforcement starts at upload completion (`armHeadSocketDeadline`); upload-idle policy with TTL fail-fast in `waitHead` | `TestSlowUploadBeatsHeadTimeout` (red pre-fix: false 504), `TestUpstreamSilenceAfterUploadTimesOut` (prompt 504 + elapsed bound) | Observed false 504 pre-fix | PASS |
| P0-1 | Loopback peer/Host bypass reached agent control handlers | `relay_authority.go:authorizeHost` (exact relay authority only); harness presents Host via `HandshakeTransport` | `TestAgentPathsRequireRelayAuthorityEvenFromLoopback` (red pre-fix: dispatched 400/401) + flipped legacy assertions | Failing-first red observed | PASS |
| P0-4 | MCP header contract unpinned | `proxy.go` (existing policy) + `/headers` fixture fields | `TestMCPHeaderPreservation` (Authorization fwd, X-Ocliv stripped, MCP-Protocol-Version/Mcp-Session-Id/Origin preserved), `TestExplicitInvalidCredentialNoCookieFallback` (M14) | New coverage (policy already correct) | PASS |
| M13 | Per-lease stream-slot exhaustion unpinned end-to-end | `limits.go` quotas (unchanged); `/hold-upload` client-released fixture | `TestPerLeaseStreamQuotaExhaustion` (65th concurrent stream 503, zero app contact, recovery after release) | New coverage (quota already enforced) | PASS |
| F4 | `Yamux.Close()` under `registry.mu` stalled unrelated leases (close handshake to dead peer hangs; loop teardown waits on it) | `relay_sessions.go`: remove-under-lock + close-outside in `registerSession`/`evictLease`/`evictIfOlder`; no post-close delete (replacement survives) | `TestBlockedSessionCloseDoesNotBlockUnrelatedLease`, `TestDelayedCleanupCannotEvictReplacement` | FAIL pre-fix (lookup stalled; mutex held for whole stuck close) | PASS |
| AF1 | Full early success + late upload abort reported as clean completion (terminal frame delivered without upload outcome) | `relay_http.go`: hold `FResponseEnd` for success (<400) until upload outcome; rejections deliver immediately; stall-idle releases the end (P0-06) | `TestHeldEndOnLateUploadFailure` (white-box, fake stream) | FAIL pre-fix (done before abort); PASS post-fix + `-race` | PASS |
| AF3 | Cancelled clean-upload-no-head exchange held slot to 30s head timeout | `relay_http.go:waitHead`: ctx-done + no head → `markStopped` + return (determined outcomes already drained) | `TestCancelWhileStalledLeaksNoGoroutines` (stack-scoped: zero product exchange goroutines post-drain) | Retained 45+ goroutines at 5s pre-fix (drains at headTimeout) | PASS (bounded drain; see note) |
| P2-1 | Per-request agent `http.Transport` left idle pools per cancelled exchange (90s linger each) | `agent_serve.go:localClient` shared client (MaxIdle 8, 30s timeout) + `closeIdleLocalConns` on `Run` return | Drain test gross bound; `TestEarlyResponseDuringUpload` + full suite green | Stack dump: 18 persistConn loops from agent Transports | PASS |

In-session red→green evidence (observed, then fixed): public takedown,
readiness bypass ×2, route status, P1-4 unit. Isolated-checkout
(`/tmp/ocliv-falsify`, `/tmp/ocliv-fals2`, since removed) red evidence:
P1-1 (15 then 10 post-revoke successes), P0-3 readiness, P1-3 orphans;
`TestOversizedTTLRejected` passed there as a functionality control.

Post-decomposition red→green evidence (observed in-session, same tree):
strict-authority 421s (loopback-Host agent requests dispatched pre-fix:
400/401 from handlers — failing-first run), slow-upload false 504
(observed pre-fix: `status=504 bytes=17, want 200`), upstream-silence
prompt 504 with elapsed bound. Stale-detach CAS: defect confirmed by
source review (pre-fix UPDATE had no generation predicate, so a late
gen-1 write could downgrade a resumed gen-2 ACTIVE row); new
fencing/error-propagation unit tests pin the fixed predicate. MCP header
pins + M14 no-downgrade (new coverage; existing policy already correct —
no product-code change required).

## Gate receipts (all on the final tree unless noted)

- `go version` → go1.25.9 linux/amd64 (host); builds use go1.26.10 via
  GOTOOLCHAIN=auto + go.mod pin.
- `go mod verify` → all modules verified.
- `go build ./...`, `go vet ./...` → clean.
- `go test ./internal/... -count=1` → 17/17 packages ok, zero failures.
- `go test ./tests/... -count=1` → 52 PASS / 0 FAIL (also under go1.26.10).
- `go test -race -count=1 ./internal/...` → all ok (incl. relay).
- `go test -race` on concurrency-heavy integration subset → ok.
- `go test -count=2 ./internal/relay/` → ok.
- `go test -count=10 ./internal/relay/` → ok (48s).
- `go test -count=10 -timeout 25m ./tests/integration/` → ok (802s;
  default 10m timeout insufficient for 10 reps — harness note, not a failure).
- Fuzz `FuzzCheckRequestSyntax` / `FuzzCheckUpgradeSyntax`, 2m each →
  PASS, no crashes (5.5M / 7.1M execs).
- `govulncheck ./...` → 0 called vulnerabilities (1 uncalled in deps).
- 2026-10-31 post-Findings-1+2 receipts (same tree): `go build ./...`,
  `go vet ./...` clean; `go test -count=1 ./internal/...` all ok;
  `go test -count=1 ./tests/...` ok (107.9s); `go test -race
  ./internal/relay/ ./internal/agent/` ok. Stale `relay_session.go` /
  `relay_agent.go` references in older rows above denote original locations
  at qualification time (see refactor map); behavior re-verified by the
  gates on this line.

## Gate 2 — private cross-machine MCP publication (2026-11-01) VERIFIED

Relay: laptop 10.9.66.20 (`ocliv` build c91a26f0, `--relay-host` +
`--mcp-host relay.ocliv.test --mcp-port 8444`, DB pre-g2 backup kept on
host). Edge: LAN Caddy 10.9.66.20:8444 (`tls internal`, lab CA copied to
publisher as `~/ocliv-live/lab-ca.crt`, trusted via `OCLIV_CACERT` — no
`-k`/InsecureSkipVerify anywhere). Publisher + auth fixture on main PC
(loopback only). All probes from the publisher machine (independent of
the relay host).

1. Enrollment: fresh `issue-enroll` → `login --relay
   https://relay.ocliv.test:8444` → `Enrolled as key-c876a91f9ea89152`.
2. `mcp publish --local http://127.0.0.1:18766/mcp --name mcp-smoke
   --auth upstream-oauth --ttl 2h --strict-discovery --resource-file …`
   → tunnel attached, lease ACTIVE.
3. `ocliv status`: lease ACTIVE (relay), route live generation 1.
4. Route minted against the publishing lease; public URL recorded:
   `https://relay.ocliv.test:8444/r/<route-id>/mcp`.
5. Binding file written atomically; fixture metadata flipped to the
   public URL with no restart (observed live).
6. Strict discovery `✓ OAuth discovery verified (resource matches
   published URL)`; direct metadata GET advertises the exact URL.
7. Authorized `tools/call ping` → `pong:ocliv-auth-fixture-1`,
   confirmed executed upstream in the fixture log.
8. Missing/wrong bearer → 401 + Bearer challenge; rotated-out token →
   401 immediately with no fixture restart (file re-read per request).
   Audience binding is structural (exact resource match at publish).
9. `access revoke` → tool calls AND metadata discovery → 503 with zero
   upstream executions in the fixture log.
10. Publisher observed the revoked credential, removed the route
    (`✓ MCP route removed`), exited; `mcp_routes` empty, lease CLOSED.

Adjacent fixes proven by this gate: `mgmtHTTPClient` lab-CA trust
(route registration was silently impossible without it), `--mcp-port`
(port-less URLs fail strict discovery closed), fixture boot-order
tolerance (missing binding file warns, strict discovery still gates).

Gate 3 (Funnel public): PASS — see GATE3-PUBLIC-FUNNEL.md.
Still open: Gate 4 (ChatGPT), ZIP pipelines.

## Requalified invariants (touched by this work)

B09 (revoked key reuse denied), C10 (revocation terminates access),
F06 (readiness-gated allocation), F12 (fail-closed persistence):
each has a negative test + falsification above → PASS (local scope).

## What is NOT proven (verdict: NOT READY for production)

- Gate B (public VPS, real DNS/TLS/SNI, cross-machine): not run — no staging infra.
- Gate D (100-conn/1000-req soak, 1–64MiB bodies, 24h soak): not run.
- Gate E (systemd/Caddy deploy, backup/restore, rollback): `packaging/`
  still empty; no clean-host run.
- H08 provenance: baseline commit `6035104` exists; post-baseline
  worktree changes (including this session's) are uncommitted — no
  push attempted.
- External reachability is explicitly unclaimed by `ocliv status` by design.

## Security gates S1–S5 (MCP amendment; local scope unless noted)

- S1 Authorization isolation — PASS (local): nonce replay rejected
  (`TestMgmtMutationReplayRejected`, `TestNonceTableBounded`), cross-tenant
  denial (isolation suites), wrong-token rejection (M14 test, 401 paths),
  authenticated management (signed mgmt + strict authority 421s), zero
  upstream processing on deny (zero-hits assertions incl. MCP denial).
- S2 Transport and edge — PARTIAL: TLS verification, SNI/Host denial,
  loopback-only relay bind, strict authority dispatch, framing/size limits
  all proven locally; public-edge TLS (managed, no `-k`) and relay-side
  exact-Host checks proven via Gate 3 Funnel (GATE3-PUBLIC-FUNNEL.md).
  Funnel→Caddy hop SNI consistency NOT VERIFIED (terminates at Funnel
  by design); VPS/ACME-DNS-01 ingress NOT VERIFIED (Gate B not run).
- S3 MCP interoperability — PARTIAL: JSON-RPC roundtrip through the tunnel,
  header preservation (current + legacy session id), SSE/WS streaming all
  proven locally; real `tools/list`/`tools/call` against a current MCP
  client and provider custom-connection interop NOT VERIFIED.
- S4 Host containment — PARTIAL (local): V1.1 adapter proves operator-only
  command selection (`TestNoShellInterpretation`,
  `TestCommandWithSpacesRejected`), no ambient secret inheritance
  (`TestEnvScrubbed` positive + negative), loopback-only
  (`TestLoopbackOnly`), pinned workdir, lifecycle binding
  (`TestCloseTerminatesChild`, timeout retires adapter), resource bounds
  (413/503/504/502 suites), and through-tunnel authorization
  (`TestStdioAdapterThroughTunnel`, `TestRemoteManagementDeniedViaTunnel`).
  OS-level confinement (dedicated user, systemd restrictions, filesystem
  allow-listing) remains a deployment obligation, NOT PROVEN; no sandbox
  is built into Ocliv by design.
- S5 Failure and recovery — PASS (local): terminal states stay terminal
  across resume/restart (`TestClosedResumeIsTerminal`,
  `TestBootReconciliation`, revoke-then-restart suites); uncertain delivery
  never auto-replayed (E14); no-duplicate-execution rests on single-writer
  stream ownership + atomic consume. Backup/restore resurrection risk
  remains NOT PROVEN (H06).

## Adversarial failure-engineering notes (2026-10-31; production code changed only by the fixes below, all red→green first)

- AF1 (false success) is real at the relay layer but NOT triggerable end
  to end through the all-Go stack: Go's client `Transport` does not
  surface a response head while its own request body is still streaming
  (verified with isolated stdlib probes for both chunked and known-length
  bodies, consuming and ignoring apps). The relay is transport-agnostic,
  so the invariant is pinned white-box at the owning layer
  (`TestHeldEndOnLateUploadFailure`); an integration-shaped variant was
  removed as premise-invalid (it could only observe the serialized path),
  with duplicate-abort coverage already provided by
  `TestAbortedUploadNeverCompletes`.
- AF3 slow-drain, characterized: only the clean-upload + no-head +
  cancelled shape waits out the head timeout; slow-upload cancels release
  promptly (upload outcome races cancellation and wins). No unbounded
  leak: stack-scoped counting shows zero product exchange goroutines
  after drain; residual counts are stdlib keep-alive pools (test client
  90s default; agent pools now shared + 30s idle cap).
- AF5 refuted with evidence: alleged dropped-call double execution was the
  agent's `ProbeLocal` readiness hit (baseline-corrected
  `TestDroppedCallExecutesAtMostOnce` proves exactly-once); alleged leak
  was pool residue (see above).
- `TestPerLeaseStreamQuotaExhaustion` now counts POSTs (`postHits`) so
  agent GET readiness probes (including reconnect re-probes) cannot
  pollute the zero-upstream-contact assertion; genuine duplicate POST
  forwards remain detected. One transient +1-hit failure under a long
  loaded sequence did not reproduce in 13 consecutive runs; mechanism
  unproven, measurement hardened.
- Residual DoS note: a hostile/silent app can still hold each exchange to
  the 30s head timeout (AF3 bound). Slots are bounded by per-lease quotas
  (503 + recovery proven), but no per-IP cost is attached to abandoned
  stalls. Cross-machine S2/S3, H06 restore, and OS-level adapter
  confinement remain NOT VERIFIED (no infra).

Next action: staging qualification (Gates B–E), then release decision.
Feature work stays frozen until then.

## Public MCP Hosting mandate — code-level qualification (2026-11-01)

Objective items P0-A/B/C + P1-A/B/C/D implemented on this tree; all
gates below ran against the final code. No pushes, deployments, or
registrations performed.

- `go build ./...`, `go vet ./...`, `gofmt -l` (repo-wide): clean.
- `go test -count=1 ./internal/...`: 17/17 packages ok.
- `go test -count=1 -timeout 280s ./tests/integration/`: ok (214s;
  9 path-route tests initially failed on the retired `mcp_routes`
  table, fixed via `insertTestPublication`, full suite re-run green).
- `go test -race` on relay/store/cli/agent: ok (incl. 10
  publication-lifecycle tests; one concurrent-rebind failure on the
  very first run did not reproduce in 4+ subsequent runs incl. race —
  mechanism unproven, recorded as flake watch, not as proof).
- Caddyfile validation with a user-space `caddy` binary (no system
  changes): single-host, funnel, and tailnet files all
  "Valid configuration". Live ACME issuance NOT VERIFIED (no DNS).
- New/changed behavior, all failing-first: strict-by-default OAuth
  discovery (`--dev-allow-unverified-discovery` dev-only, URL printed
  only when qualified); durable publications (stable route across
  leases, atomic rebind, revoked tombstones, schema v4 migration
  preserving route IDs); shutdown retains publication offline,
  `mcp unpublish` removes permanently; doctor tiers
  active/degraded/offline/expired/revoked + admission-denial counter;
  placeholder `example.*` hostnames refused at startup.
- Runtime ZIPs rebuilt from this tree into `live/ocliv-dist`
  (amd64 `da505835…`, arm64 `71d7e1e6…`, `ocliv 1.0.0`,
  secret-scan clean); plugin ZIP generatable from source
  (identity `ocliv-chatgpt-hosting` v0.1.2, verified in /tmp build).
- Public HTTPS reachability, ChatGPT registration, and provider
  OAuth interop: BLOCKED — needs operator public ingress (Funnel
  approval or VPS+DNS) and a workspace permitting custom MCP servers.
  `mcp doctor` still reports `EXTERNAL_UNVERIFIED` by design.
- Gate 3 PUBLIC FUNNEL (2026-11-01, relay `ocliv 1.0.0` restarted with
  `--relay-host/--mcp-host pop-os-3.tail8d285a.ts.net --mcp-port 10000`,
  Funnel `https://pop-os-3.tail8d285a.ts.net:10000` → Caddy 18081 →
  relay 8080): PASS — valid public TLS, challenge reachable, root 421,
  strict-discovery publish `✓ OAuth discovery verified`, noauth/badtoken
  401 with zero upstream exec, auth tools/list + tools/call 200 with
  unique nonce, unknown route 404, bad path 421, control-via-route 421,
  publisher stop → 503 retained-offline, republish same name → SAME
  route URL with working call, `mcp unpublish` → 404 on tool +
  discovery paths. Fail-closed aborts (harness binding race, then stale
  binding) deleted the route both times. ChatGPT registration remains
  BLOCKED (workspace permission). Pre-g3 lab agent key left in relay DB — revoke before any untrusted exposure.
  NOTE (SUPERSEDED by P0-A closeout below): at Gate-3 time no operator
  CLI existed to revoke an agent key; revocation required direct DB
  surgery, deliberately NOT performed against the live relay. The
  `ocliv relay revoke-key` CLI has since landed — revoke via CLI before
  opening the relay to untrusted publishers.
- P0-A/B/C closeout (post-Gate-3 worktree): `relay keys list`,
  `relay revoke-key --key-id`, `relay tenants suspend|unsuspend`
  (operator-local, transactional, evict live sessions post-commit,
  5s supervise bound otherwise); named reclaim with revoked tombstone
  detaches lease_id to NULL (FK-safe, tombstone preserved); fenced
  rebind re-proves replacement ACTIVE+TTL in the UPDATE with a bounded
  8-round CAS retry; challenge/connect/mgmt/allocate all enforce
  key-active + tenant-not-suspended. Relay + CLI suites and relay -race
  green. The pre-g3 lab key can now be revoked with the CLI instead of
  DB surgery.

## Post-Gate-3 session work log (2026-11-01, uncommitted worktree)

Phase 0 exit gate re-verified with fresh evidence (all green this
session): P0-A revocation incl. live-session tests, P0-B
`TestNamedLeaseReclaimWithRevokedPublication`, P0-C mid-flight rebind
denials, P0-D sibling-isolation (`TestMCPUnpublishByPublicationID-
IsolatesSiblings`, new) + key-rotation non-inheritance
(`TestReplacementKeyOwnsNothing`, new — replacement key lists nothing,
cannot delete the old tombstone, mints a distinct route), P0-E restore
refusal/rollback/reset/stopped-attestation tests, `TestMgmtFailClosed-
OnStorageError`. Full `go build ./...`, `go vet ./...`, `gofmt` clean;
`go test ./internal/...`, `tests/integration/` (~204s), and `-race` on
touched packages all green.

New behavior (failing-first, narrow scope preserved):

- Domain A probe contract: `ProbePath`/`ProbeStatus` joined the lease
  deployment identity (`config.ResumeQuery`/`FindResume`,
  `agent.resumeLeaseID`/`saveLease`); `ocliv status` shows `Probe:`
  (human + JSON); `doctor` judges the local target by the recorded
  contract with validated `--probe-path`/`--probe-status` overrides.
- Protocol single-sourcing: relay challenge/verify and `ocliv version`
  use `protocol.Version`; agent permanently rejects challenges outside
  `MinVersion`–`MaxVersion` (`TestChallengeVersionMismatchIsPermanent`).
  `versionString()` pinned to the constants.
- Metrics `Snapshot()` exports `ocliv_http_inflight`,
  `ocliv_ws_active`, `ocliv_upstream_dials`; negative gauges clamp to 0.
- Removed dead `doctor.Result.Report(jsonOut)` parameter (always false,
  implementation ignored it).

Docs reconciled to evidence: Gate 3 marked PASS with pointer; S2 cites
Gate 3 for public-edge TLS + relay-side Host checks (Funnel-hop SNI and
VPS/ACME still NOT VERIFIED); revoke-CLI NOTE marked SUPERSEDED;
H08 lines updated (baseline `6035104` exists, worktree uncommitted).
OPERATOR.md gained a Domain A probing section. AGENTS.md already
contained the audit-disposition rule — no duplicate added.
`mcp inspect` deliberately not added (`mcp list --name` covers it).

Dispositions: P0-A/B/C/D/E FIXED (verified this session). Remaining
BLOCKED on operator infra: permanent public DNS/ACME ingress (Gate B),
ChatGPT registration (Gate 4), clean-host install/upgrade, load/soak.
No commits, pushes, or live-infra changes by this session.

Post-Gate-3 follow-up (same session): metrics `Snapshot()` now also
covers the abuse-relevant counters the table named (reconnect total,
auth failures, fencing rejections — `TestSnapshotExportsAbuseCounters`)
and renders all int64 gauges through the clamping helper (no uint64
wrap). A dedicated nonce-replay counter was deliberately NOT added:
`nonceCache.consume` cannot distinguish replay from never-issued
without a tombstone set, and changing that security boundary for a
metric is out of scope. Relay/server/metrics suites green.

## Convergence pass (2026-11-01) — P1 installer/init + full gates

| # | Defect | Enforcement (file:function) | Regression test | Disposition |
|---|--------|---------------------------|-----------------|-------------|
| P1-init-a | ACME email only checked for `@`; newline/shell injection into generated Caddyfile possible | `cli_relay_init.go:parseACMEEmail` (printable token, single @, strict local part, hostname-validated domain) | `TestRelayInitRejectsMalformedEmail` (11 shapes incl. `\n` injection, `;` payload) | FIXED |
| P1-init-b | `writeInitFile` wrote directly; crash left torn files; symlinked `--out`/target followed | `cli_relay_init.go:writeInitFile` (Lstat symlink refusal + temp-file/chmod/fsync/rename); `runRelayInitFiles` (symlink/non-dir `--out` refusal) | `TestRelayInitRefusesSymlinkOut`, `TestRelayInitRefusesSymlinkTarget` (victim file intact) | FIXED |
| P1-inst-a | Installer `mv`d untested binary, warned-only preflight, no rollback | `packaging/install/install.sh` (candidate `--help` preflight before mv; `$BIN.prev` rollback copy; restore on unit-verify failure; rollback path echoed) | `sh -n` syntax gate (installer is root-only; live run BLOCKED pending clean-host) | FIXED (code); live-install run BLOCKED: clean host |
| P0-A/B/D | Pending-verification publication lifecycle; restore terminal-state coverage; local OAuth harness with zero-execution denials | Prior session work, re-verified this session via full gates below | Existing suites | FIXED (re-verified) |

Gates (this tree, 2026-11-01): `go build ./...`, `go vet ./...`,
`gofmt -l` clean; `go test ./internal/...` all ok;
`go test ./tests/integration/` ok (205s);
`go test -race` on relay/agent/config/cli/mcp all ok.

Remaining BLOCKED (operator infra/account, unchanged): permanent
public DNS/ACME ingress (Gate B), ChatGPT registration (Gate 4),
clean-host install/upgrade + rollback drill, load/soak, 24h stability.
`config.DefaultRelayURL` placeholder retained deliberately pending the
hosted-vs-self-host product decision (DEFERRED, not a code defect).
Single relay/SQLite remains SPOF by design. No commits yet; provenance
still unestablished.

## Verification sweep (2026-11-01, same tree)

- `govulncheck ./...`: no vulnerabilities found.
- Bounded fuzz: `FuzzCheckRequestSyntax` (proxy, 45s, 1.33M execs) PASS;
  `FuzzLeaseFenceMonotonic` (lease, 45s, 2.65M execs) PASS; no new corpus.
- Plugin release guard (`packaging/mcp/build-plugin.sh`): `--release`
  exits 1 on the `REPLACE-WITH-*` template URL; dev build exits 0 and
  writes ZIP + SHA256SUMS outside the tree. Placeholder in release
  artifacts remains impossible without the qualified live route.

## Re-audit sweep (resumed goal)

- P2 health listener: VERIFIED NON-ISSUE — `cli_relay.go` accepts
  `--health-listen` validated by loopback-only `parseRelayListen`;
  bind failure is fatal, listener shuts down with relay.
- P2-1 IPv6 probe: VERIFIED NON-ISSUE — `parseMCPLocalURL` reports the
  loopback family and both probe (`config.LoopbackTarget(port, v6)`)
  and tunnel (`--ipv6`) honor it.

## Doc-falsification sweep (resumed goal)

Executed documented commands as written against a release-mode binary
in disposable dirs (`/tmp`, never the tree):
- `mcp publish --stdio -- echo hi` → exit 2, usage, no route created
  (remote-stdio refusal intact).
- `relay init` single-host without `--mcp-host` → exit 2 with
  actionable error; `--check` on the empty dir correctly reports all
  four files missing (exit 8), not success.
- `relay init --domain hosting.test --mcp-host relay.hosting.test ...`
  → exit 0, four files generated; `--check` → exit 0 consistent.
Disposition: documented flows behave as documented; no drift found.

## Re-audit on committed HEAD (defect loop)

- Activation-vs-revoke TOCTOU: VERIFIED NON-ISSUE. `serveMCPRouteActivate`
  CAS-gates on ownership + unrevoked + unverified, but does not check
  lease/key liveness — safe because admission is the enforcing point:
  `revokeAgentKeyTx` terminally revokes all live leases in-tx with
  post-commit session eviction, and `admitRoutedLease` denies anything
  not ACTIVE with a live generation-matched session. A verified_at set
  on a dead lease still denies at every ingress path.
- Concurrent route create: re-verified FIXED. Single-statement
  INSERT..SELECT..WHERE EXISTS(lease ACTIVE) + ON CONFLICT DO NOTHING
  on `idx_mcp_publications_logical`; loser re-reads winner;
  `TestMCPRouteConcurrentCreate` green.

## Re-audit on committed HEAD, round 2 (defect loop)

- Operator-enrollment interference (P0-01): re-verified FIXED.
  `cmdIssueEnroll` uses narrow `relay.IssueEnrollmentCode(db, ...)` and
  never constructs a Server; `relay.New` (sole caller: `cmdRelayServe`)
  keeps `reconcileBoot` for genuine startup. Grep confirms no other
  `relay.New(` call sites.
- Cross-process revoke convergence: VERIFIED. Server-path revoke
  evicts live sessions post-commit (`TestRevokeAgentKeyTerminatesAuthority`,
  `TestRevokeDeniesLiveDispatchAtBoundary`); CLI-driven revocation lands
  in durable state and `supervise` revalidates lease status every 5s tick,
  evicting terminal (REVOKED/CLOSED/EXPIRED) leases under live sessions.

## Re-audit on committed HEAD, round 3 (defect loop)

- Restore atomicity/filesystem safety: VERIFIED (no edit). `BackupState`
  snapshots via `VACUUM INTO` (consistent, WAL-free) + 0600 + rename +
  dirSync. `RestoreState` enforces --relay-stopped attestation,
  `ValidateBackup` (copy + open + integrity_check), data-dir symlink
  refusal, same-file refusal, live-writer tripwire (BEGIN IMMEDIATE,
  fail-closed), revocation rollback diff incl. terminal states,
  token_generation watermark, deleted-publication resurrection guard,
  optional --reset-authority, staged 0600 install + rename + WAL
  sidecar cleanup + dirSync, post-install audit row. Residual honest
  limit (documented in code): the tripwire cannot prove an idle relay
  is stopped — operator attestation required; live drill stays BLOCKED
  on disposable infra.

## Re-audit on committed HEAD, round 4 (defect loop)

- waitHead ctx.Done asymmetry (restartHeadDeadline without
  armHeadSocketDeadline): VERIFIED NON-ISSUE. If the head already
  arrived, no socket wait is pending (awaitHead clears the deadline on
  delivery to the buffered headArrived channel). If not, the
  coordinator returns via markStopped and the admission-site
  `defer stream.Close()` (relay_public.go) releases the blocked
  awaitHead reader. Goroutine-leak coverage:
  `TestCancelWhileStalledLeaksNoGoroutines`.
- Dispatch-time session substitution: VERIFIED enforced. Admission
  site re-checks `admittedSessionCurrent(cur, sess, generation)` after
  OpenStream (P1-5); stale-generation streams are rejected before the
  request head is written, with a test barrier (`dispatchHold`)
  landing exactly in the check-to-write window.

## Re-audit on committed HEAD, round 5 (defect loop)

- Agent stale-generation + dial-target trust: VERIFIED enforced.
  `handleStream` rejects lease/generation mismatch with FAbort before
  any local dial; the dial destination is always the configured
  loopback literal (`config.LoopbackTarget(port, ipv6)` built in
  `prepareTunnel`, never stream-supplied) — D06/D07/F13 hold on the
  agent side, matching the relay dispatch re-check.
- serve-loop goroutine scope: VERIFIED fixed (P1-6). Cancellation
  watcher uses `context.AfterFunc` bound to the session lifetime and
  disarms on serve return; no per-reconnect waiter accumulation.

## Operational note (2026-11-01): funnel moved to relay host

Public edge re-established on joker3 as Gate 3 specifies: Funnel
:10000 → Caddy 127.0.0.1:18081 → relay 127.0.0.1:8080
(--relay-host/--mcp-host pop-os-3.tail8d285a.ts.net --mcp-port 10000).
Verified from public internet: valid Let's Encrypt cert, `/` → 421
relay authority denial, unknown route → 404. `tailscale funnel
status` locally prints "No serve config" despite serving — display
quirk only; public behavior is the oracle.

## Re-audit on committed HEAD, round 6 (defect loop)

- Per-lease budget lifecycle: VERIFIED. `TryAcquire`/`Release`
  symmetric with `defer Release` at admission; `Registry.Drop` on
  `evictLease` and on reconnect-grace expiry; supervise eviction of
  terminal leases funnels through `evictLease`. Restart starts empty
  (in-memory only). No leak path found.
- MCP admission pre-forwarding budget (P1-10): present —
  `MCPAdmissionBurst` per (source, lease) before stream allocation.

## Re-audit on committed HEAD, round 7 (defect loop) — REAL DEFECT FIXED

- WS hijack-buffer loss (P1): FIXED. `serveWebSocket` discarded the
  hijacked `bufrw` (`_ = bufrw`), losing client bytes pipelined past
  the handshake. New `drainHijackedBytes` forwards buffered bytes as
  `FUpgradeBytes` before the bridge loop; the agent side already
  preserved its buffer, so both directions now match. Removed dead
  `buf` lines. Also fixed the silent return on hijack failure → 500.
- Files: `internal/relay/relay_ws.go`,
  `internal/relay/relay_ws_hijack_test.go`
  (`TestDrainHijackedBytesForwardsBuffered`,
  `TestWSHijackFailureReports500`). Red→green observed (undefined
  helper, then PASS); vet clean (fixed a t.Fatal-from-goroutine);
  full relay package green.

## Round 7 supplemental — race gate (2026-11-01)
- `go test -race ./internal/relay/ -count=1 -timeout 280s` → ok (99.991s).
- WS hijack-buffer + backpressure fixes hold under race detector. Round 7 dispositions unchanged (all FIXED).

## Round 8 — CLI/doctor re-audit (2026-11-01)
- Re-inspected `runMCPProbe` modern/legacy stages, `validateEnvelope` id echo,
  `decodeJSONRPC` SSE handling, `selectDoctorLeaseID` (--lease > --name >
  latest, fail-closed), `doctorLoopbackTarget` (IPv6 record honored;
  `http://[::1]:port/mcp` is a valid URL), `parseMCPLocalURL` rejections.
- Removed stray empty ignored dir `internal/cli/ocliv-relay-data/` (created by
  a prior default-`--data` run; all tests pass explicit `--data`).
- `go test ./internal/cli/ ./internal/config/ -count=1` → ok (4.8s / 0.2s).
- Disposition: VERIFIED NON-ISSUE for this leg — no new defect; P2-1 (IPv6)
  and doctor-selection fixes hold.

## Round 9 — limits/transport re-audit (2026-11-01)
- `Throttle.Allow` in-place filter idiom is safe; cardinality capped + sweep.
- `Registry.Drop` called on `evictLease` and reconnect-expiry paths; `detach`
  (RECONNECTING, resumable) and `evictIfOlder` (replacement reuses budget)
  correctly retain it.
- Every declared cap wired: MaxHeaderBytes (relay servers), MaxBodyBytes
  (protocol running total + MCP adapter), WSMaxLifetime/WSIdleTimeout
  (relay_ws + agent_ws), HeaderTimeout/UpstreamTimeout (dialers/servers),
  PreAuthBurst + MCPAdmissionBurst (admission pre-stream).
- `go test ./internal/limits/ ./internal/transport/ -count=1` → ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 10 — authority/routing re-audit (2026-11-01)
- Re-read `authorizeHost` (strict relay authority, no loopback bypass;
  single-host route/metadata shapes pass to `handlePublic`, all other paths
  on the control authority 421), `route` (exact-Host → shared
  `admitRoutedLease`), `serveRouted` (pending-verification 404 on both
  ingresses, MCP two-endpoint surface, no visitor-credential fallback),
  `checkVisitorToken`/`checkCookieSession` (conditional-UPDATE re-checks),
  `serveProxied` (MCP admission pre-stream, dispatch-time generation
  re-check `admittedSessionCurrent`, `dispatchHold` barrier honored).
- Focused tests
  `TestControlAuthority|TestMCP|TestRoute|TestAdmit|TestPathRoute|TestVisitor|TestWildcard`
  → ok (3.9s).
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 11 — REAL DEFECT: fencing-generation restore rollback (2026-11-01)
- Finding: `rollbackDiff` refused token_generation step-back but not fencing
  `generation` step-back. `resumeLease` fences from the row's current
  generation (`newGen = ls.Generation + 1`), so restoring a gen-3 snapshot
  over live gen-5 lets a superseded gen-4 session fence and regain live
  authority (transient, race with the legitimate agent). Severity P1.
- Falsified: new `TestRestoreRefusesFencingGenerationRollback` failed
  pre-fix ("generation-rollback restore accepted").
- Fix: `revocationSet.leaseGen` (`SELECT id, generation`), populated in
  `readRevocations`; `rollbackDiff` refuses backup < live for rows present
  in both (absent rows remain operator-act data loss, symmetric with
  token-generation; live-terminal rows already covered).
- Verify: new test PASS; all 14 backup/restore tests PASS; full
  `go test ./internal/relay/ -count=1` → ok (35.3s); `go vet` + `gofmt` clean.
- Disposition: FIXED.

## Round 12 — agent lifecycle re-audit (2026-11-01)
- Re-read `agent_serve.go`: session-scoped `AfterFunc` (P1-6 holds, no
  per-reconnect waiter leak), single-reader `streamReader` (E04),
  agent-side stale-generation abort (F13), trailer rejection (E12),
  mid-body backend failure → abort not clean end (P0-05), shared
  loopback-only `localClient` with no redirects (D06/D10).
- `IsPermanent` is a typed `PermanentError` (errors.As), not message
  matching — earlier P2 concern resolved. `rn.HTTP` has no post-construction
  writers; unsynchronized read is safe.
- `go test ./internal/agent/ -count=1` → ok; `-race` → ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 13 — installer hardening + packaging re-audit (2026-11-01)
- Finding (P2, fail-early): `install.sh` wrote DOMAIN/MCP_HOST/RELAY_HOST
  raw into root-owned `relay.env` with only a placeholder-domain check; a
  typo'd value (spaces, `;`, newline) fails late at service startup instead
  of at install. Operator is root so this is typo-safety, not a privilege
  boundary — fail direction was already closed.
- Fix: `valid_host()` in `install.sh` (strict DNS label shape, one
  trailing FQDN dot tolerated to match relay `canonicalHost`); numeric
  check for MCP_PORT. Verified matrix 15/15 via shell harness, including
  a red pre-fix run that caught leading-hyphen acceptance (`-foo`, `--x`).
- Durable tests: `packaging/install/install_validation_test.go`
  (`TestInstallValidHostMatrix`, `TestInstallScriptSyntax`) — PASS.
- Packaging re-audit: systemd unit + `ocliv-relay-launch.sh` add
  `--mcp-host`/`--relay-host`/`--mcp-port` only when non-empty (P0-B
  holds); unit keeps loopback-only, NoNewPrivileges, ProtectSystem=strict;
  installer keeps build→preflight→preserve-prev→activate→verify order with
  explicit clean-host NOT YET QUALIFIED honesty.
- `go test ./packaging/install/ -count=1` → ok.
- Disposition: FIXED (installer slice); VERIFIED NON-ISSUE (unit/launcher).

## Round 14 — edge/packaging re-audit (2026-11-01)
- Finding (P2, misconfiguration risk): `Caddyfile.tailnet` defaulted
  `bind {$STAGING_BIND:100.113.85.107}` — a stale machine-specific IP.
  An operator following the doc ("replace with the laptop IP") but
  missing the default would bind a dead address.
- Fix: no default (`bind {$STAGING_BIND}`) so Caddy fails fast at adapt
  time when unset; comments + `docs/OPERATOR.md` now mandate exporting
  `STAGING_BIND=$(tailscale ip -4)`. No other references to the stale IP
  exist in the repo.
- Plugin gates re-verified: `build-plugin.sh --release` → exit 1 on
  `REPLACE-WITH-*` placeholders; dev build → exit 0.
- Full `caddy validate` remains BLOCKED (no caddy binary here; needs the
  relay laptop + sudo). Placeholder syntax verified by inspection.
- Disposition: FIXED (tailnet default); VERIFIED NON-ISSUE (plugin gates).

## Milestone gate — Rounds 11–14 (2026-11-01)
- `go build ./...` → ok; `go vet ./...` → ok;
  `gofmt -l internal/ cmd/ tests/ packaging/` → clean.
- `go test ./internal/... -count=1` → all ok.
- `go test -count=1 -timeout 280s ./tests/integration/` → ok (205.3s).
- `go test -race ./internal/relay/ -count=1` → ok (77.2s, post-backup-fix).
- Worktree clean; all changes committed (67ed597 tip).

## Round 15 — MCP ingress/publication re-audit (2026-11-01)
- Re-read `relay_mgmt_routes.go` create-or-rebind: natural-key
  `ON CONFLICT ... DO NOTHING` + CAS retry (8 attempts), atomic rebind
  with `EXISTS(ACTIVE)` predicate, `INSERT...SELECT...WHERE EXISTS(ACTIVE)`
  atomic mint, profile-clash rejection, tombstone handling. Unique index
  `idx_mcp_publications_logical` present with dedup migration in store.go.
- Re-read `relay_mcp_ingress.go`: EscapedPath parsing defeats %2e
  traversal, route-ID charset, exact two-shape matching, mode/profile
  binding (`mcpModeBinding`), single shared `admitRoutedLease` authority.
- Focused tests (relay `TestMCP|TestPublication|TestRouteCreate|TestActivate|
  TestOAuth|TestFixture`, cli `TestMCP|TestPublish|TestProbe|TestDoctor`)
  → all ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 16 — MCP adapter/proxy re-audit (2026-11-01)
- Re-read `internal/mcp/mcp.go` + `jsonrpc.go`: pinned executable
  (LookPath once, no shell), scrubbed env, loopback-only listener,
  id-correlated coordinator (single stdout reader, waiter drop on
  cancel/timeout, late replies discarded), notifications → 202 without
  waiting, duplicate in-flight ids rejected, `/`+`/mcp` path restriction,
  body caps both directions, timeout retires adapter fail-closed,
  Close order (listener → kill → reap).
- `go test ./internal/mcp/ ./internal/proxy/ ./internal/protocol/ ./internal/access/ -count=1` → all ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 17 — store/persistence re-audit + Round 11 adversarial review (2026-11-01)
- Schema: numbered transactional migrations (V1–V5), version stamp in the
  same tx, unknown-newer fails closed, V2 invalidates pre-P0-4 session
  rows, V3/V4 dedup before unique indexes. Matches the claimed design.
- Round 11 adversarial review: `generation` exists in the base leases
  schema (NOT NULL DEFAULT 1), and `readRevocations` only runs on
  `store.Open`'d (migrated) DBs — the new `SELECT id, generation` cannot
  hit a column-missing database. `--reset-authority` intentionally
  bypasses all rollback checks (documented escape hatch). Mutation check:
  new test failed pre-fix, passes post-fix; legitimate restores (equal
  or absent generations) are not refused.
- Disposition: VERIFIED NON-ISSUE (store); Round 11 FIXED stands.

## Round 18 — REAL DEFECTS: doctor wrong-family + wrong-authority probes (2026-11-01)
- Finding 1 (P1, misdiagnosis): `CheckAgent` hardcoded `127.0.0.1:port`
  for the local-service probe while lease records already stored the
  `IPv6` family ("so diagnostics probe the exact local target") — an
  IPv6 tunnel with a healthy `[::1]` service was reported as a verified
  "unreachable". Demonstrated: IPv4 probe of a live IPv6-only server
  returns verified-negative under the old path.
- Finding 2 (P1, misdiagnosis): `CheckRelay` hardcoded
  `relay.<domain>` although the relay supports `--relay-host` (Funnel
  `*.ts.net` ingress) — relay doctor probed a hostname the relay does
  not serve.
- Fix: `AgentInput.IPv6` → `net.JoinHostPort` family-exact probe, wired
  from the latest lease record in `cmdStatus`; `RelayInput.RelayHost` +
  `relayAuthorityHost()` (explicit wins, else `relay.<domain>`, empty
  fails closed with explicit unknown-authority findings), wired from
  `--relay-host` in `cmdRelayDoctor` (validated via `parseHostname`);
  wildcard lines degrade honestly when no domain is configured.
- Tests: `TestAgentProbeHonorsIPv6Family` (negative + positive),
  `TestRelayAuthorityHostSelection` (4 cases),
  `TestRelayDoctorProbesExplicitHost` (finding names the explicit host).
  All PASS; full `doctor`/`cli`/`config` suites green; vet+gofmt clean.
- Disposition: FIXED.

## Round 19 — metrics/identity/config re-audit (2026-11-01)
- Metrics: fixed counter set, no unbounded labels (G08), gauges clamp
  negatives instead of wrapping; exposition is internal-only.
- Identity: CSPRNG seeds, domain-separated handshake bytes, 2-min
  nonces, 5-min skew bound, verifier-only enrollment storage, 0600 key
  files with unsafe-mode refusal. No defects found; in-memory seed
  zeroing absent (standard Go limitation, ACCEPTED RISK).
- Config/leases: IPv6/TTL/UpstreamHost/ProbePath recorded per lease and
  honored by resume matching (P1-7) and now by doctor (Round 18).
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 20 — relay init generation re-audit (2026-11-01)
- `parseRelayInit` validates domain/mcpHost via the same hostname
  parsers as serve (fail-closed before generation), requires mcp-host
  on the single-host edge, validates ACME email strictly (no controls,
  whitespace, or shell metacharacters; hostname domain part).
- `writeInitFile`: Lstat symlink refusal, identical-content idempotent
  re-run, conflicting content fails closed, temp-file + rename writes.
- `buildInitFiles` renders from embedded packaging templates (no drift);
  `relay.env` values come only from validated inputs.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 21 — visitor/access re-audit (2026-11-01)
- Re-read `relay_access.go`: P0-4 holds (independent non-secret row id,
  bearer only in cookie, verifier-keyed lookup), atomic single-redeem
  consumption, CSRF same-origin redeem, strict-CSP unlock page,
  pre-auth rate limiting on unlock/redeem via trusted-edge client IP,
  per-instance random HMAC key with documented restart invalidation.
- Focused tests `TestUnlock|TestRedeem|TestCookie|TestShare|TestVisitor|
  TestAccess|TestSession` → ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 22 — connect/handshake re-audit (2026-11-01)
- `handleChallenge` pre-auth limited; `handleConnect` requires full
  header set, version match, 32-byte challenge nonce consumed exactly
  once BEFORE signature verification (replay probing burns the nonce),
  identity gate, domain-separated signature verify, distinct WS close
  codes (4401/4409/4429) for terminal/conflict/quota.
- Connect attempts are nonce-gated by the pre-auth-limited challenge
  endpoint, so the missing direct pre-auth check on connect is not a
  bypass (defense in depth holds).
- Post-upgrade attach failure fences with the fenced generation
  (`markReconnecting(ls.ID, ls.Generation)`, adversarial Finding 1 fix).
- Focused tests `TestConnect|TestHandshake|TestChallenge|TestNonce|
  TestAttach|TestAllocate|TestResume` → ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 23 — CLI tunnel lifecycle re-audit (2026-11-01)
- `attachEvents`: non-blocking callback, generation-based delivery
  (P1-01 holds); `runTunnel` fails fast on terminal runner errors with
  corrective actions (P1-02); `runSteadyState` drains re-attachments,
  runner self-exit is terminal; `closeTunnelWith` uses the live
  attachment lease ID (never the store latest), nonzero exit on
  unconfirmed remote close (P1-8); JSON output secret-free (A07),
  share link only via TTY or explicit 0600 file.
- Minor: `runnerExit` maps errors by message substring (CLI surface
  only; agent retry uses typed `PermanentError`). ACCEPTED (no change).
- Focused tests `TestTunnel|TestClose|TestAttach|TestCleanup|TestRunner|
  TestSteady|TestShare` → ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 24 — HTTP exchange + fencing re-audit (2026-11-01)
- Re-read `relay_http.go` coordinator: three distinct deadlines (TTL
  absolute, upload-idle policy, post-upload first-byte), socket deadline
  armed only post-upload (Finding 2 holds), early-head upload watch with
  bounded teardown, determined-outcome-before-cancellation ordering,
  single writer lock, TTL re-checks per phase (R4).
- Focused tests: held-end on late upload failure, stalled-upload
  teardown, revoke fail-closed, stale-detach fencing, newer-deadline
  expiry, stale-generation registration + disconnect → all PASS.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 25 — WebSocket re-audit (2026-11-01)
- Agent (`agent_ws.go`): buffered-reader preservation post-101 (P1-10),
  accept validation before relay confirm (E10), verbatim handshake
  replay with single upgrade pair (D11), short-write completion, idle
  write deadlines, mgmt nonces (P1-07).
- Relay (`relay_ws.go`): subprotocol-offer verification before
  completing the public 101, hijack-buffer forwarding + 500-on-failure
  (Round 7), hijack-failure closes stream fail-closed.
- End-to-end WS covered by `tests/integration/ws_test.go` (green in the
  Round 11–14 milestone gate, 205s suite).
- Focused relay WS tests + `go test -race ./internal/agent/` → ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 26 — fuzz re-run (2026-11-01)
- `FuzzCheckRequestSyntax` (proxy, 30s, 1.1M execs) → PASS.
- `FuzzLeaseFenceMonotonic` (lease, 30s, 2.0M execs) → PASS.
- No new corpus failures; worktree clean of fuzz artifacts.
- Disposition: VERIFIED (continued).

## Round 27 — docs reconciliation + CLI convention check (2026-11-01)
- Swept OPERATOR.md / MCP-HOSTING.md / GATE3 / QUALIFICATION.md for
  stale claims after Rounds 11–26: loopback examples accurate,
  STAGING_BIND mandate documented, placeholder gates described, no
  references to removed defaults. No contradictions found.
- `ocliv relay --help` / `ocliv mcp --help` fail as unknown commands —
  consistent CLI-wide convention (only top-level `ocliv --help`
  exists). Not a defect; no change.
- Live read-only probe: `ocliv doctor` in this environment reports
  verified relay dispatch (HTTP 401 on challenge), trusted TLS, and an
  honest verified-negative local probe. No state mutated.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Milestone gate — Rounds 18–27 (2026-11-01)
- `go build ./...` → ok; `go vet ./...` → ok;
  `gofmt -l internal/ cmd/ tests/ packaging/` → clean.
- `go test ./internal/... -count=1` → all ok.
- `go test -count=1 -timeout 280s ./tests/integration/` → ok (211.7s).
- `go test -race ./internal/doctor/ ./internal/cli/` → ok.
- Worktree clean; all changes committed (af4853b tip at gate time).

## Round 28 — lease management/revocation re-audit (2026-11-01)
- `agentLeaseAuth`: ownership + skew + signature + one-time global
  nonce (INSERT claim, replay denied); GET status needs no nonce
  (read-only, correct).
- `revokeLeaseTx` / `revokeAgentKeyTx`: single-tx revocation of
  tokens, sessions, generation bump, lease status, publication
  tombstones; post-commit session eviction kills in-flight forwarding;
  tenant unsuspend never resurrects keys (explicit re-enrollment).
- 11 focused tests (`TestMgmt|TestLease|TestRevoke|TestRotate|
  TestShare|TestClose|TestSuspend|TestUnsuspend|TestAtomic|TestEvict`)
  → all PASS.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 29 — transport/enrollment/operator re-audit (2026-11-01)
- Transport: `checkedTLS` refuses nil/InsecureSkipVerify (B01/B02),
  plaintext only via explicit loopback-test flag; bounded control
  messages, stream-open timeout, caller-must-close discipline (E06).
  `isWSS` prefix check is loose ("httpsX") but fail-closed at dial.
- Enrollment: one-time code consumed transactionally with key insert;
  `IssueEnrollmentCode` is a narrow store op — no `Server`
  construction, no `reconcileBoot` side effects on live leases (P0-01).
- Operator revocation paths covered in Round 28.
- Focused transport/enrollment/operator tests → ok.
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 30 — Server construction/dist/harness re-audit (2026-11-01)
- `relay.New` is the single construction site: `reconcileBoot` errors
  refuse startup (P1-05), mux wiring + authority gate (`authorizeHost`
  before mux, CONNECT rejected first) in one place. No second
  construction path; enrollment uses the store-only function (P0-01).
- `live/ocliv-dist/SHA256SUMS` verifies OK (both runtime zips).
- `tests/staging/` harness present (edge/forwarding/recovery + fixtures).
- Disposition: VERIFIED NON-ISSUE for this leg.

## Round 31 — MCP publish/expose boundary re-audit (2026-11-01)
- `parseMCPPublish` refuses `--stdio` under both auth modes (P0-1/P0-2:
  bridge cannot enforce upstream OAuth, fixture profile cannot bound
  an arbitrary child) and refuses anonymous-fixture publication (P0-F);
  `mcp expose` is loopback-only with no tunnel path.
- Publish order: local URL validation → local probe → protocol probe
  (AUTH_REQUIRED accepted as presence only for upstream-oauth) →
  tunnel → route; nothing registered remotely on local failure.
- Unpublish: route-ID path deletes exactly one owned publication;
  lease path deletes routes then closes lease with independently
  recorded outcomes (404 already-gone is success, not failure).
- 23 focused tests → all PASS.
- Disposition: VERIFIED NON-ISSUE for this leg.

## FINAL CONVERGENCE AUDIT (2026-11-01)
System-wide re-audit Rounds 7–31. Every subsystem examined against the
live tree; all discoverable actionable defects fixed with red→green
tests and committed in small slices. Final gates at tip: build, vet,
gofmt, full internal suite green; worktree clean.

Disposition ledger (this loop):
- FIXED (4): WS hijack-buffer loss + silent hijack failure (R7);
  restore fencing-generation rollback (R11); installer hostname/port
  validation (R13); doctor IPv6-family + relay-host probes (R18).
- FIXED (1): tailnet Caddyfile stale bind default (R14).
- VERIFIED NON-ISSUE (21 legs): CLI/doctor, limits/transport, authority/
  routing, agent lifecycle, MCP ingress/publication, MCP adapter/proxy,
  store, metrics/identity/config, relay init, visitor/access, connect/
  handshake, CLI tunnel lifecycle, HTTP exchange/fencing, WebSocket,
  docs reconciliation, lease mgmt/revocation, transport/enrollment,
  Server construction/dist, MCP publish/expose, fuzz + integration
  suites green.
- ACCEPTED RISK (2, minor): CLI runnerExit message matching (agent uses
  typed PermanentError); in-memory seed zeroing absent.
- BLOCKED, operator-only (unchanged, need no code): clean-host
  install/upgrade drill; Gate B public DNS/ACME; Gate 4 ChatGPT
  registration + real provider OAuth; load/soak/24h stability;
  production backup recovery on live infra.
No unresolved actionable finding remains. Loop converged.

## Round 32 — clean-host install drill (docker Debian, disposable) + login fix
Drill (container removed afterwards, zero host footprint):
- `install.sh` on clean debian:stable-slim + Go 1.26: build ok, `--help`
  preflight ok, binary/launcher/unit/env installed, perms verified
  (`relay.env` 0600 root, `/var/lib/ocliv` 0700 ocliv:ocliv), ocliv user
  created, re-run preserves `$BIN.prev` rollback candidate.
- `systemctl daemon-reload` fails without init (exit 127) — expected:
  install.sh needs a systemd host for activation; everything before that
  point verified. Residual: activation + `systemd-analyze verify` still
  need a VM/systemd host (narrowed BLOCKED).
- Relay boots from installed artifacts (namespace t.drill.test).
- Caddy 2.11.7 edge (`tls internal`, header-overwrite discipline):
  `caddy validate` ok; staging CA trusted via system store.
- Enroll → login → named tunnel ACTIVE/protected → unauth browser 302,
  API 401 → redeem 200 → authorized cookie 200 with exact fixture body
  → tunnel close → authorized cookie 503. Full lifecycle proven.
- Drill finding (P1, FIXED): direct-IP enroll is correctly rejected at
  the authority gate (421), but login mapped every non-200 to "invalid
  or expired code", sending the operator to re-issue a live code.
  `loginDeniedMessage` now names the real status (401 keeps the
  bad-code message) and states the code was not consumed.
- Tests: `TestLoginDeniedMessageHonestStatus`,
  `TestLoginAuthorityRejectionSavesNothing` → PASS; full cli suite green.

## Round 33 — bounded load soak (disposable loopback, 3 min)
- Setup: relay + agent + fixture on loopback, public named tunnel,
  20-way parallel GETs with small bodies, mid-soak tunnel kill and
  named resume (fencing exercised under load).
- Result: 7880/7880 HTTP 200 through the full forwarding path
  (phase 1 + post-resume phase 2, zero 503/deny leakage), 0 errors in
  the relay log, resumed tunnel ACTIVE.
- Relay RSS 14.4MB → 21.4MB during load, flat across the 30s settle
  (no leak signature; Go heap not yet collected is expected).
- Scope: bounded 3-minute smoke, NOT 24h stability; loopback only
  (TLS edge covered by the Round 32 drill). Soak script kept at
  /tmp/soak/run.sh (transient, outside the repo).
- Disposition: PASS (bounded); 24h soak remains BLOCKED (needs time +
  production-like host).

## Round 34 — relay laptop upgrade + cross-machine E2E (2026-11-01, joker3)
- Found live staging on 10.9.66.20 (old binary, Funnel→Caddy:18081→
  relay:8080) with CLOSED/EXPIRED leases only — safe to restart.
- Drift fixed: laptop Caddyfile.funnel used `{scheme}` (wrongly reports
  http behind Funnel TLS); replaced with repo `X-Forwarded-Proto https`.
- Upgraded to tip (md5 3fcdd609): DB backed up pre-swap, old binary +
  laptop Caddyfile preserved, schema migrated on boot, keys intact.
- Funnel edge re-verified (401), plus new LAN edge (Caddy :8443,
  tls internal): enroll → login → ACTIVE protected tunnel from this PC
  → unauth 302/401 → redeem 200 → authorized 200 exact body → close →
  503. Full cross-machine path on the release candidate.
- `relay init` deployment files generated on the laptop and
  `--check` passes. systemd activation still needs sudo on joker3
  (operator step below).
- Disposition: FIXED (edge drift); VERIFIED (upgrade + E2E).

## Round 35 — systemd relay live + cross-machine E2E (2026-11-01, joker3)
- Operator installed the generated unit (`ocliv` user, 0600 env with
  DOMAIN+RELAY_HOST+MCP_HOST+MCP_PORT, migrated lab DB, daemon-reload,
  enable --now) → `systemctl is-active` = active.
- Systemd instance verified from this PC: funnel edge 401; tunnel
  attach ACTIVE/protected through the unit; tailnet edge unauth 401 →
  redeem 200 → authorized 200 exact body → close → 503.
- Migrated enrollment key works under the unit (identity preserved
  across foreground→systemd cutover). No live tunnels were disrupted
  (all leases were terminal before cutover).
- Remaining: public DNS/ACME + ChatGPT perms (operator/infra).
- Disposition: VERIFIED (systemd activation + full cycle).

## Round 36 — wildcard DNS-01 + reserved-domain guards (2026-11-02)
- Finding (P0, incomplete TLS config): `relay init --edge wildcard`
  generated a Caddyfile whose DNS-01 block was commented out, and
  `--check` passed it — a deployment that fails only at runtime.
- Finding (P1, impossible config): wildcard on RFC-reserved/never-public
  namespaces (`.test`, `.localhost`, `.local`, `.home.arpa`,
  `example.*`, single-label) can never complete public DNS-01.
- Fix: wildcard REQUIRES `--dns-provider` (+ `--dns-env`, default
  `DNS_API_TOKEN`); both rendered verbatim only after token-shape
  validation; template stanza is now active with placeholders;
  reserved namespaces refused unless `--allow-reserved-domain`
  (lab prep); provider flags rejected on single-host; `--check` fails
  on dead (commented) dns stanzas, `<provider>` remnants, and staging
  markers (`tls internal`, `STAGING_`, tailnet IP, `:10000`).
- Tests: 6 new (provider required, single-host rejection, reserved
  refusal matrix, escape hatch + --check, malformed provider/env,
  dead-stanza/staging-marker --check); updated wildcard generation
  test asserts the active stanza. All 16 init tests PASS.
- Disposition: FIXED.

## Round 37 — installer rollback preservation (2026-11-02)
- Finding (P1): `install.sh` overwrote `$BIN.prev` on every run, so a
  second upgrade destroyed the first rollback point (verified by
  reading the unconditional `cp -p` before the fix).
- Fix: `preserve_rollback()` keeps the first candidate (first-wins);
  re-runs no longer clobber it.
- Test: `TestInstallPreservesRollbackCandidate` drills two upgrades
  against the extracted function (red before: function absent; green
  after). Full `packaging/install` package PASS (5/5).
- Disposition: FIXED.

## Round 38 — offline-route negative test (2026-11-02)
- Gap: "disabled or offline routes" had Gate-3 manual evidence but no
  repo regression test; unknown-host, replay, stale-generation, and
  restart-recovery already covered (`staging_domain_test.go`,
  `TestMgmtMutationReplayRejected`, `TestStaleDisconnect*`,
  `TestRelayRestartRecovery`).
- Test: `TestOfflineRouteDeniesWithoutForwarding` (lifecycle_test.go):
  public lease serves 200 baseline, agent image stopped, visitor must
  converge to 503 with zero additional local-app hits. PASS (0.25s).
- Invalid-certificate rejection stays NOT VERIFIED locally (harness
  is plain-HTTP loopback; needs the external TLS gate).
- Disposition: FIXED (locally testable portion).

## Convergence checkpoint — Rounds 36-38 gates (2026-11-02)
- `go build ./...`, `go vet ./...`, `gofmt -l` (clean), full
  `go test ./internal/...`, integration suite 210s PASS, race
  (relay/agent/cli/mcp/doctor) PASS — all on the Round 38 tree.
- Code-controlled work complete: wildcard DNS-01 init guards,
  installer rollback preservation, offline-route negative test,
  home-host + VPS guides, funnel relay-host rule.
- NOT VERIFIED (external infra required): live public DNS-01 wildcard
  issuance, off-network HTTPS tunnel test, ChatGPT registration
  (workspace permission), invalid-certificate rejection over real TLS,
  24h soak. No PUBLIC READY claim.

## Round 39 — setup detection slice (2026-11-02)
- New `internal/setup` package: interface scan + per-family echo
  observation classifies direct-v6/direct-v4/NAT-needs-forward/CGNAT/
  unknown; inbound always reported UNKNOWN (outbound echo is not
  inbound evidence). No side effects.
- New `ocliv setup --check/--auto/--json` (auto = detect + guided
  next steps in this slice; provisioning follows). Token/credential
  handling deferred to the dynv6 slice (env/file only, never argv).
- Tests: 6 classification/echo tests + 2 CLI tests (echo verdict,
  unknown-flag rejection). Focused suites PASS; live `setup --check`
  on this host correctly reports nat-ipv4-needs-forward.
- Disposition: FIXED (slice 1 scope). dynv6 update, bootstrap,
  wildcard, Oracle adapter remain pending.

## Round 40 — setup dynv6 DNS slice (2026-11-02)
- New `UpdateDynv6` client: zone restricted to *.dynv6.net (refused
  pre-network otherwise), token required, server errors redact the
  token, non-2xx fails.
- `setup --auto --hostname ZONE` reads the HTTP token from DYNV6_TOKEN
  or owner-only --token-file (never argv/logs/errors); --dry-run
  previews with the token redacted and sends nothing; missing token
  exits 4 with the exact account step.
- Tests: 4 client tests + 3 CLI tests (dry-run silence, fixture
  update, missing-token auth). Focused suites PASS. No live DNS
  mutation performed in this slice.
- Disposition: FIXED (slice 2 scope). Bootstrap/systemd/enrollment
  (slice 3) pending.

## Round 41 — setup render+verify+persist slice (2026-11-02)
- `setup --auto --hostname Z --acme-email E [--out D]`: after the DNS
  update, renders the single-host deployment via the existing init
  machinery, self-checks it with checkInitDir, confirms the name
  resolves to the observed egress, and only then persists relay_url
  (mergeRelayURL) for `ocliv 3000`/`mcp publish`. Mismatch or
  unresolvable DNS exits 5 with no persistence. Nothing activated.
- Tests: render-persists-on-match, render-refuses-on-mismatch (stubbed
  resolver, temp HOME, fixture endpoints). Focused suites PASS.
- Disposition: FIXED (slice 3a scope). Caddy/systemd/enrollment
  automation (slice 3b) pending.
