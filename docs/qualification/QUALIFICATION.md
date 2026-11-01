# Ocliv — Local Qualification Record (Gate A + Phase 1/2)

Date (UTC): 2026-10-31. Tree: `/home/bamn/ocliv` (no git baseline; all files
untracked — H08 release provenance remains open). Toolchain: go1.26.10
(`toolchain go1.26.10` in go.mod). No pushes, no live-infra changes.

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

## Requalified invariants (touched by this work)

B09 (revoked key reuse denied), C10 (revocation terminates access),
F06 (readiness-gated allocation), F12 (fail-closed persistence):
each has a negative test + falsification above → PASS (local scope).

## What is NOT proven (verdict: NOT READY for production)

- Gate B (public VPS, real DNS/TLS/SNI, cross-machine): not run — no staging infra.
- Gate D (100-conn/1000-req soak, 1–64MiB bodies, 24h soak): not run.
- Gate E (systemd/Caddy deploy, backup/restore, rollback): `packaging/`
  still empty; no clean-host run.
- H08 provenance: no git baseline exists.
- External reachability is explicitly unclaimed by `ocliv status` by design.

## Security gates S1–S5 (MCP amendment; local scope unless noted)

- S1 Authorization isolation — PASS (local): nonce replay rejected
  (`TestMgmtMutationReplayRejected`, `TestNonceTableBounded`), cross-tenant
  denial (isolation suites), wrong-token rejection (M14 test, 401 paths),
  authenticated management (signed mgmt + strict authority 421s), zero
  upstream processing on deny (zero-hits assertions incl. MCP denial).
- S2 Transport and edge — PARTIAL: TLS verification, SNI/Host denial,
  loopback-only relay bind, strict authority dispatch, framing/size limits
  all proven locally; cross-machine TLS/edge/SNI behavior NOT VERIFIED
  (Gate B open, no staging infra).
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
