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
