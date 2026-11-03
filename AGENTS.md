# AGENTS.md — Operating Ocliv

Guide for agents (and humans) running, testing, and troubleshooting
Ocliv. Ocliv is a minimal-dependency, self-hosted localhost-to-HTTPS
tunnel: one Go relay binary, one Go agent binary, Caddy as the TLS edge,
SQLite for relay state. The agent makes only outbound authenticated
connections (WSS + yamux, Ed25519 identities). The relay never dials
out. Default visitor access is protected; public exposure is explicit
opt-in only.

Related docs: [production spec](/home/bamn/ocliv/ocliv_production_spec_v1.md),
[invariants](/home/bamn/ocliv/ocliv_invariants_and_exceptions_v1.md),
[anti-spec](/home/bamn/ocliv/ocliv_anti_spec.md),
[MCP hosting](/home/bamn/ocliv/docs/MCP-HOSTING.md),
[tailnet staging](/home/bamn/ocliv/docs/OPERATOR.md),
[packaging](/home/bamn/ocliv/packaging/caddy/Caddyfile.single-host).

## Non-negotiables

- The relay binds loopback only (`--listen 127.0.0.1:PORT`). A public
  relay listener bypasses the TLS edge and is rejected at startup.
- No `--insecure`, no `InsecureSkipVerify`, no HTTP fallback, no
  client-supplied executable paths, no second proxy or gateway.
- `--domain` is required and placeholders (`example.com/net/org`) are
  refused. There are no safe defaults for addressing.
- Route IDs are opaque identifiers, never bearer secrets. Upstream
  OAuth protects published tool calls,
  never TLS/hostname/path secrecy. Anonymous fixtures are local-only
  (`mcp serve`); `mcp publish` refuses them, so they can never back
  a public route.
- `X-Ocliv-Authorization` is the relay's own credential and never
  reaches the local app; application `Authorization` passes through
  byte-identical for the upstream server to validate.
- Funnel (`tailscale funnel`) is a temporary test edge only, never a
  product dependency. Always `tailscale funnel reset` when done.
- Never print secrets. `attachJSONMap` keeps share URLs out of JSON;
  delivery is via verified TTY or `--share-link-file PATH`.

## Build and verify

```sh
cd /home/bamn/ocliv
go build ./...
go vet ./...
gofmt -l internal/ tests/
go test ./internal/... -count=1
go test -count=1 -timeout 280s ./tests/integration/
go test -race ./internal/relay/ ./internal/agent/ ./internal/config/ ./internal/cli/ ./internal/mcp/
```

No CI config or Makefile exists in-tree; the commands above are the
gates. Run the full integration suite once after relay/transport
changes, not after every edit. One focused test run per change; never
re-run an unchanged check to collect evidence.

## Workflow A — local smoke (one machine, no network)

```sh
go build -o /tmp/ocliv ./cmd/ocliv
mkdir -p /tmp/ocliv-lab && chmod 700 /tmp/ocliv-lab
/tmp/ocliv relay serve --listen 127.0.0.1:8080 \
  --domain ocliv.test --data /tmp/ocliv-lab   # terminal 1
/tmp/ocliv relay issue-enroll --data /tmp/ocliv-lab --tenant lab  # terminal 2
# enroll the agent, start a local app on 127.0.0.1:3000, then:
/tmp/ocliv 3000
```

## Workflow B — MCP hosting for ChatGPT (single-host)

Relay (public machine, loopback relay + Caddy on :443):

```sh
ocliv relay serve --listen=127.0.0.1:8080 --data /var/lib/ocliv \
  --domain <domain> --mcp-host <relay-host>
```

`--mcp-host` is the exact public FQDN serving `/r/<route-id>/mcp`
(often the same host as agent control). Without it, route creation
fails closed with 409. `--relay-host` overrides the control authority
when the public hostname is not `relay.<domain>` (e.g. `*.ts.net`).

Publisher (machine running the MCP server, outbound only):

```sh
ocliv login --relay https://<relay-host> --code-file -
ocliv mcp publish --local http://127.0.0.1:8765/mcp \
  --name dev-tools --auth upstream-oauth     # native HTTP MCP server
# NOTE: `publish --stdio` is disabled (bridge cannot enforce auth yet).
```

The server must serve exactly `/mcp`; there is no `--public` flag and
`mcp manage` is never exposed remotely. The printed
`https://<relay-host>/r/<route-id>/mcp` is stable across leases for the
same `--name` (durable publication); republish rebinds it.
Ctrl+C closes the lease and RETAINS the publication offline (same URL
on republish); `mcp unpublish --lease ID` removes it permanently.
OAuth discovery verification is strict by default:
unreachable/invalid discovery deletes the route and fails closed.
Explicit dev-only `--dev-allow-unverified-discovery` warns and serves
with the URL marked NOT VERIFIED (never for ChatGPT).
`ocliv mcp doctor [--lease ID] [--name LABEL]` reports
lease, route, local service, and MCP protocol separately.

## Workflow C — temporary Funnel public test

On the relay machine (reversible; reset when done):

```sh
./caddy run --config packaging/caddy/Caddyfile.funnel --adapter caddyfile &
ocliv relay serve --listen=127.0.0.1:8080 --data "$HOME/ocliv-lab" \
  --domain <anything-valid> --relay-host <funnel-host> --mcp-host <funnel-host>
tailscale funnel 18081
tailscale funnel status   # note the https://<host> name
# ... publish from the publisher machine against https://<host> ...
tailscale funnel reset
```

The funnel hostname doubles as control authority and MCP host; the
relay keeps them separated by exact host plus strict path split.

Lab relay readiness (loopback-only, 2026-11-03 live VERIFIED): the internal
health mux (`127.0.0.1:18080`, never public) serves `/health/live` ("ok") and
`/health/ready`, where ready evaluates `ReadyForSessions()`
(`internal/relay/relay.go:76` — SQLite pool-conn PingContext(2s) + admission-key
capacity under `limits.MaxThrottleKeys`). A 200 ready is a genuine prerequisite
probe, not process-alive theater — but it still proves nothing about public
reachability; external proof stays with `mcp doctor` + public probes.

## Exit codes

`0` ok (also clean shutdown) · `2` CLI validation · `3` local target
unreachable · `4` auth/enrollment · `5` relay TLS/reachability ·
`6` protocol verification failed (e.g. `mcp doctor` found an
unusable MCP endpoint) · `7` quota/lease · `8` internal error.
A green `mcp doctor` exit means initialize + tools/list both answered;
anything else is a failed oracle, not a pass.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `421 misdirected` on agent path | Host header is not the relay authority | Use the exact `--relay-host` (default `relay.<domain>`); check SNI/Host at the edge |
| `421 misdirected` on `/r/.../mcp` | Host is not the configured `--mcp-host`, or path is not route-shaped | Set `--mcp-host` to the exact public FQDN; route shape is `/r/<route-id>/mcp` exactly |
| `409` creating a route | Single-host ingress not configured | Restart the relay with `--mcp-host <relay-host>` |
| Route URL empty / `(no external host configured)` | Same as above | Same as above |
| Route `404` | Unknown/expired route or dead lease | Republish; check lease status with `mcp doctor` |
| Route `503` + `Retry-After` | Lease inactive, offline, or stale generation | Reconnect the agent; revocation/closure is terminal |
| Relay refuses `--listen` | Non-loopback listener | Bind `127.0.0.1`; expose only via Caddy/Funnel |
| Relay refuses `--domain` | Empty or placeholder domain | Configure the real domain; no default exists |
| `mcp doctor` exit `6` | Local `/mcp` failed initialize or tools/list | Probe the local server directly; fix it before blaming the tunnel |
| `not enrolled` | No agent keys | `ocliv login` with a fresh one-time enrollment code |
| `tailscale funnel` asks for approval | First-time Funnel needs tailnet admin consent | Approve in the admin console, or test over the tailnet instead |
| `setup --auto` stops after DNS | CGNAT, missing token, or no viable path | Read the printed reason; fix that prerequisite (token, forward, provider) and re-run — nothing half-provisions |
| setup persists nothing | DNS does not match egress yet | Wait for propagation and re-run; relay_url is written only after a verified match |

## Repo map

- `internal/relay/` — ingress, authority, leases, live sessions,
  visitor access, route management, HTTP/WS forwarding.
  `relay_authority.go` (host dispatch), `relay_mcp_ingress.go`
  (path-route resolution), `relay_public.go` (admission + dispatch).
- `internal/agent/` — tunnel client: challenge, attach, local
  forwarding. `internal/cli/` — all UX: `cli.go` (dispatch/help),
  `cli_commands.go` (relay/tunnel), `cli_mcp*.go` (publish/serve/doctor).
- `internal/mcp/` — bounded stdio adapter (loopback only, argv-only
  children). `internal/setup/` — `setup --auto` detection (read-only),
  dynv6 sync, deployment render, bootstrap plan, Oracle adapter; live
  executors need root, tests cover detection/client/plan/enroll-core.
  `internal/{access,proxy,protocol,lease,store,limits,transport}/`
  — small policy/state primitives; keep them that way.
- `tests/integration/` — harness + end-to-end (path routes, profiles,
  lifecycle, chaos). `packaging/caddy/` — wildcard + single-host edges;
  `packaging/systemd/` — relay unit. `docs/` — operator guides.

When changing behavior: one focused failing test first, the smallest
fix, focused suite green, then the broad gates once. Never weaken an
assertion to get green, and never present local green as public
qualification — external items stay NOT VERIFIED until exercised
against real infrastructure.

## Audit dispositions

Every audit ends with one disposition per material finding —
FIXED, VERIFIED NON-ISSUE, ACCEPTED RISK, DEFERRED, or BLOCKED —
named with the evidence behind it. A fix counts as FIXED only after
independent verification: a check separate from the implementation's
own claims (red-before/green-after where practical), not the absence
of a failure. Do not advance to the next audit phase while an
unresolved finding invalidates it; carry it as BLOCKED or DEFERRED
with its reason instead of silently dropping it.

### 2026-11-02 evidence-driven remediation register

- Task A issuer segment-scope (`ocliv-native.mjs`, sibling-prefix/userinfo/fragment rejection): FIXED — red-before (33/1) / green-after (34/34), full gates green.
- Task B listener normalization (`cli_relay.go`, numeric bind, TOCTOU closed): FIXED — red-before / green-after, `internal/cli` + race green.
- Task C edge identity (spoofed XFF): VERIFIED NON-ISSUE for code — no code change needed; proven by live 130-rotating-spoof probe (120x401 then 10x429, one bucket) plus new isolated-edge regression test.
- AUDIT_2026-11-02 "no security vulnerabilities / P0 NONE": REFUTED as a qualification finding — Tasks A and B were real defects, now FIXED above; the audit's architecture description itself is SUPERSEDED where it conflicts with the fixed code.
- Skybridge ChatGPT/Auth0 live-integration claim: UNVERIFIED (no dated redacted evidence on file) — README/SPEC downgraded accordingly; public OAuth/MCP handshake half re-verified live 2026-11-02 (PRM 200, pong, anon/revoked 401s).
- Metis public integration (HTTP+OAuth upstream, publish/revoke through public route): BLOCKED on Metis owner — loopback expose legs pass (`TestOclivLoopbackExposeServesMetisTools`, `TestOclivLoopbackRemoteMessageChain`), `--stdio` prohibition preserved.
- Gate 4 ChatGPT registration, clean-host install, permanent ingress, soak: NOT VERIFIED (operator-gated, unchanged).

### 2026-11-03 product-rereview remediation round (`abdda2e` → `804f21a`)

- P0-A wildcard DNS proof + ACTION_REQUIRED + persist-only-on-success (`cli_setup.go`): FIXED — fresh `<label>.t.<domain>` verification, manual-record instruction on miss, exit codes distinguish completed/action-required/failed, relay URL persists only after gates pass.
- P0-B dynv6 token sanitization (`setup/dynv6.go`): FIXED — failing-first transport-error regression, token never in errors/output/logs, categories preserved.
- P0-C preserve deployments (`setup/bootstrap.go`): FIXED — unmanaged-Caddy refusal, staged install with marker, rollback on later-step failure, injected-failure tests.
- P1-D backoff reset (`agent/agent.go`): FIXED — reset after healthy session, escalation preserved, 2x stability runs.
- P1-E dynamic DNS refresh (`setup/refresh.go`, `--refresh-dns`): FIXED — change-only updates, no relay restart, change/no-change CLI tests.
- P1-F named status states (`cli_status.go`, `doctor` already verified/unverified): FIXED — RELAY DISCONNECTED / AUTH REQUIRED / RECONNECTING / ROUTE OFFLINE with Next actions in human + JSON; attachment never claimed as public reachability.
- P1-G durability (`config/leases.go`): FIXED the one found gap — crashed-save `.tmp-*` sweep with failing-first regression; rest of the gate list (restart, revoke races, restore rollback, leak bounds) VERIFIED NON-ISSUE against existing suites (`lifecycle`, `revoke`, `relay_backup`, `exchange_adversarial`).
- P2-H `ocliv mcp PORT` alias (`cli_mcp.go`): FIXED — thin rewrite to existing publish with `--auth upstream-oauth` pinned; parser-level regression test.
- P2-I README + everyday-first help: FIXED — truthful quickstart, capability matrix, BLOCKED/NOT VERIFIED labels where true.
- P2-J shared-relay readiness (`docs/SHARED-RELAY.md`): recorded as BLOCKED — operating requirements + client contract specified; no operated relay, no anonymous free-for-all.
- Broad gates at `804f21a`: build + vet + `go test ./internal/...` green, full integration suite green (211s), race on relay/agent/cli/config/setup green. Soak, clean-host install, public ChatGPT registration: NOT VERIFIED (operator-gated).

### 2026-11-03 chaos engineering Stage 5, local scope (`143b9af` → `2ff2ad9`)

- E5 nonce persistence across restart: VERIFIED NON-ISSUE (INSERT OR IGNORE + 5-min skew; no code change).
- E2 failed-validation restore (`setup.installManagedFile`): FIXED — loud error, backup preserved; red→green proven.
- E1 concurrent refresh overlap, E3 unwritable-rollback, C1 compound chain, C2 stale-timestamp replay, C3 16-way route convergence: PASS (C3 `relay_chaos_routes_test.go`, race-clean).
- D1–D3 local DNS/TLS/enrollment faults: PASS; D4/D5 live LAN impostor via 10.9.66.20: PASS (zero hits); D6 dynv6 error shapes: PARTIAL (401 auth-first; 200-with-error shape unobservable without valid token).
- P7 doctor/status honesty, P8 unit validation, P9 planner dry-run honesty: PASS. R1 health-listener Serve logging: FIXED.
- F1 bounded fuzz (`lease` + `proxy`, ~16.8M execs): PASS, zero crashes.
- A2 unbounded `audit_events` growth: FIXED (Stage 6) — 90-day `store.AuditRetention`, schemaV6 time index, `PruneAuditEvents` in `reconcileBoot` (fail-closed); red→green regression tests; full gates green. E2/C1/E3 chaos replayed green on corrected impl (VERIFIED); D6 dynv6 200-shape BLOCKED (needs valid token). Full Stage-6 matrix: `docs/qualification/CHAOS-BATCH.md`.
- bamnlabs.dynv6.net apex claim: DONE by operator (resolves to 71.201.182.175); `relay` subdomain deferred (apex suffices for single-host edge).
- Bounded soak: PASS (Stage 6, operator-authorized) — `TestSoakBoundedTraffic` SOAK_SECS=300: 42,837 ok, 0 fail, avg ~56ms, goroutine growth +6; mid-run restart resumes same lease. Incidental C08 proof (cookie-POST without Origin 403s).
- Scaled pressure beyond 8 workers, cross-machine partition/TLS-SNI, public edge, provider OAuth: NOT EXECUTED/BLOCKED (operator-gated). Full matrix: `docs/qualification/CHAOS-BATCH.md`.

### 2026-11-03 Stage 6 funnel smoke + revoke fix (`05a3237` → `16ad2c1`)

- Funnel lab edge (direct relay on funnel backend port, no Caddy): FIXED + live-verified — enroll → attach → strict-discovery publish → full OAuth DCR/PKCE/token → `tools/list` + `tools/call` (`pong:ocliv-oauth-lab-1`) over `https://pop-os.tail8d285a.ts.net/r/E2CI3j6ZIqS1yVqpsMdYNw/mcp`; no-bearer/tampered 401s. Evidence: `docs/qualification/GATE3-PUBLIC-FUNNEL.md` addendum.
- Upstream revoke unreachable via path route (allowlist authorize/token/register only): FIXED — `/oauth/revoke` added to `mcpOAuthEndpoints` (`relay_mcp_ingress.go`) with parse + dispatch red→green regression tests; live: revoke → 200, revoked call → 401; relay restart preserved stable route. Full gates green (internal ×3 incl. one unattributed transient FAIL, integration 242s, race relay/agent/cli/mcp).
- `publish --auth fixture-anonymous` refusal, upstream-oauth-without-OAuth discovery failure: VERIFIED NON-ISSUE (correct fail-closed behavior, observed live).
- Gate 4 ChatGPT registration, funnel teardown decision, permanent ingress (dynv6/Caddy/router): BLOCKED/NOT VERIFIED (operator-gated).

### SAPRE baseline (`597af82`, live funnel lab)

- Publisher reconnect loop in `publish.log`: VERIFIED NON-ISSUE — 4 reconnects + generation-2 re-attach all coincide with the relay redeploy; stable since, route enforcing (401).
- Live edge latency (20-sample, no-bearer `tools/list`): public funnel med 252ms (80–426ms) vs relay-direct med 9ms (5–13ms). No anomaly; tail consistent with shared funnel transit. Operating envelope anchor, not an SLO.
- Whole-repo `go vet ./...` + `gofmt`: clean.
- Earlier single transient internal FAIL (1 of 5 full runs, unattributed): UNREPRODUCED — 4 consecutive 18/18 green runs since; carried as flake watch, not a defect.
- Live stack untouched by test runs (fixtures are repo-tracked, runtime state in /tmp only).
- `mcp doctor --name` unreachable-`FindByName` bug (prior audit): FIXED in current tree — `selectDoctorLeaseID` (`cli_mcp_publish.go:889`) resolves explicit → name → latest with fail-closed mismatch; regression tests `TestSelectDoctorLeaseIDOrder/AmbiguousName` green on `6114ba0`.
- Supply chain (SAPRE): VERIFIED — `go mod verify` clean, `govulncheck ./...` no vulnerabilities, 4 direct deps (websocket, yamux, x/term, modernc sqlite); no lockfile drift (`go.mod` pinned, `go.sum` present).
- README claim-vs-reality (SAPRE §6): VERIFIED — `mcp PORT` alias pins upstream-oauth via `mcpPortAliasArgs` (`cli_mcp.go:72`, regression green); five everyday commands listed first in `usage()`; token only via `DYNV6_TOKEN`/`--token-file`, never argv (`cli_setup.go:171` + `dynv6.go` redaction). No theater found in spot check.

### SAPRE security note — stale lab credential store

- `live/relay-data/ocliv.db` (Oct 31, stale lab run): holds 1 agent key + 1 enrollment code, mode 644 inside a 700 dir, gitignored, no process attached (`fuser` empty). Exposure: VERIFIED NON-ISSUE (700 parent, gitignored, codes long expired). Hygiene: file itself is not 0600 because `lockDownFiles` only runs on `store.Open` and nothing has opened it since Oct 31 — ACCEPTED RISK, left untouched. If this directory is ever copied elsewhere, re-lock or drop the DB first.

### SAPRE §7–§8 cross-domain checks (2026-11-03, live funnel lab)

- Readiness probe honesty (SAPRE §7): VERIFIED — `/health/live` + `/health/ready` on loopback-only 18080; ready evaluates `ReadyForSessions()` (`relay.go:76`: SQLite pool-conn PingContext(2s) + preAuth/throttle/MCP admission-key capacity). Live 200 on both. Genuine prerequisite probe, not process-alive theater; proves nothing about public reachability.
- MCP admission vs availability (SAPRE §8): VERIFIED — P1-10 throttle is pre-stream in `serveProxied` (`relay_public.go:384`), per-(trusted-edge-IP, lease), separate `MCPAdmissionRejects` counter; non-MCP traffic unaffected by construction. No contention tradeoff found.
- Dispatch-time generation fencing / P1-5 (SAPRE §3): FIXED in current tree — `serveProxied` recheck (`relay_public.go:436`) requires pointer identity + generation match via `admittedSessionCurrent` (`:365-369`), not mere liveness. Regressions `TestAdmittedSessionCurrent`, `TestDispatchReplacementBeforeCheckRejected`, `TestDispatchReplacementInCheckWriteWindowBindsStaleGeneration` in `relay_public_test.go`.
- Saturation behavior (SAPRE §5): VERIFIED predictable-rejection — live 130-rotating-spoof probe recorded 120x401 then 10x429 from one shared bucket (Task C above): abuse degrades to 429, unrelated leases unaffected by per-(source,lease) scoping. No unbounded accumulation observed.
- Route-ID secrecy (SAPRE §2): VERIFIED NON-ISSUE by design + live proof — route IDs are non-secret routing identifiers; knowledge of the URL buys nothing without the OAuth/visitor credential (live: no-bearer/tampered-bearer → 401, zero upstream execution). No secret material in route metadata.
- Audit-vs-availability (SAPRE §8): VERIFIED — `DB.Audit` (`store.go:309`) discards its Exec error (`_, _ =`), so a dead/full SQLite can lose a log row but can never convert a denial into an allow or crash the path; the 429/401 still returns. Observability degrades open, admission stays fail-closed. First-bottleneck hypothesis for future >8-worker load tests: one audit write per denied request (bounded since A2 by 90-day prune).
- Live edge re-verified 2026-11-03 (SAPRE §10): public funnel route still 401s a no-bearer `tools/list` after all ledger work; no drift, no exposure introduced by read-only analysis.
- Publish-mode refusals P0-1/P0-2 (SAPRE §2/§6): VERIFIED in code + tests — `--stdio` unconditionally rejected (`cli_mcp_publish.go:293`, stdio bridge can't enforce auth), `--auth fixture-anonymous` rejected for publish (`:300`, local-only `mcp serve` only), both before any remote mutation. Regressions in `cli_mcp_publish_test.go:183+` (auth×stdio matrix + invalid combos `:202-204`).
- Gate standing (SAPRE §10): full `go test ./internal/...` 18/18 green, `go test -race ./internal/cli/` clean, and full integration suite green (243s) — all WITH the post-gate `--help` fix in tree (`cli_relay.go` + new test file are the only Go drift from `6114ba0`). Govulncheck stands (no dependency change).
- Replay protection P1-07 (SAPRE §2/§3): VERIFIED mechanism — `nonceCache.consume` (`relay_nonce.go:57`) delete-on-read under mutex = single-use; missing/already-consumed nonce reports false. Restart-bounded by 5-min skew (chaos E5 VERIFIED NON-ISSUE).
- Graceful shutdown (SAPRE §7): VERIFIED — `signal.NotifyContext` (Interrupt+SIGTERM) owns relay shutdown (`cli_relay.go:363`), `httpSrv.Shutdown` + `healthSrv.Shutdown` (`:381-382`), exits `ExitCleanShutdown` (`:388`). No abrupt-drop path in the serve command.

### SAPRE production readiness gate (2026-11-03, scope: lab + temporary funnel edge)

| # | Gate | Disposition | Basis |
|---|------|-------------|-------|
| 1 | Architectural integrity | VERIFIED | Decomposition preserved (leases/sessions/registry/ingress/authority/access/http); ownership contracts explicit; zero Go drift from gated HEAD; no god objects added (this pass adds no code). |
| 2 | Security | PARTIAL | Lab + funnel-lab verified: 401s, generation fencing, publish refusals, revocation, single-use nonces, secret hygiene. Permanent ingress + provider OAuth BLOCKED (operator). |
| 3 | Concurrency correctness | VERIFIED at tested scope | P1-5 fencing + regressions, C3 16-way, race suites green; >8-worker pressure NOT VERIFIED. |
| 4 | Performance | PARTIAL | Envelope measured, no SLO defined: soak avg ~56ms, funnel med 252ms / relay 9ms (20-sample, tail 80–426ms transit). |
| 5 | Capacity and saturation | PARTIAL | 8-worker soak + predictable 429 under abuse; >8 workers UNTESTED. |
| 6 | Integration completeness | PARTIAL | Composed funnel smoke PASS (OAuth DCR→tools/call→revoke); ChatGPT registration BLOCKED (operator workspace). |
| 7 | Operational readiness | PARTIAL | Health/readiness/shutdown/backup-code verified; clean-host install, restore drill, permanent ingress NOT VERIFIED (operator-gated). |
| 8 | Critical invariant preservation | VERIFIED | All recorded gates stand; tree shows docs-only drift. |
| 9 | Recovery and convergence | VERIFIED at tested scope | Stage 6 matrix (restart/resume/revoke/restore-code); compound failures untested. |
| 10 | Regression stability | VERIFIED with watch | Gates green; one unattributed transient FAIL carried as flake watch, 4+ consecutive greens since. |

**Overall: NOT READY for production; CONDITIONALLY READY for lab + temporary-funnel operation.** No unresolved critical defect is locally actionable — every remaining gap is operator-gated (dynv6 token/Caddy install/router, ChatGPT registration, funnel teardown decision) or explicitly out-of-scope scale testing. No code changes were needed or made in this pass; §9 remediation outcome = nothing to fix, all findings FIXED-in-tree or VERIFIED.

### Post-gate fix — `issue-enroll --help` minted a code (P3, self-found 2026-11-03)

- Defect: `cmdIssueEnroll` ignored `-h`/`--help`, opened/created the store, and printed a live enrollment code. Found by running `ocliv relay issue-enroll --help` against the repo cwd: created gitignored `./ocliv-relay-data/ocliv.db` + printed code. No live store touched (live relay uses `/tmp/ocliv-funnel-lab/data`); stray db removed, so the exposed code is unredeemable.
- Fix: `-h`/`--help` prints usage to stderr and exits `ExitCLIValidation` before store open (`cli_relay.go:477-484`). No other relay leaf changed (none has a help convention; widening that is out of scope).
- Proof: new `cli_relay_enroll_test.go` asserts non-zero exit + no db created for both flags — FAILs on unfixed code (exit 0), PASSes fixed. `gofmt`/`go vet` clean, full `internal/cli` package green; then full `go test ./internal/...` re-run green (18/18) WITH the fix in tree, `gofmt -l` + `git diff --check` clean. Uncommitted, like the rest of this pass.
- CLI surface completeness (SAPRE §6): VERIFIED — `ocliv mcp` dispatches expose/manage/publish/serve/doctor/list/unpublish + numeric-port alias (`cli_mcp.go:36-67`, alias `mcpPortAliasArgs :69`), every advertised subcommand maps to a real handler; expose-vs-publish is the local-only-vs-public security boundary, not a dead path. M12 closed toolset (`manageTools :34`: status/share/revoke only, no exec).
