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
go test -count=1 -timeout 420s ./tests/integration/
go test -race ./internal/relay/ ./internal/agent/ ./internal/config/ ./internal/cli/ ./internal/mcp/
```

No CI config or Makefile exists in-tree; the commands above are the
gates. Run the full integration suite once after relay/transport
changes, not after every edit. One focused test run per change; never
re-run an unchanged check to collect evidence.

The integration suite takes ~282s end-to-end (2026-11-12 measurement;
it has grown as regression coverage was added). The whole-suite timeout
is therefore 420s. That increase is CI headroom for a longer suite, NOT
a performance result and not an excuse for slower tests: individual
tests still carry their own internal deadlines (agent attach waits,
visitor deadline loops, agent reconnect windows), and a per-test
regression toward that 282s envelope is a defect, not a baseline.

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
- Metis public integration (HTTP+OAuth upstream, publish/revoke through public route): PARTIALLY VERIFIED — the public path route against a REAL Metis MCP server is now covered by a committed test (`tests/integration/mcp_metis_composed_test.go`, skip-gated on `OCLIV_METIS_BIN`): tools/list through the public route returns Metis's 15 `metis_*` tools, a wrong-audience bearer and a missing bearer are both refused with 401 (body asserted to be Metis's own rejection, not the relay's), and MCP-Protocol-Version `2025-06-18` is rejected with 400. The two loopback expose legs remain Metis-owned and pass against this build (`TestOclivLoopbackExposeServesMetisTools`, `TestOclivLoopbackRemoteMessageChain`). A reproducible runbook and orchestration script are committed (`tests/staging/composed/run-composed.sh`, `docs/COMPOSED-DEMO.md`); the Locus inference leg, public DNS/ACME/Caddy, and a production IdP stay NOT VERIFIED (operator-gated). `--stdio` prohibition preserved.
- Gate 4 ChatGPT registration, clean-host install, permanent ingress, soak: NOT VERIFIED (operator-gated, unchanged).

### 2026-11-03 product-rereview remediation round (`abdda2e` → `804f21a`)

- P0-A wildcard DNS proof + ACTION_REQUIRED + persist-only-on-success (`cli_setup.go`): FIXED — fresh `<label>.t.<domain>` verification, manual-record instruction on miss, exit codes distinguish completed/action-required/failed, relay URL persists only after gates pass.
- P0-B dynv6 token sanitization (`setup/dynv6.go`): FIXED — failing-first transport-error regression, token never in errors/output/logs, categories preserved.
- P0-C preserve deployments (`setup/bootstrap.go`): FIXED — unmanaged-Caddy refusal, staged install with marker, rollback on later-step failure, injected-failure tests.
- P1-D backoff reset (`agent/agent.go`): FIXED — reset after healthy session, escalation preserved, 2x stability runs.
- P1-E dynamic DNS refresh (`setup/refresh.go`, `--refresh-dns`): FIXED — change-only updates, no relay restart, change/no-change CLI tests.
- P1-F named status states (`cli_status.go`, `doctor` already verified/unverified): FIXED — RELAY DISCONNECTED / AUTH REQUIRED / RECONNECTING / ROUTE OFFLINE with Next actions in human + JSON; attachment never claimed as public reachability.
- P1-G durability (`config/leases.go`): FIXED the one found gap — crashed-save `.tmp-*` sweep with failing-first regression; rest of the gate list (restart, revoke races, restore rollback, leak bounds) VERIFIED NON-ISSUE against existing suites (`lifecycle`, `revoke`, `relay_backup`, `exchange_adversarial`).
- P2-H `ocliv mcp PORT` alias (`cli_mcp.go`): FIXED — thin rewrite to existing publish. The bare alias now DEFAULTS to the relay-side managed mode (`--auth ocliv-managed`: one-command publish for a local MCP server with no native OAuth, operator-authorized clients through the per-transaction consent flow); an EXPLICIT `--auth` (any value, including upstream-oauth passthrough) passes through untouched. Parser-level regressions pin both directions. (Supersedes the earlier "pinned upstream-oauth" wording above and the SAPRE §6 claim-vs-reality line, which describe pre-2026-11-12 behavior.)
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

### 2026-11-12 managed-authorization remediation + external qualification

Scope: one focused remediation pass over the five review findings, then an
external qualification against an isolated staging stack. The production Pi
relay was NOT deployed to and NOT restarted.

Dispositions (one per material finding; evidence in
`docs/qualification/MANAGED-AUTHZ-RESULTS-2026-11-12.md`):

- **Goal 1 — consent page, no URL credential: FIXED.** The reusable
  `pairing_code` GET parameter is gone. The authorize endpoint renders a
  route-scoped consent page; the credential is submitted by POST against a
  one-time, expiring, transaction-bound challenge (`authz_consent`), and is
  single-use. Live: no credential in the authorize URL, none in the page
  (field name only), challenge replay → 400, consumed credential → 403, and
  approval alone yields no code. `TestConsentPageNotURLCredential`,
  `TestActiveGrantNeedsNoOclivParams`, `TestActiveGrantAloneNeverYieldsACode`.
- **Goal 1 — "ordinary OAuth client needs no Ocliv-specific authorization
  parameters": FIXED.** The authorize request carries only standard OAuth
  parameters (client_id, redirect_uri, response_type, code_challenge,
  code_challenge_method, state, resource); the credential travels on the
  consent POST, never as an authorization parameter. Verified live (G4) and
  by unit test.
- **Goal 2 — client-level revocation: FIXED.** `AuthorizeClaims` refuses a
  token whose client is revoked and `ServeToken` rechecks before issuing.
  Live: a revoked client's existing token → 401, a revoked client cannot
  redeem a never-redeemed code → 400 "client is not approved for this
  route", other clients unaffected → 200. Failing-first tests
  `TestRevokedClientCannotUseExistingToken`,
  `TestRevokedClientCannotRedeemCode`.
- **Goal 3 — JTI: FIXED.** Every newly issued managed token carries a jti and
  a token without one is refused at managed admission. Revocation stays
  scoped to (issuer, tenant, route). Live: jti present on every token,
  RFC 7009 revoke → 200 then the token → 401 on the next request, an
  unrelated client's token still 200, an invalid token → 200 (RFC 7009
  §2.2). Tests `TestMissingJTITokenRejected`,
  `TestTokenRevocationScopedToTenantAndRoute`.
- **Goal 4 — runbook ordering: FIXED.**
  `docs/qualification/MANAGED-AUTHZ-QUALIFICATION.md` §3.8 (publisher
  restart) now runs BEFORE §3.9 (key rotation), and §3.9's token must be
  minted fresh after §3.8; every gate states its required starting state.
  Verified live: the route id survives the publisher restart, the
  pre-restart token still works, and the rotation refuses the old token
  immediately with no relay restart.
- **Goal 5 — resource parameter: FIXED.** The canonical resource is required
  on authorize and token and must equal the route exactly; the token
  audience is bound to it. Live: foreign resource → 400 `invalid_target` on
  both endpoints, missing resource → 400, `aud` = the route URL.
- **F1 — `mcp publish --auth ocliv-managed` sent the CLI auth name as the
  ingress profile: FIXED** (red: live `400 unknown ingress profile`).
- **F2 — a managed publication was left unverified by the lease reclaim and
  the route rebind, so a publisher restart left the route 404: FIXED**
  (red: `TestManagedAuthzReclaimKeepsRouteServing` 404 → green; live P3/P4).
- **F3 — the SQLStore test schema lagged the store schema: FIXED.**
- **F4 — `TestMCPPortAliasArgs` demanded that publish accept
  `fixture-anonymous`, contradicting the standing invariant: FIXED** (the
  refusal is now the proof that an explicit `--auth` is preserved).
- **Cross-key named-host reclaim (P0-2): FIXED.** Automatic reclaim is
  reserved for the SAME agent key; a different key in the same tenant is
  refused (the reclaim would otherwise hand one publisher another
  publisher's route and its operator approvals).
- **F6 — unpublishing a route left the operator's approvals ACTIVE: FIXED.**
  The external qualification found 22 active grants and 27 client
  registrations surviving a removed route: an approval is authority over a
  route that no longer exists, and the runbook's teardown oracle requires
  the grant row to be gone or revoked. `RevokeGrantsForRoute(tenant, route)`
  now retires the route's approvals with the delete, scoped to tenant+route
  (another route's approvals are untouched). Red-before:
  `TestUnpublishRetiresRouteApprovals` (*status="active", want "revoked"*) →
  green; live: active `1→0`, revoked `0→1`, and the route then answered 404.
- **External qualification teardown: VERIFIED.** The route was unpublished
  (404), the Pi's `ocliv-staging-*` user units were stopped and disabled
  (0 remaining), the pop-os staging relay/health/edge listeners were gone
  (nothing on 18085/18086/18443) and the public edge refused connections
  (`000`). Production stayed untouched throughout: `ocliv-relay` active with
  the 2026-11-11 binary (sha256 `0d47481f…`) and health 200/200.
- **Upstream-execution oracle: VERIFIED.** The runbook demands the
  upstream's own access log, not just the status, as the denial oracle. The
  harmless upstream was instrumented to append one line per MCP method it
  receives: an authorized call moved the counter +1, while the no-bearer,
  tampered-bearer and revoked-client denials each moved it +0.
- **Runbook rows 15 and 17 exercised live.** 15: publishing the same name
  with `--auth upstream-oauth` → 409 "publication exists with profile
  managed-oauth", exit 4, route id unchanged. 17: a second key in the SAME
  tenant was refused the named host with 7 audited `lease_reclaim`/`denied`
  rows, and the original lease kept serving.
- **Cross-key conflict retries instead of failing fast: ACCEPTED RISK
  (operator-facing wart).** The refusal is correct and audited, but the
  relay reports it with close code 4409, which the agent treats as a
  retryable conflict (by design: 4409 also covers a concurrent allocation
  race), so the operator sees an endless "reconnecting" loop. Making it
  terminal needs a dedicated error code, because the ownership conflicts
  and the allocation race share the closed `conflict` code. The security
  property itself is verified; only the operator-facing UX is affected.
- **Verification flakiness: ACCEPTED RISK (watch).** `TestNoisyFailingChild`
  (internal/mcp) failed once under `-race` and passed 3/3 on re-run; it is a
  post-crash timing assertion, not a defect observed in the code.
- **Integration gate timeout: FIXED.** The documented `-timeout 280s` failed
  on a healthy 331 s suite; the cap is now 420 s.
- **ChatGPT registration, permanent public ingress, ACME/Caddy edge,
  production deployment of managed OAuth: NOT VERIFIED / operator-gated.**
  The managed flow needs an operator-mediated consent and a single-use
  credential per authorization, so an unattended client cannot complete it.
- **External qualification: PASSED, 41/41 checks** against the isolated
  staging stack (relay on loopback + self-signed tailnet edge + harmless
  stdio upstream + staging DB). Production isolation proven: the Pi relay
  still runs the 2026-11-11 binary (sha256 `0d47481f…`), health 200/200, and
  `/var/lib/ocliv` is root-owned and unreadable to the staging operator.
  Rollback is demonstrated (stop the staging units, remove the staging dirs).

### 2026-11-11 post-qualification hardening round (`bcaebd8` → working tree)

Scope: production relay on PiInDaSky (.170) at `bamnlabs.dynv6.net` (Caddy TLS edge, Pi-hole keeps :80, Tailscale, nft allowlist). Two confirmed findings from the tenant-isolation qualification, fixed with red-before/green-after regressions, then deployed.

- **F1 — `mcp unpublish --publication-id` misreported a 404 as success (P2, reporting).** `cli_mcp_publish.go` treated HTTP 200 *and* 404 as "removed" and printed `✓ MCP publication removed` with exit 0. A foreign tenant's denied DELETE returns 404 (`relay_mgmt_routes.go`: `RowsAffected()==0`), so a cross-tenant denial looked like a successful deletion. Reproduced live: the `isolation-probe` key printed "removed" (exit 0) while the `piindasky` publication stayed intact and the route kept 401ing. FIXED — the `--publication-id` branch now switches on status: 200 → `✓ ... removed`, exit `ExitOK`; 404 → `mcp unpublish: publication <id> not found or not owned by this key (the relay does not disclose ownership)`, exit `ExitAuth`; anything else → the previous status/detail error, exit `ExitInternal`. The relay's non-disclosing 404 is preserved. Red-before: `TestMCPUnpublishPublicationIDNotFoundIsNonzero` FAILs on the unfixed tree (`unpublish unknown route exit=0, want 4`); green-after: PASS. Also asserts an owned 200 delete exits 0 and a repeat delete exits 4.
- **F2 — denied management-plane deletes left no audit trail (P2, observability).** Only the successful delete was audited (`relay_mgmt_routes.go`); the 404 path returned silently, so a foreign-key delete attempt was unattributable. FIXED — `schemaV7` adds `audit_events.key_id TEXT NOT NULL DEFAULT ''` (`currentSchema` 6→7, forward-only; legacy rows keep the empty default), new `DB.AuditKey(actor, tenant, keyID, leaseID, category, result, detail)`, and the DELETE handler now audits `ok` / `denied` / `error` with the authenticated key identifier. Denied detail is `route <id> not found or not owned by this key` — names the target, leaks no ownership, carries no credentials/tokens/codes. Red-before: `TestKeyPublicationDeleteAudit` FAILs (`cross-key denied audit rows=0 want 1`); green-after: PASS (cross-tenant denied → 404 + 1 denied row + zero mutation; owner delete → 200 + 1 ok row + route gone; repeat delete → 404 + 1 denied row).
- **Schema V7 migration.** `ALTER TABLE audit_events ADD COLUMN key_id ...`; applied automatically on relay start; `TestOpenMigratesAuditEventsToV7` proves a pre-V7 row survives with the empty default and new key-scoped rows record the key. `TestOpenIdempotentAndDowngradeRefused` re-verified at `currentSchema=7`.
- **Gates.** `go build ./...`, `go vet ./...`, `gofmt -l internal/ tests/` clean; `go test ./internal/... -count=1` 18/18 green; full integration suite green (259s).
- **Deployment (PiInDaSky .170).** Only the `ocliv` binary swapped (`/usr/local/bin/ocliv`, sha256 `0d47481f2e2b7cbff34df57a713f0e39849be92cd85deabd5f256be07a00d0b1`, arm64 build of this tree). Caddy, Pi-hole, Tailscale, firewall, and the relay config/data layout untouched. Script: `~/ocliv-relay-deploy/deploy-relay-hardening.sh`.
- **Post-deploy evidence.** Health `live:200 ready:200`; all units active; `schema_version=7`; `audit_events` carries `key_id`; a live denied delete (`zzz-not-a-route`) produced `time=2026-11-11T22:52:26Z actor=agent tenant_id=tenant-enr-1794417320397708243 key_id=key-83eeb2d84ab043b2 category=mcp-route-delete result=denied`; the live publication still served the full external OAuth chain (`pong:ocliv-oauth-lab-1`) with 401 on no/tampered bearer.
- **Rollback dependency (V7) — read before any rollback.** The pre-hardening binary refuses a V7 database (`case v > currentSchema: fail closed`), so a binary-only rollback leaves the relay DOWN. Rollback MUST restore both artifacts together:
  `sudo cp -a /usr/local/bin/ocliv.bak-20261111-165127 /usr/local/bin/ocliv` **and** `sudo cp -a /var/lib/ocliv/ocliv.db.bak-20261111-165127 /var/lib/ocliv/ocliv.db`, then `sudo systemctl restart ocliv-relay`. Do not attempt binary-only rollback.
- **Artifact retirement (qualification cleanup).** The public OAuth lab fixture and its publisher were stopped/disabled on bamn's user manager and the publication `rdZp9IR6xkQKtpu_nLtUEw` unpublished (verified: units `inactive`/`disabled`, `mcp list` empty, route 404, relay 200/200, Caddy/SSH/Tailscale/Pi-hole/DNS/firewall unchanged). Source, units, env, resource file and deploy scripts preserved under `~/ocliv-relay-deploy/fixture-preserved/`. The `isolation-probe` key (`key-47a7f03865a2df0e`) was revoked (403 after). No enrollment codes/tokens in persistent artifacts (codes are hashed verifiers at rest).
- **Deferred, not dismissed — local MCP servers without native OAuth.** Supporting local MCP servers (e.g. `/opt/ir-controller`) is a core architectural requirement, not an edge case. Strict upstream discovery stays; the revised design (shared relay-side authorization module vs embedded publisher-side vs external-IdP passthrough; free, persistent, one-command publish) is tracked in `docs/ADR-local-mcp-auth.md` and is explicitly NOT implemented.

### 2026-11-12 managed-auth security-correction round (`abbbe34` → working tree)

Scope: the 2026-11-11 managed-auth rereview of the relay-side Authorization
Server for local MCP servers with no native OAuth (`internal/authz/`,
managed publish/approval CLI, managed-route ingress). One bounded
security-correction pass: no new identity providers, no gateway
aggregation, no per-tool policy, no deployment machinery.

**Committed vs uncommitted.** `abbbe34` is the committed baseline. The six
pre-existing modified tracked files from the prior pass (`cli_authz_test.go`,
`cli_mcp_publish.go`, `relay_leases.go`, `relay_mcp_ingress.go`,
`relay_mgmt_routes.go`, `mcp_managed_authz_test.go` — ingress-profile naming
and managed `verified_at` preservation) plus ALL of this round's changes are
UNCOMMITTED in the working tree; nothing below is in a commit. This pass made
no code commits of its own. A concurrent second agent session was editing the
same tree mid-remediation; it was reconciled to ONE design (its `ConsentedAt`
latch was discarded because a once-consented grant would issue codes forever,
re-opening P0-1) with snapshots preserved outside the repo; final-state proof:
`grep -rn 'ConsentedAt\|RecordConsent' internal/ tests/` returns empty.

- **P0-1 — an approved client ID was sufficient authorization.** FIXED
  (uncommitted). `ServeAuthorize` (`internal/authz/handlers.go`) no longer has
  an ACTIVE-grant branch: operator approval (ACTIVE) and transaction
  authorization are separated, every authorization renders the consent page,
  and only a completed consent — the operator's single-use pairing credential
  against a one-time, transaction-bound challenge — calls `issueCode`.
  Existing tokens keep working on the durable grant. Red-before/green-after:
  `TestActiveGrantAloneNeverYieldsACode`; `TestActiveGrantNeedsNoOclivParams`
  re-scored to the new semantics (ACTIVE grant → consent page, never a silent
  code); integration `TestManagedAuthzConsentPageFlow` (standard params alone
  → 200 consent page, no Location; fresh credential → code).
- **P0-2 — named-lease reclaim crossed publisher-key ownership.** FIXED
  (uncommitted). The reclaim transaction in `insertLease`
  (`internal/relay/relay_leases.go`) now reads `agent_key_id` and refuses a
  different key in the same tenant with `CodeConflict` plus one
  `lease_reclaim/denied` audit row (written after rollback — the store pool is
  single-connection). Automatic reclaim is reserved for the SAME key
  (publisher restart); a cross-key takeover requires an explicit, audited
  ownership-transfer operation, which does NOT exist yet. Regression:
  `TestNamedReclaimCrossKeyRefused` (two distinct enrolled keys in one tenant:
  no attach, original lease keeps serving, denied audit row);
  `TestNamedReclaimCutsOverTraffic` re-scoped from the old cross-key success
  case to same-key reclaim.
- **Management-plane cross-key boundary.** VERIFIED NON-ISSUE + pinned.
  `agentLeaseAuth` (`relay_mgmt.go`) signature-verifies the caller, binds the
  signing key to the lease, and single-use-nonces mutations;
  `serveMCPRouteMutation` (`relay_mgmt_routes.go`) re-checks
  `rowTenant`/`rowKey` before any rebind. New
  `TestMgmtCrossKeySameTenantRefused` proves a real second key in the same
  tenant gets 403 on revoke/rotate/close/share and route creation, the
  owner's lease is unaffected, and the denials are audited. This is a DISTINCT
  boundary from P0-2 (durable lease lifecycle vs authenticated management
  plane) and is now covered separately.
- **Consent flow (P1 cluster).** FIXED (uncommitted): the consent form's
  action is the canonical route-scoped AS URL (`IssuerURL + "/consent"`, not
  the server-root path route dispatch never served) —
  `TestManagedAuthzConsentFormActionIsRouteScoped` parses the action from the
  rendered HTML and completes the transaction by POSTing to THAT URL
  (browser-style, not a manually constructed substitute). `ServeConsent`
  rebinds the full transaction (tenant, route, client, redirect, PKCE
  challenge, state, resource) and records consent ok/denied audit rows.
  Approval + credential issuance is one atomic store operation
  (`ApproveGrantWithPairingSecret`; a revoked grant is never resurrected).
  Pairing credentials are single-use AND expiring (schemaV11;
  `ConsumePairingSecret` burns atomically inside a transaction). `issueCode`
  composes the redirect through `url.Values` — pre-existing query parameters
  survive, and RFC 9207 `iss` is included.
- **PKCE grammar (P1).** FIXED (uncommitted): RFC 7636 §4.1 verifier
  syntax/length (43–128 unreserved characters) and §4.2 S256 challenge
  encoding are enforced at both authorize and token; the old one-character
  test verifiers were normalized, not the enforcement weakened.
- **Bounded authorization state (P1).** FIXED (uncommitted): per-route
  registration (200) and pending-consent (100) quotas (429 past the caps),
  per-tenant+endpoint rate limiting on the public OAuth endpoints
  (`relay_authz.go`), and `PruneAuthitExpired` in `reconcileBoot`
  (revocations retained 30 days, far beyond token TTL, so pruning can never
  resurrect access).
- **P2 — one-command managed publishing.** FIXED (uncommitted): the bare
  `ocliv mcp PORT` alias defaults to `--auth ocliv-managed`; an explicit
  `--auth` (any value) passes through untouched.
- **Runbook.** `docs/qualification/MANAGED-AUTHZ-QUALIFICATION.md`
  (uncommitted) corrected: consent mechanics replace the removed
  `pairing_code` GET flow; the token exchange supplies the required
  `resource` and a conforming verifier; negative paths N8–N11 added
  (approval-alone, replayed credential, expired credential, short verifier);
  the owner-key reclaim boundary is documented; and the absence of refresh
  tokens is recorded as a known limit (1-hour access tokens; a new
  authorization needs a fresh credential).

**Test evidence (this tree; the remediated code is COMMITTED at `17f2100`).** `go build
./...`, `go vet ./...`, `gofmt -l internal/ tests/` clean;
`go test ./internal/... -count=1` green (all packages); full integration
suite green (282s; gate timeout raised to 420s); `go test -race` green on
relay/agent/config/cli/mcp. New regressions live in
`internal/authz/boundary_test.go` plus
`tests/integration/{mcp_managed_authz,tunnel}_test.go`.

**External managed-auth qualification: PASSED (41/41 checks, plus the
upstream-execution oracle and rows 15/17 exercised live).** The condition
stated below has been met: an isolated staging run on the existing Pi
infrastructure, a separate staging database, and a harmless upstream MCP
server. Relay on pop-os bound to loopback only (127.0.0.1:18085/18086), a
self-signed TLS edge on the tailnet IP 100.77.54.48:18443, the staging DB in
its own 0700 directory outside the production tree, the publisher + harmless
stdio upstream on the Pi, and the operator CLI against the staging DB only.
Production isolation is proven, not asserted: the Pi relay still runs the
2026-11-11 binary (sha256 `0d47481f…`), health 200/200, and `/var/lib/ocliv`
is root-owned and unreadable to the staging operator.
Evidence: `docs/qualification/MANAGED-AUTHZ-RESULTS-2026-11-12.md`; the
runbook's verdict table is filled (13 PASS, 2 PARTIAL, 2 NOT VERIFIED live —
the expired-credential case, the missing-jti live forgery, and the quota
caps, each covered by unit tests instead).
The upstream-execution oracle the runbook demands: the harmless upstream
writes one line per MCP method it receives; an authorized call moved the
counter +1, while the no-bearer, tampered-bearer and revoked-client denials
each moved it +0.

**Known limitation (not a defect in the five items):** a cross-key named-host
conflict is refused, audited and leaves the original lease serving, but the
relay reports it with close code 4409, which the agent treats as a RETRYABLE
conflict (by design: 4409 also covers a concurrent allocation race). The
operator therefore sees an endless "reconnecting" loop instead of a terminal
error. Making it terminal needs a dedicated error code, because the
ownership conflicts and the allocation race currently share the closed
`conflict` code. Recorded as an operator-facing wart; the security property
itself is verified.

**Production deployment: NOT PERFORMED.** The working relay on PiInDaSky
(.170) was not touched: no binary swap, no schemaV11 migration of the
production database, no service changes.

### 2026-11-13 permanent-edge correction round (working tree, uncommitted)

Scope: two bounded corrections — (1) the false "443-only because no
challenge override appears in `caddy adapt`" claim, and (2) the
incomplete clean-host bootstrap. The production Pi relay was NOT
touched: no deployment, no binary swap, no database change.

- **ACME claim correction: FIXED (uncommitted).** The earlier
  "issuance uses TLS-ALPN-01 because the issuers carry no challenge
  override" conclusion was not established: Caddy enables HTTP-01 and
  TLS-ALPN-01 by default, so the absence of a challenge override
  proves nothing and the issuer still attempts HTTP-01 over port 80
  first. `packaging/caddy/Caddyfile.single-host` now carries an
  explicit `issuer acme { email {$OCLIV_ACME_EMAIL}
  disable_http_challenge }` block, keeping the contact email and the
  trusted-edge proxy contract; the generic tunnel edge's certificate
  policy is untouched. Red-before/green-after:
  `TestSingleHostTemplatePinsTLSALPNChallenge` fails on the old
  template and passes on the fixed one. `scripts/verify-single-host-edge.sh`
  now asserts the explicit disable (issuer module+email, and
  `challenges.http.disabled: true` on every issuer) instead of an
  absence, and runs two negative controls: adapting the same file with
  `disable_http_challenge` REMOVED shows the issuer NOT proven
  :80-free (the retired absence-check passed on both configs — it was
  vacuous), and adapting with the global `http_port` trap shows the
  disable surviving while an inert alternate_port plus an app-level
  `http_port` appear (the trap is inert-but-misleading on the pinned
  edge; on any unpinned edge it flips the issuer to HTTP-01 on an
  alternate port). Live evidence: real `caddy:2-alpine` `caddy
  validate` + `caddy adapt` in this pass — one server on `:443`, no
  `http_port`, issuer `challenges.http.disabled: true`, loopback
  upstream. Docs reconciled: `docs/SETUP.md`, `docs/MCP-HOSTING.md`,
  `docs/qualification/PERMANENT-EDGE-2026-11-13.md` (the wrong row now
  carries an explicit correction paragraph). `packaging/caddy/Caddyfile.single-host.local`
  (loopback smoke variant) passed its one read-only `caddy validate`
  today through the normal in-band guard; it stays uncommitted
  (optional fixture).
- **Clean-host bootstrap completion: FIXED (uncommitted).**
  `ocliv setup --auto` previously installed only the Caddyfile and the
  unit, leaving a fresh host without the service account, binary,
  launcher, environment file, or data directory the unit requires —
  the relay could not start. `PlanBootstrap` now plans the complete
  set in prerequisite order (service account → binary → launcher →
  data dir → env → Caddyfile → Caddy activation → unit → relay start
  → enrollment; non-root prints all ten manual commands), `internal/setup`
  gained the executors (`EnsureServiceAccount` — idempotent, never
  removes; `EnsureDataDir`/`RollbackDataDir` — existing state never
  removed; `InstallBinaryTo`/`RollbackBinary` — first-candidate
  rollback; `InstallEnvTo` — 0600 + marker + unmanaged refusal;
  `InstallLauncherTo` — 0755, shebang on line 1, embedded source via
  `packaging/systemd.RelayLauncher()`; `ActivateAndReloadCaddy` —
  enable/start + reload; rollback-only `ReloadCaddy` that never starts
  a stopped Caddy), and `runSetupBootstrap` rolls the binary and data
  dir back beside the managed files. Unmanaged destinations are still
  refused, not overwritten. Failing-first tests:
  `internal/setup/bootstrap_cleanhost_test.go` (11 tests: plan
  completeness/order, non-root manual set, account idempotence +
  loud-failure, data-dir create/keep/rollback, binary
  first-candidate rollback + fresh-install removal, env 0600+marker+
  unmanaged refusal, launcher shebang/mark/perms) — red on the
  pre-fix tree, green after.
- **Gates (this tree).** `go build ./...`, `go vet ./...`,
  `gofmt -l internal/ tests/` clean; `go test ./internal/... -count=1`
  green (all packages); `go test ./packaging/... -count=1` green;
  full integration suite run once (recorded when it completes).
- **NOT VERIFIED / operator-gated (unchanged by this pass).** Live
  root execution of any bootstrap executor, real ACME issuance on the
  permanent edge, public reachability of any host's 443, the
  acceptance target (an ordinary public HTTPS MCP round trip with no
  Tailscale), ChatGPT registration, permanent ingress. `tailscale
  funnel reset` needs the operator's password (no passwordless sudo
  on this box); the single stale entry (`pop-os.tail8d285a.ts.net` →
  127.0.0.1:18082, nothing listening) was re-confirmed read-only
  today and left for the operator to remove with
  `sudo tailscale funnel reset`. The Pi relay (`.170`) stays
  offline and untouched; `10.9.66.193` was NOT commandeered.

### 2026-11-14 source-review remediation (authorization boundary + bootstrap atomicity)

Scope: the pasted review (`pasted-text-1.txt`, phases 1–5) implemented on
`master` (base `e5f56b9`), failing-first, smallest boundary-preserving
fixes, with Phases 1–4 completed earlier the same day. All gates run on
the final tree.

- **P1 — token-revocation route binding (`internal/authz/handlers.go` `ServeRevoke`): FIXED.**
  Revocation is now fenced to (issuer, audience/tenant, route): a token
  whose issuer/audience/tenant/route does not match the revocation target
  gets RFC 7009 §2.2's 200-without-effect and makes NO durable write, so
  a cross-route SQL-poisoning revocation cannot disable another route's
  token. Red-before: `internal/authz/cross_route_security_test.go`
  (foreign-token revocation persisted `revoked=true`; replay accepted)
  FAIL on the unfixed handler; green after.
- **P1 — client-registration ownership and code redemption scoping: FIXED.**
  `GetClient`/`ListClients` select `tenant_id, route_id`;
  `CreateGrant` and `ApproveGrantWithPairingSecret` refuse
  cross-route/unknown/unbound clients; `ConsumeCode` is scope-aware and
  atomic (the tenant/route fence executes inside the SQL transaction
  before consumption, closing the check-then-act race); `MemStore` and
  the `Store` interface carry the same contract; `AuthorizeClaims` fails
  closed on a client whose tenant/route does not match the token's.
  ServeAuthorize/ServeConsent/serveCodeGrant/serveRefreshGrant resolve
  clients through the route-scoped helper. Red-before:
  `internal/authz/client_code_scope_test.go` (7 tests, incl.
  cross-route negative controls) FAIL on the unfixed tree; green after.
  Numerous pre-existing fixtures updated to register clients with
  matching Tenant/Route (the fixtures predated ownership enforcement).
- **P2 — reserved upstream identity headers: FIXED.**
  `SanitizeVisitorHeaders` (`internal/proxy/proxy.go`) now strips
  `x-ocliv-upstream-sub` and `x-ocliv-route` from visitor traffic;
  `serveProxied` (`internal/relay/relay_public.go`) injects
  `X-Ocliv-Upstream-Sub` and `X-Ocliv-Route` into the upstream-bound
  head AFTER sanitization, and the managed path only removes the
  visitor's `Authorization` before delegating. A visitor-spoofed
  identity header can no longer reach the upstream. Wire-level
  boundary tests in `internal/relay/relay_mcp_header_boundary_test.go`,
  red-before/green-after.
- **P2 — bounded OAuth request parsing and metadata: FIXED.**
  `ServeRegister` caps the body (`MaxRegisterBody`, `MaxBytesReader`),
  decodes with `json.Decoder` plus a second decode that rejects trailing
  bytes, and enforces per-field limits (client name ≤256 chars, redirect
  URI list ≤32 entries/≤2048 chars each). `ServeConsent`/`ServeToken`/
  `ServeRevoke` wrap form parsing in `MaxBytesReader(MaxFormBody)`.
  Red-before: `internal/authz/body_bounds_test.go` (oversize +
  malformed-input rejection) FAIL on the unfixed tree; green after.
- **P2 — bootstrap atomic replacement (`internal/setup/bootstrap.go`): FIXED.**
  `InstallBinaryTo` stages the candidate on the destination filesystem
  as `<dst>.ocliv-staged`, validates it at the publish boundary
  (`validateStagedBinary`, an indirection for failure injection), and
  atomically renames it into place — an interrupted write can only touch
  the staged artifact, which is swept on failure; `dst` is always either
  the previous binary or the complete new one. The `.ocliv-bak`
  rollback point, the FIRST-candidate-wins rule, and ownership checks
  are preserved; no generic transaction framework was added. Red-before:
  `internal/setup/bootstrap_atomic_test.go`
  (`TestInstallBinaryInterruptedBeforeReplacementKeepsPrevious` FAILs on
  the unfixed direct-`os.WriteFile` path) / green-after; the
  completed-replacement-then-later-failure rollback test pins the
  preserved rollback contract.
- **Schema tension recorded (assessed, no migration):** the review's
  route-scoped revocation fence coexists with the existing
  (issuer, tenant, route)-scoped `jti` revocation table; the global-jti
  question was assessed and deliberately left as-is to avoid a silent
  persistent-schema change. Route-scoped fencing above is the enforced
  contract.
- **Gates (final tree, GOCACHE=/tmp/ocliv-go-build).** `go build ./...`,
  `go vet ./...`, `gofmt -l internal/ tests/` clean;
  `go test ./internal/... -count=1` green (all 19 packages);
  `go test -race ./internal/relay/ ./internal/agent/ ./internal/config/ ./internal/cli/ ./internal/mcp/` green;
  full integration suite green in 246.75s (timeout 420s).
- **NOT VERIFIED / operator-gated (unchanged).** No deployment of the
  current HEAD; the Pi stays on the 2026-11-11 binary. The review's
  own caution stands: do not deploy solely on these local gates —
  qualify the actual deployed binary against the real public edge after
  the operator chooses to deploy.

### 2026-11-14 second review — restore-protection, parser, and bootstrap-durability corrections

Scope: the follow-up deployment review's findings, closed with failing-first
regressions and focused corrections before any production promotion. All gates
run on the corrected source (GOCACHE=/tmp/ocliv-go-build).

- **P1 — Restore could resurrect managed authorization (`internal/relay/relay_backup.go`): FIXED.**
  The restore-time rollback guard now reads `authz_clients.revoked_at`,
  `authz_grants.status<>'active'`, and `authz_revocations.jti` into the
  revocation set, and `rollbackDiff` refuses a restore that would roll any of
  that managed authority backward (guarded on the live DB actually having the
  managed tables, so pre-V8 databases are not over-refused). `resetRestoredAuthority`
  now terminally revokes managed clients and grants, consumes outstanding
  codes/consent challenges, and **deletes the managed JWT signing key**
  (`DELETE FROM authz_issuer_key`) so every token minted under restored
  authority fails closed. Red-before: `TestRestoreRejectsManagedRevocationRollback`
  and `TestResetAuthorityInvalidatesManagedOAuth` FAIL on the unfixed guard
  (restore accepted; managed client left active); green after. A
  mutation-check (re-breaking only the managed-client reset) re-confirms the
  test genuinely asserts. `TestRestoreSafeManagedBackupStillWorks` proves a
  non-rolling-back restore is still permitted and preserves a legitimate
  active grant (the guard does not over-refuse).
- **P2 — Registration parser accepted malformed trailing data (`internal/authz/handlers.go`): FIXED.**
  The "exactly one JSON value" check now requires `io.EOF` specifically on the
  second decode; a second value OR malformed trailing bytes (a syntax error)
  is refused with zero durable writes. Red-before:
  `TestRegisterRejectsMalformedTrailingJSON` FAILs on the unfixed handler
  (`object + garbage` registered); green after.
- **P2 — Bootstrap replacement crash-durability (`internal/setup/bootstrap.go`): FIXED.**
  `InstallBinaryTo` stages under a UNIQUE per-install name
  (`<dst>.ocliv-staged-<pid>`, `O_EXCL`) instead of one fixed path, so two
  concurrent installs cannot write the same temporary; the staged file is
  `fsync`ed before the atomic rename and the parent directory is `fsync`ed
  after, so the rename is journaled (power-loss durability). `RollbackBinary`
  now also stages + `fsync` + atomic-renames the backup into place instead of
  a direct `os.WriteFile`. `validateStagedBinary` is documented strictly as a
  test hook for the publish boundary (candidate integrity is established by
  staging an exact byte copy + atomic rename + fsync; there is no separate
  signature to check at install time). Regressions:
  `TestInstallBinaryLeavesNoStagedArtifact`,
  `TestInstallBinaryValidationFailureSweepsStaged`.
- **P1 — Promotion plan corrected (`docs/qualification/PRODUCTION-PROMOTION-PLAN.md`): FIXED.**
  Three corrections: (1) the "post-backup tokens fail closed on restore"
  claim was WRONG — restoring the DB restores the signing key, so post-backup
  tokens can still verify; the plan now states a plain restore preserves (not
  revokes) post-backup authority and points to `--reset-authority` (which now
  retires the managed signing key) as the real cut. (2) The unsafe manual
  `cp -a` database restore — which bypasses the rollback guard — is replaced
  with the guarded `ocliv relay restore --data DIR --in FILE [--reset-authority]
  --relay-stopped`. (3) The post-rollback expectation text is corrected to
  match. The CLI restore success message now names managed clients/grants and
  the retired signing key.
- **Gates (corrected source).** `go build ./...`, `go vet ./...` (GOCACHE set;
  default cache is read-only), `gofmt -l internal/ tests/` clean;
  `go test ./internal/... -count=1` green (all 19 packages);
  `go test -race ./internal/relay/ ./internal/agent/ ./internal/config/ ./internal/cli/ ./internal/mcp/` green;
  full integration suite green in 267.15s (420s cap).
- **Still operator-gated (unchanged).** No production deploy. The Pi stays on
  the 2026-11-11 binary (`0d47481f…`) until the operator chooses to promote.
  The legacy-empty-tenant/route managed clients note stands: existing managed
  OAuth clients may need re-registration/re-approval after upgrading (V11
  binds clients to a route and the new source refuses unbound registrations).

### 2026-11-14 isolated ARM64 Pi qualification (candidate f2d2bec)

Scope: the staging directive — qualify the exact remediated ARM64 candidate on
PiInDaSky (10.9.66.170) in isolated loopback staging, no production change, no
public-edge claim. All seven execution requirements met.

- **Candidate frozen: DONE.** Remediation committed as `f2d2bec` (only the
  intended fix + regression tests; unrelated `events.jsonl`, `guidance.md`,
  `lab-backup/` left untracked). ARM64 built
  (`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w"`,
  go1.26.10), SHA-256 `fe48fb96…25a06b`. Provenance in
  `docs/qualification/pi-staging/PROVENANCE.txt`.
- **Unprivileged staging: DONE.** Owner-only `~/ocliv-stage` (0700), separate
  SQLite DB, loopback ports 28080/28085 (relay/health) + 28099 (harmless MCP
  upstream). No `/var/lib/ocliv`, `/usr/local/bin`, production Caddy, systemd
  units, Pi-hole, or Tailscale change.
- **Real-ARM64 exercise: DONE (29/29 PASS).** Startup, **schema V11**,
  restart persistence (durable publication), health/readiness, managed OAuth
  discovery (RFC 9728 PRM + RFC 8414 AS metadata), DCR, operator consent,
  authorization-code exchange, refresh rotation + replay rejection,
  revocation, and MCP tools/list + tools/call — all through the real ARM64
  binary and an isolated publisher + harmless counting upstream.
- **Security boundaries: DONE.** Cross-route authorize/code/revoke refused
  without destroying legitimate state; cross-route revocation does NOT poison
  the jti; spoofed `X-Ocliv-Upstream-Sub`/`X-Ocliv-Route` stripped (upstream
  sees only relay-minted values, external `Authorization` never forwarded);
  no-bearer/forged/tampered all 401 with **zero** upstream executions;
  malformed trailing JSON refused; consent-challenge replay rejected.
- **Recovery rehearsal: DONE (staging only).** Guarded backup; managed
  revocation rollback **refused** (`restore would resurrect … authz-grant:…`);
  `--reset-authority` invalidates managed clients/grants **and deletes the
  signing key** (`authz_issuer_key` → 0). Production DB never opened/migrated.
- **Production availability preserved: DONE.** BEFORE/AFTER recorded — binary
  `0d47481f…` unchanged, relay `active`, health `ok/ok`, production listener
  intact; staging confined to 28080/28085/28099.
- **Promotion package: DONE.** `docs/qualification/PROMOTION-RUNBOOK-2026-11-14.md`
  — qualified-commit artifact digest, schema-compatibility results, backup
  validation, legacy-client (empty tenant/route) re-registration note, restart
  sequence, post-deploy checks, paired rollback, and explicit operator gates.
- **Reproduce:** `~/ocliv-stage/pi_qual.py` on the Pi (runs the full suite).

**NOT VERIFIED (out of loopback scope):** public-edge / off-LAN reachability
and a real authorized `tools/call` through the public HTTPS edge; the live
production DB schema version (root-only, not yet read); ChatGPT/provider-IdP
OAuth. Staging qualification does not authorize production promotion — that
remains an explicit operator decision via the runbook gates.

### 2026-11-14 promotion-review recovery-correction pass (post-f2d2bec)

Scope: the promotion review's narrow recovery-qualification correction pass.
The isolated 29/29 qualification stays CLOSED/accepted; `f2d2bec` and the
qualified binary (`fe48fb96…`) were NOT altered or rebuilt. One source fix,
one runbook correction, one live disposable cross-version proof. No promotion,
no production mutation.

- **P1 — grant revocation guard keyed on client_id only: FIXED.** The guard's
  managed-grant identity is the full `(tenant_id, route_id, client_id)`
  composite PK, now a typed `authzGrantKey` struct (never a concatenated
  string). Two grants for one client on different routes can no longer mask
  each other's revocation. Red-before: `TestRestoreRejectsCrossRouteGrantRevocationRollback`
  FAILs on the unfixed `relay_backup.go` (cross-route rollback accepted) →
  green-after on the fixed source; full `internal/relay` package green.
- **P0 — paired rollback is not schema-compatible: FIXED (documentation +
  live proof).** `relay restore` runs `store.Open` on the backup, which
  migrates the scratch copy forward to V11 before installing — so no
  old-binary paired rollback exists. The runbook §5 was rewritten from
  "paired binary AND database rollback" to **forward-only, roll-forward
  recovery with the candidate binary** (reinstall known-good candidate; the
  guarded restore enforces revocation monotonicity; `--reset-authority` cuts
  managed authority). **Live cross-version proof (disposable, production
  untouched):** the actual production binary (`0d47481f…`, commit `6472ff8`)
  creates a **V7** DB; the candidate opens it and migrates to **V11** and
  serves; the old binary then **refuses the V11 DB** (`unknown state schema
  version`, fail-closed — not a silent brick); the candidate's guarded restore
  of the pre-upgrade V7 backup succeeds, migrates it to V11, and the restored
  DB serves under the candidate. Recovery = roll-forward, proven end-to-end.
- **P1 — Step 0 schema oracle wrong: FIXED.** `relay doctor` does not report
  schema version and `sqlite3` is absent on the Pi; the runbook now uses a
  genuinely read-only Python `sqlite3` query (uri `mode=ro`, `store.Open`
  never called) reporting `MAX(v)` + the unbound managed-client count, plus a
  read-only managed-client inventory.
- **Broad gates on the final source:** build + vet + gofmt clean; `go test
  ./internal/...` 18/18 green (relay 30s incl. the new regression). The
  unrelated untracked `events.jsonl`, `guidance.md`, `lab-backup/` were left
  alone. The qualified binary is unchanged — this pass does not re-qualify
  transport/OAuth, only the recovery contract.

### 2026-11-14 final artifact qualification — candidate realigned to 19d46d8

The promotion review correctly noted the frozen binary `fe48fb96…` (f2d2bec)
predated the composite-grant fix in `19d46d8`. This pass built a new artifact
from the final source and re-ran the bounded qualification on the actual
promotion binary. `f2d2bec`/`fe48fb96…` is now SUPERSEDED (kept for reference
only, must not be deployed).

- **New qualified artifact: `1ceaaff4173406f4b7bda5dbc897156273cfa2cd699fc57ae3932debc85912d7`**
  from `19d46d8`, same build config (go1.26.10, `CGO_ENABLED=0 GOOS=linux
  GOARCH=arm64 go build -trimpath -ldflags="-s -w"`, 13,500,578 bytes).
  Provenance updated in `docs/qualification/pi-staging/PROVENANCE.txt`;
  runbook §1/§2 re-pointed at the new digest.
- **29/29 Pi staging checks: PASS on the new binary.** Full isolated
  loopback re-run (fresh `relay-data`/`qual-home`, relay pre-started on
  28080/28085, harmless upstream on 28099). Phase E rollback-guard reason now
  emits the composite key (`authz-grant:t1/<route>/<client>`), confirming the
  typed `authzGrantKey` fix is live in this artifact.
- **Cross-route grant rollback (this binary): VERIFIED.** Live route-A grant
  revoked + route-B active; backup reversed; `relay restore` refused
  (`restore would resurrect 1 … authz-grant:t1/r-a/cli-x`), rc=8; live
  route-A still revoked, route-B still active.
- **Cross-version recovery (this binary): VERIFIED on disposable V7 state.**
  Actual production binary (`0d47481f…`, `6472ff8`) creates V7 → candidate
  opens and migrates to V11 and serves → old binary refuses V11
  (`unknown state schema version`, fail-closed) → candidate guarded-restores
  the V7 backup to V11 and the restored DB serves. Production `ocliv-relay`
  stayed `active` throughout.
- **Three runbook inconsistencies: FIXED.** (1) Step 3 "only the paired
  rollback recovers" → forward-only roll-forward wording; (2) Step 4 `sudo
  sqlite3` → read-only Python query (sqlite3 absent on the Pi); (3) Step 0
  managed-client inventory now tolerates an absent `authz_clients` table
  (pre-V8 schema). Recovery-point tradeoff recorded explicitly in §5.
- **NOT VERIFIED (operator-gated, unchanged):** live production DB schema
  read, off-LAN public-edge `tools/call`, ChatGPT/provider-IdP OAuth, legacy
  managed-client re-registration. Promotion remains an explicit operator
  decision via the runbook gates.

No files or production services were changed by the review; this pass changed
only the candidate artifact, runbook/provenance, and this register.

### 2026-11-14 release acceptance — obsolete promotion plan retired

Independent release assessment accepted source `19d46d8` / candidate
`1ceaaff4…`, closed the security-remediation review, and kept production
promotion on hold pending operator pre-flight. One P1 documentation hazard
was found and fixed in the same pass:

- **P1 — obsolete promotion procedure: FIXED.** The old
  `docs/qualification/PRODUCTION-PROMOTION-PLAN.md` (source `95cc66c`,
  superseded binary `8041278…`) still instructed operators to restore the
  old binary after `relay restore` — impossible after the V11 forward
  migration and dangerous to follow. It is now marked
  **SUPERSEDED — DO NOT EXECUTE** with an explicit pointer to
  `PROMOTION-RUNBOOK-2026-11-14.md` as the current procedure; the obsolete
  content is retained as historical context only.
- **Operator pre-flight is strictly read-only** against PiInDaSky
  (10.9.66.170): health/readiness, installed-binary digest, live DB schema
  version + managed-client inventory via read-only Python `sqlite3` (uri
  `mode=ro`; `store.Open` never called). **Hard stop before** any backup,
  binary replacement, schema migration, or service restart — those remain
  explicit operator decisions via the runbook gates.
- Off-LAN public-edge baseline should be captured **before** promotion so a
  pre-existing edge failure is not misattributed to the new binary.
- Durable preservation of the qualified source and artifact is an operator
  action before deployment; the local checkout and staging `/tmp` copies are
  not a disaster-recovery plan.
