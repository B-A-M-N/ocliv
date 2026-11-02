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
