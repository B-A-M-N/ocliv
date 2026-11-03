# Gate 3 — Public Funnel Qualification Report (2026-11-01)

## Topology under test

Public client (this machine, public internet, no tailnet path) →
`https://pop-os-3.tail8d285a.ts.net:10000` (Tailscale Funnel, managed TLS) →
Caddy `127.0.0.1:18081` (funnel file, header overwrite + Host-strip) →
relay `127.0.0.1:8080` (`ocliv 1.0.0`, `--relay-host/--mcp-host
pop-os-3.tail8d285a.ts.net --mcp-port 10000`) → agent WSS+yamux →
fixture `127.0.0.1:18765` (throwaway stdlib MCP, bearer `g3-test-token`, /tmp only).

## Verdicts

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | Valid public TLS, no `-k`/`--insecure` | PASS | `curl` chain verified; challenge POST reached relay (400 = relay-level reject of empty body) |
| 2 | Authority denial | PASS | `/` → 421; unknown route → 404; off-profile path → 421; control path via route → 421; forged Host denied pre-forward |
| 3 | Strict-discovery publish | PASS | `✓ MCP route ready (auth: upstream-oauth)` + `✓ OAuth discovery verified (resource matches published URL)`; URL `https://pop-os-3.tail8d285a.ts.net:10000/r/8wWK3wXg0mEol-rFiRyG6w/mcp` |
| 4 | Unauthenticated tool use | PASS (denied) | no-token → 401, wrong-token → 401, zero upstream execution (fixture access log) |
| 5 | Authorized interop | PASS | `tools/list` 200, `tools/call ping` 200 with unique nonce `pong-g3-*` |
| 6 | Offline publisher | PASS | SIGTERM → `publication retained (offline until republished)`; route → 503, no stale forwarding |
| 7 | Stable rebind | PASS | Republish same name → SAME route URL; live `tools/call` 200 |
| 8 | Permanent removal | PASS | `mcp unpublish --lease …` → `✓ MCP route removed`; tool path + discovery path → 404 |
| 9 | Fail-closed aborts | PASS | Two failed publishes (fixture binding race; stale binding) each auto-deleted the route, no orphan |

## Notes

- The relay's well-known rewrite (`/.well-known/oauth-protected-resource/r/<id>/mcp`
  → upstream `/.../mcp`) was proven by fixture access logs, not inferred.
- `https://g3smoke.t.ocliv.test` printed at attach is the lease's wildcard
  identity, not the route URL; the route URL is printed only after discovery.
- Funnel SNI/Host consistency at the Funnel→Caddy hop stays NOT VERIFIED
  (SNI terminates at Funnel by design); relay-side exact-Host checks PASS.
- Pre-g3 lab agent key remains in relay DB — revoke with
  `ocliv relay revoke-key --key-id <id> --data ~/ocliv-lab` before
  untrusted exposure (CLI landed post-Gate-3; P0-A).

## Gate 4 — ChatGPT registration: BLOCKED

Needs a workspace permitting custom MCP servers. Nothing in code stands in
the way; the URL to register comes from a fresh `mcp publish` of the real
MCP server. `mcp doctor` reports `EXTERNAL_UNVERIFIED` by design until then.

## Addendum — 2026-11-03 replication (direct-relay funnel, no Caddy)

Topology: public client → `https://pop-os.tail8d285a.ts.net:443`
(Funnel, managed TLS) → relay `127.0.0.1:18082` directly
(`--relay-host/--mcp-host pop-os.tail8d285a.ts.net`, `--domain ocliv.test`).
No Caddy in this run (funnel repoint needs root; relay got the backend
port instead). Runtime state in /tmp only; repo tree untouched otherwise.

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | Valid public TLS, no `-k` | PASS | curl default trust; challenge POST → 401 relay-origin |
| 2 | Authority denial | PASS | `/` → 421; bogus enroll code → 401, unconsumed |
| 3 | Strict-discovery publish | PASS | `✓ MCP route ready (auth: upstream-oauth)` + `✓ OAuth discovery verified`; route `https://pop-os.tail8d285a.ts.net/r/E2CI3j6ZIqS1yVqpsMdYNw/mcp` (oauth-lab fixture, read-only ping) |
| 4 | Unauthenticated tool use | PASS (denied) | no-bearer → 401, tampered-signature → 401 |
| 5 | Full OAuth + authorized call | PASS | DCR → PKCE authorize → token → `tools/list` 200, `tools/call ping` 200 (`pong:ocliv-oauth-lab-1`) |
| 6 | Upstream revoke via route | FIXED + live-verified | `POST /r/<id>/oauth/revoke` → 421; allowlist in `internal/relay/relay_mcp_ingress.go:198-202` covers authorize/token/register only. Tokens stay valid to 900s expiry; relay-side unpublish/lease-revoke remains the kill switch. Fix landed + live-verified: `/oauth/revoke` added to `mcpOAuthEndpoints` with parse + dispatch regression tests; live `POST /r/<id>/oauth/revoke` → 200, revoked-token `tools/call` → 401. Relay restart for deploy preserved the stable route (publisher reconnected, same URL). |

Note: `publish --auth fixture-anonymous` correctly refused (fail-closed);
upstream-oauth with the no-auth smoke fixture correctly failed discovery
before this run switched to the OAuth lab fixture.
