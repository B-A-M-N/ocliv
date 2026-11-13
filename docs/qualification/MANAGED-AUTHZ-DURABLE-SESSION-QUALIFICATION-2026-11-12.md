# Managed-auth qualification — pass 4 (durable client session)

**Date:** 2026-11-12/13 · **Binary:** `919e9c15febc83372540f13e515688e0419c9e5df56ac0dc45b09f3af0b2e3fe`
(commit `7883cfd`, arm64-independent local build) · **Client:** official MCP Python SDK `mcp==1.28.1`
· **Stack:** isolated staging only — relay `127.0.0.1:18082` (health `127.0.0.1:18095`), staging DB
`/tmp/ocliv-qual4/data`, harmless upstream `127.0.0.1:18999`, public edge
`https://pop-os.tail8d285a.ts.net` (tailscale funnel + trusted cert).
**Production untouched:** no process, binary, DB or service on the Pi was read or written; `/var/lib/ocliv`
was never opened.

## Why this pass existed

Passes 1–3 (`33e5a94`, `f0a7196`, `7883cfd`) proved discovery, consent, token exchange, tool
execution, restart stability and cross-key rejection with a real SDK client, but the SDK run ended at
one successful session. The review's P5-4 ("refresh/reconnect behaviour across access-token expiry")
and P3 ("unattended client continuity") were therefore still open: nothing had yet shown that an
approved client survives the one-hour access-token lifetime **without a new operator credential**.

## What was exercised

| # | Gate | Result | Evidence |
|---|------|--------|----------|
| 1 | Complete OAuth flow with a current MCP SDK | PASS | SDK drove 401 → PRM → AS metadata → DCR → PKCE authorize → browser consent → token (access + refresh) → `initialize` → `tools/list` → `tools/call` (`pong:ocliv-qual-1`) |
| 2 | Real external client over trusted HTTPS | PASS | official `mcp==1.28.1` `OAuthClientProvider` against `https://pop-os.tail8d285a.ts.net/r/<route>/mcp`; the SDK read the relay's own `WWW-Authenticate` challenge |
| 3 | `tools/list` + `tools/call` | PASS | `tools/list` → `["qual_ping"]`; `tools/call` → `pong:ocliv-qual-1..5` |
| 4 | **Refresh/reconnect across access-token expiry** | **PASS (new)** | see below |
| 5 | Token and client revocation | PASS | operator `authz revoke` → existing access token `401`, refresh grant `400 invalid_grant "client is not approved for this route"`, upstream counter unchanged |
| 6 | Same-key restart / cross-key takeover | PASS | same key: route id `GGEQqztOK0ul-oRFwpt1Bw` preserved across stop→503→restart→401, lease rebound to a new lease id under the same key. Second key in the same tenant: takeover refused, 7 `lease_reclaim`/`denied` audit rows, original lease and route untouched, original publisher still serving |
| 7 | Unpublish with durable grant retirement | PASS | publication row deleted; both grants `active→revoked`; client registration rows preserved; route `404` |
| 8 | No unauthorized upstream executions | PASS | the harmless upstream counts one line per MCP method; it moved only on authorized `tools/call` (5 total), and did **not** move for any 401/400/403 path |

## Gate 4 in detail — the unattended durable session

One SDK process, one consent, then a session that outlives the access token:

```
session-1-begin        fresh client: 401 challenge -> discovery -> consent
authorize-url          https://pop-os.tail8d285a.ts.net/r/OkNs.../oauth/authorize?...   (no credential in the URL)
callback-received      real browser submitted the single-use pairing credential
token-stored           rotation=False  access_prefix=eyJhbGci
initialize-ok
tools-list             ["qual_ping"]
tools-call             pong:ocliv-qual-4
access-token-expired-in-process
                       prior_access_prefix=eyJhbGci
                       token_endpoint=https://pop-os.tail8d285a.ts.net/r/OkNs.../oauth/token
session-2-begin        no browser leg, no operator step
token-stored           rotation=True   <-- the SDK refreshed through the relay's grant
initialize-ok
tools-list             ["qual_ping"]
tools-call             pong:ocliv-qual-5
session-2-complete     unattended=True
```

The SDK's own expiry accounting was made stale exactly as the relay's one-hour TTL would make it;
the SDK then took its refresh branch against the **route-scoped** token endpoint it had discovered
from the 401 challenge, and continued with `tools/list` + `tools/call` with no browser, no operator
credential and no new consent. The upstream counter moved by exactly one (the authorized
`tools/call`).

Relay-side refresh semantics, confirmed live over the public edge:

```
refresh #1 (live refresh token)   -> 200  (new access + new refresh)
refresh #2 (replay of the rotated) -> 400  {"error":"invalid_grant",
                                                "error_description":"refresh token already rotated or revoked"}
```

## Newly found defects (this pass) — not fixed here, reported for authorization

1. **P2 — `ocliv relay issue-enroll --tenant NAME` (space form) is silently ignored.**
   The parser only accepts `--tenant=NAME` (`internal/cli/cli_relay.go:491`). With the space form the
   enrollment code is minted with an empty tenant, so `IssueEnrollmentCode` invents a fresh tenant
   namespace (`tenant-enr-<id>`) and the publisher is enrolled **outside** the tenant the operator
   named — with its own authority namespace and no visible error. Reproduced live: the code for
   `--tenant=qual4` carried `tenant_id='qual4'`; the code for `--tenant qual4` carried
   `tenant_id='tenant-enr-1794540384041270531'`. Other subcommands (e.g. `ocliv authz approve
   --tenant qual4`) accept the space form, so the CLI is inconsistent. Fix direction: accept both
   forms (and reject an empty value), and fail loudly when a named tenant cannot be bound.
   **This pass did not touch `internal/cli/cli_relay.go`** — it is outside the boundaries authorized
   for this remediation.
2. **P3 — the bare `ocliv mcp PORT` alias mints a random publication name per run.**
   Two publishes of the same port produced `pub_name` `amber-798680c1d9b36e0b20b1c1e6` and
   `quiet-1be08adb0970ed974d9c85ad`, hence different route ids. Route ids are stable per *name*
   (verified: `--name stable-test` kept `GGEQqztOK0ul-oRFwpt1Bw` across a publisher restart), but an
   operator who uses the bare alias loses the durable-URL property the alias is meant to provide.
   Fix direction: derive a stable default name from the target (e.g. `port-18999`) or require
   `--name` for a durable publication.

## Known limits that remain

- The TypeScript SDK client was not driven.
- Refresh across a *real* wall-clock hour was not waited out; the one-hour TTL was simulated by
  making the SDK's own expiry accounting stale, then exercising the relay's real refresh grant.
- A **restarted** SDK client whose access token has already expired does **not** refresh silently:
  the SDK has no cached AS metadata after a restart, so it re-runs discovery and, on the 401, starts
  a full authorization (browser consent) instead of using its refresh token. Unattended continuity is
  therefore proven for a long-lived client process, not yet for a crash-restarted one.
- ChatGPT registration, CIMD, permanent public ingress, ACME/Caddy edge and production deployment
  remain unverified/operator-gated.
- The cross-key conflict still surfaces as an endless "reconnecting" loop (close code 4409 is
  retryable); the security property is verified, the operator-facing UX is not.

## Teardown

Staging relay, publishers, upstream and `/tmp/ocliv-qual4` removed after the run. The production
relay was never contacted.
