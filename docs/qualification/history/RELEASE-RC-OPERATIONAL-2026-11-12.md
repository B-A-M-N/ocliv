# Release qualification — operational fixes and final RC (2026-11-12)

Scope: the three operational defects from the release review, the
release-gate tests that went with them, and ONE independent official-SDK
qualification pass against the final release candidate. No OAuth
architecture was changed and no authorization matrix was repeated.

## Artifacts under qualification

| Item | Value |
|---|---|
| Source commit | `6472ff8` (fix: terminal ownership denial gets its own corrective action) |
| Preceding commit | `48cf7d5` (the three operational fixes + the refresh-burn fix) |
| Binary | built from a CLEAN clone at `6472ff8`, no uncommitted changes |
| Binary digest | `025c30cae3ad9fb7b8c37258f304a59783568406d2e0cb636e94b6e8c576d659` |
| Staging stack | isolated relay on 127.0.0.1:18082 (health 18096), harmless upstream on 127.0.0.1:18999, separate DB and HOME dirs, public edge via the funnel |
| Production | untouched — no migration, no binary swap, no schema change |

The earlier candidate `3f9999d12a1deb18e1d06cd06359b459ec9da945c4c3222d5ffa1671a871d52a`
(commit `48cf7d5`) was superseded: its live cross-key run terminated
correctly but printed the generic re-enroll advice, which is wrong for a
name conflict. That hint was fixed and the candidate rebuilt.

## Fix 1 — explicit tenant arguments are honored or refused

`ocliv relay issue-enroll --tenant NAME` (space form) was silently
ignored: the code was bound to an invented `tenant-enr-<id>` namespace
instead of the tenant the operator named. A publisher enrolled in the
wrong tenant lands in the wrong administrative scope, so this was a
scope defect, not a parsing nit.

- Both spellings (`--tenant NAME`, `--tenant=NAME`) are honored.
- An explicit but EMPTY or MISSING value is REFUSED (exit 2, no code
  minted) rather than ignored.
- No `--tenant` at all still means "mint a fresh enrollment".

Red-before (3 failures): the space form bound `tenant-enr-1794553276839552346`;
`--tenant=` exited 0; `--tenant` with no value exited 0. Green after.

Live proof on the RC: four enrollment codes minted, one per spelling and
per run — every one bound to `rctenant`:
`enrollment tenants: [('rctenant',), ('rctenant',), ('rctenant',), ('rctenant',)]`,
and two distinct keys in that tenant (`key-d65fab675384eb49`,
`key-b325ba2a3b25b310`).

## Fix 2 — durable publication identity

A bare `ocliv mcp PORT` minted a RANDOM publication name per run, so the
public URL changed on every restart and each run left another publication
row behind under the same owner.

The name is now DERIVED FROM THE SERVICE (port, local target, auth
profile), not from the moment of publication. An explicit `--name` still
wins, and `--fresh-publication` asks for a new identity on purpose.

Live proof on the RC, two separate publisher restarts:

| Case | Before restart | After restart | Rows |
|---|---|---|---|
| named publication `rc-qual` | route `h5VRXQnQP1WUgLBxormeHQ` | route `h5VRXQnQP1WUgLBxormeHQ` | 1 |
| bare alias `ocliv mcp 18999` | name `mcp-18999-ocliv-managed-0e107996`, route `ffga2Mr12I9849TPAUUCyw` | same name, same route | 1 |

The publication was rebound to the replacement lease in both cases
(`lease_id` changed, `route_id` did not), which is the durable-URL
guarantee: the endpoint an operator handed to a client survives a
publisher restart.

## Fix 3 — cross-key conflict is terminal and actionable

A cross-key publication conflict was closed with the RETRYABLE conflict
code (4409), so the agent looped forever printing "reconnecting" and
never told the operator what to do. Ownership denials now carry their
own error code (`ownership_conflict`) and close code (4413); the agent
classifies them as terminal with an actionable message. The allocation
race keeps its retryable class, so a race a retry can win is still
retried.

Live proof on the RC — a second agent key in the same tenant publishing
the held name:

```
publication name is held by another agent key in this tenant: publish under a different --name,
or ask the operator to transfer or revoke the existing one
EXIT_CODE=4
```

Terminal (no reconnect loop), exit 4, and the advice is correct: it does
NOT send the operator to re-enroll, because the credential is valid.

The rejection was NOT weakened. Server-side state after the attempt:
the publication still belongs to key A (`wwQKJ41ce-IdWkUtOwDpfw`,
`owner_key_id=key-d65fab675384eb49`), the lease is still key A's and
ACTIVE, both denials are audited (`lease_reclaim/denied`,
`attach/denied/ownership_conflict`), and the route still answers 401 to
an unauthenticated call rather than being hijacked.

The denial is recognized by a TYPED sentinel (`agent.ErrLeaseOwnership`),
not by message wording, so a wording change cannot reclassify it.

## Defect found by the new concurrency test — refresh rotation was not atomic

The release-gate concurrency test (simultaneous refresh attempts with
one refresh token) failed on the first run: **2 of 8** attempts
succeeded. The refresh grant burned its token check-then-act, so two
simultaneous rotations could both mint a live pair — a refresh-token
replay window.

Fixed with an atomic burn (`Store.BurnToken`): the insert IS the
decision, so exactly one concurrent caller can burn a given refresh
token and every other caller is told it lost. `RevokeToken` stays
idempotent, because RFC 7009 revocation must remain so.

After the fix: 25 consecutive runs, always exactly one winner.

## Release-gate tests

- **Concurrent refresh attempts** — exactly one winner; the losers fail
  closed with `invalid_grant` and never receive a second pair.
- **Natural access-token expiry** — with a short TTL the token stops
  being admitted when it expires (no simulation), and the refresh grant
  still issues a working pair.

## Independent official-SDK qualification (Python MCP SDK 1.28.1)

Run against the RC binary over public HTTPS. The SDK discovered the
authorization server from the relay's own 401 challenge, registered
through DCR, and completed consent the way a browser does.

Phase 1 — the complete flow: 5/5 PASS. `initialize-ok`, `tools/list
[qual_ping]`, `tools/call` → `pong:ocliv-qual-4`, an access+refresh pair
issued, exactly one upstream `tools/call` executed, exactly one
authorization code consumed, and the server-side audit chain
`operator/approve/ok` → `client/consent/ok`.

Phase 2 — renewal after the access token is rejected: 8/8 PASS. RFC 7009
revoke returned 200 and is recorded server-side; the revoked token is
refused with 401 and the refusal did NOT execute upstream; the relay's
refresh grant answered 200 with a fresh pair; the presented refresh token
was burned (rotation); the renewed token was admitted and its
`tools/call` reached the upstream.

### The Python SDK's re-consent after a server-side rejection is CLIENT-side

The SDK falls back to a full authorization flow when its access token is
rejected server-side. The mechanism is in the SDK's own source
(`mcp/client/auth/oauth2.py`): it refreshes only when its own clock says
the token expired (`if not is_token_valid() and can_refresh_token()`), so
a server-side revocation of a still-locally-valid token goes to the 401
branch and re-consents.

This was isolated, not assumed, with two branches:

- **A (relay half) — 5/5 PASS.** The relay's refresh grant works: 200, a
  fresh pair, the rotation burn recorded, the renewed token admitted,
  and the renewed call executed upstream.
- **B (client half) — 4/5 PASS.** With the SDK's own expiry view forced
  into the past (its own code path, no SDK modification), the SDK took
  its refresh branch and recovered with NO new browser authorization:
  `tools/list` and `tools/call` → `pong:ocliv-qual-6`. The server
  confirms it: for that client there is exactly ONE operator approve and
  ONE consent, and exactly ONE rotation row — the renewal consumed
  neither a code nor an approval.

  The one non-PASS check was a mis-stated assertion in the harness (it
  compared the renewed token against the ORIGINAL token, which the
  relay had already rotated in branch A); the server-side rotation row
  for that client is the correct evidence.

**Conclusion:** the relay-side refresh path is NOT implicated. The
TypeScript SDK's crash-restart recovery (qualified earlier) and the
Python SDK's behaviour differ because their 401 handling differs — the
TypeScript client refreshes on rejection, the Python client does not.
This is a client-SDK property, and it bounds what Ocliv can promise: an
official client that re-consents on a server-side token rejection will
re-consent. Ocliv's guarantee is that the refresh grant works and the
operator approval is not consumed by a renewal.

## Gates

| Gate | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `gofmt -l internal/ tests/` | clean |
| `go test ./internal/... -count=1` | all packages green |
| `go test -race` (relay, agent, cli, authz, apperr, protocol) | all green |
| `go test -count=1 -timeout 420s ./tests/integration/` | green, 231s |

The race and integration runs above were executed at `48cf7d5`; the
subsequent change (`6472ff8`) touched only the agent's denial error
construction and the CLI's hint mapping, and was re-verified with
`go build`, `go vet`, `gofmt`, `go test ./internal/...` and
`go test -race ./internal/cli/ ./internal/agent/` — all green.

## Remaining blockers (unchanged by this pass)

1. **Raspberry Pi unreachable** — host-level outage. Unreachable over
   LAN (ARP FAILED) and over Tailscale (last seen ~5h). A full /24 SSH
   sweep with host-key comparison found no copy of it on the LAN. The
   LAN gateway and other hosts answer. Read-only investigation only; no
   migration, no binary swap, no reinstall. Last verified production
   state (before the outage): relay active, binary
   `0d47481f2e2b7cbff`, health 200/200, `/var/lib/ocliv` untouched by
   this work. Needs physical/operator recovery; production promotion
   cannot be planned against an unreachable host.
2. **AGENTS.md P4 reconciliation unapplied** — the write guard's
   approval prompt timed out on every attempt in this session, and the
   guard forbids retrying or routing around it. The reconciliation text
   is ready and must be applied through the authorized guard with an
   in-band approval.
3. **Permanent ingress / ACME / Caddy** not qualified for production.
4. **ChatGPT registration and CIMD** — separate acceptance gate; passing
   the official Python and TypeScript SDKs does not establish ChatGPT
   interoperability.

No production promotion, live schema change, or production binary
replacement was performed.
