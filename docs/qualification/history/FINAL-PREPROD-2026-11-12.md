# Final pre-production qualification — release candidate `95cc66c` (2026-11-12)

Scope: the final pre-production review. Priority 1 items A-F were found
**already implemented** in `26ac95a` (which post-dates the `33e5a94`
baseline) and were re-verified rather than rewritten. ONE new verified
defect was found and fixed, plus the one Priority 1 regression that was
missing. No OAuth architecture was redesigned, no external identity
infrastructure was introduced, no gateway aggregation was added, and the
production Pi relay was not touched.

## Artifacts under qualification

| Item | Value |
|---|---|
| Source commit | `95cc66c` — fix(relay): advertise the RFC 9728 metadata URL as resource_metadata |
| Preceding commits | `48cf7d5`, `6472ff8` (operational fixes), `26ac95a` (A-F + refresh tokens), `7883cfd` (route-scoped throttle) |
| Binary | built from a CLEAN clone at `95cc66c`; no uncommitted changes |
| Binary digest | `804127863c9ae8c87bebcc13de2b6ffbf3c33542834b1c58e317e82c7ec118c4` |
| Go toolchain | go1.26.10 linux/amd64 |
| Staging stack | isolated relay on 127.0.0.1:18082 (health 18096), harmless upstream on 127.0.0.1:18999, separate DB and HOME dirs, public edge via tailscale funnel with real TLS |
| Production | untouched — no migration, no binary swap, no schema change; `/var/lib/ocliv` never used for staging |

## The one NEW verified defect: Priority 1 A, the challenge parameter name

The managed route's `WWW-Authenticate` advertised the RFC 9728
protected-resource metadata URL under the parameter name **`resource_uri`**.

RFC 9728 §5.1 names that parameter **`resource_metadata`**, and the MCP
2025-11-25 authorization spec requires servers to "include the resource
metadata URL in the `WWW-Authenticate` HTTP header under
`resource_metadata`".

**No client parses `resource_uri`.** The official Python MCP SDK reads
`resource_metadata` (`mcp/client/auth/utils.py`:
`extract_field_from_www_auth(response, "resource_metadata")`), and finding
nothing, it silently fell back to GUESSING the well-known path — which
happened to match Ocliv's own layout. The earlier qualification therefore
passed **by luck**: a client that trusts the challenge would have
dead-ended, and a client whose fallback differs (root-only well-known)
would have failed outright.

Failing-first evidence (red on the old code):

```
--- FAIL: TestManagedChallengeUsesRFC9728ResourceMetadataParameter
    challenge "Bearer resource_uri=\".../.well-known/oauth-protected-resource/r/OK5RxSlpMr1kslFoqd0zNg/mcp\""
    does not carry the RFC 9728 parameter resource_metadata="..."
--- FAIL: TestManagedChallengeMetadataURLIsFetchableAndRouteBound
    challenge "...resource_uri=..." has no resource_metadata parameter
--- FAIL: TestManagedChallengeMissingBearerHasNoErrorCodeAndInvalidDoes
    invalid-bearer challenge lost the metadata URL
```

Fix: the challenge now carries `resource_metadata`, and the stale
parameter is gone.

Live proof after the fix — the SDK's OWN extraction function, run against
a real 401 from the release candidate (`scripts/verify-challenge-following.py`,
6/6):

```
challenge: Bearer resource_metadata="https://pop-os.tail8d285a.ts.net/.well-known/oauth-protected-resource/r/tLr9k_MPbqi55NoNcaU1gA/mcp"
PASS the official SDK extracts the metadata URL from the challenge
     extracted='https://pop-os.tail8d285a.ts.net/.well-known/oauth-protected-resource/r/tLr9k_MPbqi55NoNcaU1gA/mcp'
PASS the advertised metadata document is served  status=200
PASS the metadata names this route's resource
PASS the metadata names at least one authorization server
```

## Priority 1 — status of each item

| Item | Disposition | Evidence |
|---|---|---|
| A — MCP bearer challenges | **FIXED** (`95cc66c`) | red-before/green-after above; live SDK extraction |
| B — DCR resource exhaustion | **VERIFIED** + one missing test added | quota enforced atomically (count+insert in one transaction, both stores); abandoned registrations reclaimable past `MaxPendingClientAge`; approved/granted/revoked identities never deleted. The limiter is ROUTE-scoped (`7883cfd`); the per-tenant contention tests Priority 1 B required are new in `internal/relay/relay_authz_contention_test.go` |
| C — atomic unpublish | **VERIFIED** | one transaction covers publication delete + grant retirement; failure-injection regression (`relay_unpublish_atomic_test.go`) proves a retirement failure rolls the publication back; live unpublish retired the route's ACTIVE grant to `revoked` in the same commit, kept the grant row and the client registration, route → 404 |
| D — redirect URI validation | **VERIFIED** | `url.Parse` + `Hostname()` + `Port()` + `net/netip` (never colon splitting); bracketed IPv6 loopback accepted, private/ULA/link-local literals rejected, exact allowlist matching preserved |
| E — fail-closed pairing expiry | **VERIFIED** | a malformed or missing expiry timestamp denies the credential instead of making it eternal |
| F — authorization-state retention | **VERIFIED** | `PruneAuthzExpired` clears consumed/expired codes and consents and revocations past the 30-day window; `PruneAbandonedClients` reclaims never-approved registrations; driven by `RunAuthzMaintenance` on the relay's own lifecycle (no second daemon) and at boot; active grants are never pruned, so a prune can never resurrect access |

## Priority 2 — standards compatibility

Verified for the implemented subset:

- **DCR** accepts `application_type` and refuses a `web` client using a
  loopback redirect (the RFC 8251 shape). Older clients that omit the
  field are accepted.
- **`iss`** is present in the authorization response (RFC 9207).
- **Resource indicators** are required and bound; the token audience is
  bound to the exact route.
- **Revocation** is RFC 7009: idempotent, 200 for an unknown token.
- **Metadata** is RFC 8414 (AS) and RFC 9728 (PR), both route-scoped.

**CIMD is NOT implemented and NOT claimed.** It is a separately bounded
compatibility milestone, not part of this remediation.

## Priority 3 — unattended client access

Refresh tokens are issued, rotate, and reject replay
(`26ac95a`), so the operator approves a client ONCE and the session
continues unattended. The rotation burn is ATOMIC
(`Store.BurnToken`): the concurrency gate found **2 of 8** simultaneous
rotations had both minted a live pair, and the atomic burn makes exactly
one caller win (25/25 runs). No permanent, unrevokable access token
exists; operator revocation stays terminal.

## Priority 5 — independent staging qualification: 37/37 checks

Two harnesses, both permanent in the repo:

- `scripts/qual-managed-oauth.py` — the OAuth flow, tools, revocation,
  refresh and replay rejection (15 checks).
- `scripts/qual-managed-lifecycle.py` — same-key restart, cross-key
  takeover refusal, unpublish with grant retirement (22 checks).

Raw evidence: `docs/qualification/evidence/rc3-oauth-flow.log` and
`rc3-lifecycle.log`.

| # | Requirement | Result |
|---|---|---|
| 1 | Complete OAuth flow with a current MCP SDK | PASS — Python MCP SDK 1.28.1: initialize, tools/list, tools/call → `pong:ocliv-qual-1` |
| 2 | A real external client over trusted HTTPS | PASS — DCR registered `cli_DtU-XaIJ6JaDpvNuYCXElA`; grant ACTIVE; the challenge is followed without fallback |
| 3 | Successful tools/list and tools/call | PASS — exactly one authorized upstream execution |
| 4 | Refresh/reconnect across access-token expiry | PASS — refresh grant issues a new pair; the renewed token reaches the upstream; REPLAY of the rotated token → 400 |
| 5 | Token and client revocation | PASS — RFC 7009 revoke → 200; the revoked token → 401; no upstream execution |
| 6 | Same-key restart and cross-key takeover refusal | PASS — restart keeps the SAME route id (new lease, one publication row, 503 → 401); cross-key refused with exit 4 and an actionable message; original owner unaffected; refusal audited |
| 7 | Unpublish with durable grant retirement | PASS — publication gone, grants retired to `revoked` in the same commit, grant rows and client registrations preserved, route → 404 |
| 8 | No unauthorized upstream executions | PASS — every denial left the upstream's counter unmoved (0 → 0 on refusal; 1 → 1 after revocation) |

## Gates at `95cc66c` (Go 1.26.10)

| Gate | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `gofmt -l internal/ tests/` | clean |
| `go test ./internal/... -count=1` | green, 18 packages |
| `go test -count=1 -timeout 420s ./tests/integration/` | green, 248s |
| `go test -race` (relay, agent, cli, authz, limits, apperr, protocol) | green |
| `git diff --check` | clean |

## Remaining known limitations

1. **Real-client registration is operator-mediated.** Each new client
   needs an operator approval and a single-use pairing credential. An
   unattended client cannot self-register. This is the intended security
   boundary, not a defect — but it IS an operational step per client.
2. **The Python SDK re-consents after a SERVER-side token rejection.** It
   refreshes only when its own clock says the token expired, so a
   revocation that arrives early sends it into a fresh authorization.
   This was isolated, not assumed: the relay's refresh grant works
   (5/5), and with the SDK's own expiry calculator patched the SDK renews
   with NO new consent — one approve row, one consent row, one rotation
   row server-side. A client-SDK trigger, not a relay defect.
3. **Production deployment is BLOCKED.** The Raspberry Pi relay is
   unreachable (host-level outage; no working network path over LAN or
   Tailscale; absent from a full /24 host-key sweep). The permanent
   ingress / ACME / Caddy edge is NOT VERIFIED.
4. **CIMD is not implemented or claimed.**
5. **Any pre-`95cc66c` binary advertises the unusable `resource_uri`
   parameter.** A client that trusts the challenge may dead-end — upgrade
   required.

## Production promotion: BLOCKED

The designated relay host is unreachable, so the promotion procedure
cannot be executed or verified against the real deployment configuration.
This is a deployment blocker, not a code blocker: the release candidate is
qualified on an isolated stack with a real external client over trusted
HTTPS.

No production migration, no binary replacement, and no schema change was
performed. `/var/lib/ocliv` was never used for staging. Promotion
requires, in order: (1) the Pi reachable and its current state verified
(binary digest, schema version, health); (2) a WAL-safe backup of the
production DB with a content checksum, paired with the new binary in the
rollback plan (schema V11 is forward-only, so binary-only rollback
leaves the service DOWN — both artifacts must be restored together);
(3) the permanent ingress/ACME/Caddy edge qualified against that host;
(4) the operator's explicit approval for each of those steps.
