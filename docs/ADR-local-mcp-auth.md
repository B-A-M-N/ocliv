# ADR: Authorization for local MCP services

- Status: Proposed — design only, no implementation
- Date: 2026-11-11 (revised; supersedes the first revision of this file)
- Scope: publishing **local MCP servers that have no native OAuth** without
  adding a mandatory external identity provider, reverse proxy, OAuth server,
  or per-service adapter — and keeping the endpoint free and persistent.

## Problem

Ocliv must stay a lightweight, self-hostable tunnel for local HTTP services,
MCP servers, and existing MCP gateways. Publishing an MCP service today
requires the upstream to serve standard OAuth discovery (RFC 9728 PRM +
RFC 8414 AS metadata + `/oauth/*`). Local MCP servers do not, so they cannot
be published.

Correction to the first revision: the fix must not add a mandatory external
IdP/proxy/adapter, must not cost money, and must not turn a publisher relaunch
into a setup ritual. The endpoint has to come back with one command and no
re-enrollment, re-configuration, or re-approval.

## Requirements

R1. Preserve the proven relay, TLS edge, tunnel transport, enrollment,
    publication lifecycle, and security invariants.
R2. Separate tunnel transport from authorization, **without a separate
    user-managed gateway process**.
R3. One reusable authorization module, configured **once per relay**, with
    strict per-tenant, per-publication, and per-client boundaries. Evaluate
    the existing Auth0 option first. No mandatory
    Keycloak/Authentik/Zitadel/Hydra.
R4. Three explicit publishing classes:
    - C1 generic HTTP service with a visitor-access policy;
    - C2 native HTTP MCP server/gateway, including OAuth passthrough;
    - C3 local MCP server without OAuth, protected by Ocliv-managed
      authorization.
R5. Publisher-side stdio-to-HTTP adapter built on the existing bounded MCP
    machinery (child lifecycle, cancellation, streaming, errors, limits). No
    arbitrary remote command execution.
R6. Secure auth is the default for remotely published MCP tools; operator
    approval/revocation; unknown client = no tool access; **no unauthenticated
    fallback**.
R7. RFC 9728 PRM, AS discovery, PKCE, resource indicators (RFC 8707),
    audience isolation, CIMD, DCR where required. Proven security libraries;
    no hand-rolled OAuth crypto or token verification.
R8. Route-specific authorization and explicit grants. Validate before
    forwarding; never forward an external bearer to an unauthenticated
    upstream; tunnel enrollment is not end-user authorization.
R9. Preserve MCP semantics (streaming, cancellation). Qualify legacy MCP
    versions and the current 2026-07-28 protocol separately.
R10. An existing MCP gateway may be published as one upstream; Ocliv must not
    duplicate gateway aggregation/routing/orchestration.
R11. **Persistent endpoint**: relaunching the publisher re-establishes the
    same endpoint with no re-enrollment, re-configuration, or re-approval.
R12. **Free**: the default path requires no paid or hosted service.

## Approaches

### A. Shared relay-side authorization module — recommended

A new `internal/authz` package inside the relay, configured once per relay.
The relay is the Authorization Server for C3 routes: it serves PRM + AS
metadata + `/oauth/*`, issues signed tokens, and validates them at admission.

```
client -> relay /r/<id>/... -> [authz module] -> local MCP (loopback, tunneled)
                                       ^ jwks / issuer key (relay DB)
```

- **No new process, no new deployment, no external service.** The module is a
  distinct package; the transport path is unchanged.
- **Configured once per relay**: issuer key + approval policy live in the
  relay DB; every tenant/publication inherits the boundary.
- **Persistent**: clients, grants, and the issuer key persist in the relay DB,
  so a publisher relaunch rebinds the same route with no re-approval.
- **Free**: self-hosted issuer; $0.
- **Cost**: the relay grows a security-critical OAuth surface. Mitigated by
  keeping it a separate package with its own tests; the relay already
  terminates TLS, holds the enrollment keys, and audits every route decision.

### B. Embedded publisher-side module

The same `internal/authz` package linked into the `ocliv mcp publish` process.
The publisher serves the OAuth endpoints locally (loopback) and forwards MCP to
the local server; the relay sees a standard `upstream-oauth` upstream and is
**unchanged**.

- Keeps the relay a dumb pipe (best for R1).
- But the auth state lives on the publisher machine, so R11 depends on local
  persistence, and R3's "configured once per relay" becomes "configured per
  publisher". Multi-tenant boundary enforcement is weaker (each publisher is
  its own issuer).
- Publisher footprint grows (issuer key, client store, approval UX).

### C. External-IdP passthrough (Auth0 first)

The relay forwards OAuth to an external AS (Auth0, or any OIDC issuer). The
MCP server is local; the relay validates the IdP's token and forwards MCP.

- Smallest Ocliv code (no issuer of our own).
- **Violates R12** unless a free tier is acceptable; violates the
  "no mandatory external service" rule. Auth0 free tier is $0 but hosted and
  has tenant/MAU limits.
- Best treated as an **optional mode** for operators who already have an IdP,
  not the default.

## Comparison

| Requirement | A relay-side | B publisher-side | C external IdP |
|---|---|---|---|
| R1 relay invariants | preserved (transport untouched) | preserved (relay unchanged) | preserved |
| R2 no separate process | yes (in-process module) | yes (in-process) | yes |
| R3 once per relay | **yes** | no (per publisher) | yes |
| R4 three classes | yes | yes | yes |
| R6 auth default, no fallback | yes | yes | yes |
| R7 proven libraries | yes | yes | yes (IdP) |
| R11 persistent relaunch | **yes** (relay DB) | yes (local state) | yes |
| R12 free | **yes** (self-hosted) | **yes** | only free tier |
| Relay attack surface | grows (isolated module) | unchanged | unchanged |
| Publisher footprint | unchanged | grows | unchanged |
| Extra deployment | none | none | external service |

## Recommendation

**A — shared relay-side authorization module**, with **C as an optional
passthrough mode** (Auth0 evaluated first, since the Skybridge work already
integrated it). Reject B: it fragments the per-relay boundary and makes R11
depend on publisher-local state.

Rationale: A is the only option that satisfies R2, R3, R11, and R12
simultaneously with no new deployment and no cost. The relay already terminates
TLS, holds the enrollment keys, and audits every route decision — adding a
bounded, separately-tested issuer is the smallest change that meets the
product constraint "one command, authenticated endpoint, forever".

## Reusable Go components

| Component | Location | Reuse |
|---|---|---|
| Bounded stdio→HTTP MCP adapter | `internal/mcp/mcp.go` (`Options`, `New`, `Adapter.Start`) | R5: `ocliv mcp publish --stdio -- CMD` wraps this directly; child lifecycle, scrubbed env, body/concurrency caps, fail-closed retire all inherited. |
| MCP JSON-RPC envelope | `internal/mcp/jsonrpc.go` | unchanged. |
| Visitor token / session / CSRF primitives | `internal/access/access.go` | approval-session cookies, CSRF, safe-method checks for the consent screen. |
| Route admission + OAuth path routing | `internal/relay/relay_mcp_ingress.go` | extend `admitPathRoute` with a managed-auth branch. |
| Publication lifecycle (durable route IDs, per-name stability) | `internal/store` + `internal/relay` | R11: route IDs are already stable per host/profile/name. |
| Management-plane audit + key attribution | `internal/store.AuditKey` (schemaV7) | audit client registrations, approvals, denials. |
| Enrollment / identity | `internal/identity` | tunnel keys unchanged; enrollment stays distinct from end-user authorization (R8). |
| CLI dispatch + port alias | `internal/cli/cli_mcp.go` | add `--stdio` and `--auth ocliv-managed`; keep the `mcp PORT` alias. |

New code is limited to `internal/authz/` plus thin wiring.

## Code-edit notes

1. **`internal/authz/` (new)** — four files:
   - `issuer.go`: Ed25519 (or RS256) issuer key persisted in the relay DB;
     JWKS document; token mint/verify via `golang-jwt/jwt/v5` (or
     `lestrrat-go/jwx`); audience + tenant + publication + client claims.
   - `store.go`: client registrations, authorization codes, grants/approvals,
     issuer key. New tables in `schemaV8`.
   - `handlers.go`: PRM (RFC 9728), AS metadata (RFC 8414), `/oauth/authorize`
     (consent + PKCE), `/oauth/token`, `/oauth/register` (RFC 7591),
     `/oauth/revoke`, JWKS. OAuth flow logic on a proven library
     (`ory/fosite` or `go-oauth2/oauth2`) — **no hand-rolled crypto**.
   - `authorizer.go`: admission check — issuer, audience, expiry, tenant,
     publication, client status, scope→tool allowlist.
2. **`internal/store/store.go`** — `schemaV8`: `authz_clients`,
   `authz_codes`, `authz_grants`, `authz_issuer_key`. Forward-only migration;
   rollback note like V7 (binary + DB must match).
3. **`internal/relay/relay_mcp_ingress.go`** — for managed routes, route
   `/.well-known/*` and `/r/<id>/oauth/*` to the authz module instead of the
   upstream; require a valid bearer on `/r/<id>/mcp`; inject an upstream
   identity header and **never forward the external bearer**.
4. **`internal/cli/cli_mcp.go` / `cli_mcp_publish.go`** — add `--auth
   ocliv-managed` (default for C3) and `--stdio`; `--stdio` starts
   `mcp.Adapter` and publishes its loopback address.
5. **`internal/cli/cli_authz.go` (new)** — `ocliv auth list|approve|revoke|
   status`; operator approval/revocation UX; unknown client denied by default.
6. **`internal/cli/cli_status.go`** — show endpoint + auth mode + client/grant
   status.

## Security boundaries

1. The local MCP server stays loopback-only (or a 0600 Unix socket); the relay
   is the only path.
2. The authz module validates the bearer on **every** `/mcp` request; no
   session-only trust.
3. The external bearer is never forwarded upstream; the relay injects a
   relay-minted upstream identity header.
4. Audience is pinned per route (RFC 8707 resource indicator); issuer pinned to
   the relay; tokens short-lived; refresh/rotation via the module.
5. Tenant isolation: a client grant is scoped to one tenant + one publication;
   a client cannot move between routes.
6. Enrollment (tunnel key) ≠ end-user authorization (OIDC grant). No fallback.
7. Unknown/unapproved client → no tool access (deny by default).
8. Consent is explicit; every approval/revocation/issuance is audited with
   `AuditKey`.
9. DCR constrained: allowlisted redirect URIs, PKCE S256 required, no implicit
   grant, no public-client bearer issuance without PKCE.
10. stdio adapter: command/args/dir/env are operator-pinned at launch; no
    remote selection; child kill/wait and body/concurrency caps unchanged.

## Test cases

Unit (`internal/authz`)
- Token mint/verify: signature, `aud`, `iss`, `exp`, `sub`, scope claims.
- Audience isolation: a token for route A is rejected on route B.
- Tenant isolation: a client grant in tenant X is rejected for tenant Y.
- PKCE: missing/invalid `code_verifier` → denied; S256 enforced.
- DCR: registration, duplicate, invalid redirect URI; no implicit grant.
- JWKS: key rotation publishes a new key; old tokens fail closed.

Integration (`tests/integration`)
- **Acceptance**: publish a local MCP server with no OAuth in one command →
  external HTTPS endpoint → no bearer 401 → approved client 200 `tools/list`.
- **R11**: kill the publisher, relaunch the same command → same endpoint, no
  re-enrollment, no re-approval.
- **R5**: `publish --stdio -- CMD` → adapter serves MCP; child killed on
  shutdown; oversize body rejected; no remote command selection.
- **R8**: enrollment key alone cannot call tools; external bearer not forwarded
  (assert the upstream sees the relay identity, not the client bearer).
- **Negative**: unapproved client → 401/403, zero upstream execution; revoked
  client → denied; expired token → denied.
- **Regression**: existing `upstream-oauth` strict-discovery tests unchanged and
  green; legacy MCP version and 2026-07-28 qualified separately.
- **R10**: publish an existing MCP gateway as one upstream; tools/list returns
  the gateway's own tools (no Ocliv-side aggregation).

## Incremental implementation sequence

1. `internal/authz` core (issuer, store, handlers, authorizer) + unit tests;
   no relay wiring yet.
2. `schemaV8` + migration test (with the binary+DB rollback note).
3. Relay wiring: managed routes, admission, bearer validation, upstream
   identity injection.
4. Publisher CLI: `--auth ocliv-managed`, `--stdio`; `ocliv auth` operator UX.
5. Integration: acceptance, R11 relaunch, R5 stdio, negative paths.
6. Optional mode C (Auth0 passthrough) behind the same route shape.
7. MCP-version qualification (legacy vs 2026-07-28) and gateway publication.

## Acceptance criterion

After one-time relay setup and publisher enrollment:

```
ocliv mcp publish 8765
```

produces a stable HTTPS endpoint for a previously unauthenticated local MCP
service. An unknown client gets no tool access; an operator-approved client
gets authenticated access. Relaunching the publisher restores the same
endpoint with no further setup. No external IdP, proxy, or adapter is required,
and the path costs nothing to run.

## Explicitly out of scope

- No implementation until this design is reviewed.
- No change to `upstream-oauth` discovery strictness or its tests.
- No new mandatory container, external service, or per-publisher IdP.
- No claim of zero-configuration public hosting: DNS, reachable public
  ingress, and a hosted relay are still required.
- The IR controller is not the first validation target; use a harmless local
  MCP service with read-only tools.
