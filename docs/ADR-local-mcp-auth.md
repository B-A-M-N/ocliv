# ADR: Authorization for local MCP services

- Status: Proposed — direction approved; tightening pass 2
- Date: 2026-11-11 (revision 2)
- Scope: publishing **local MCP servers that have no native OAuth** without a
  mandatory external IdP, proxy, OAuth server, or per-service adapter — free,
  persistent, one command, deny-by-default.

## Problem

Ocliv must stay a lightweight, self-hostable tunnel for local HTTP services,
MCP servers, and existing MCP gateways. Publishing an MCP service today
requires the upstream to serve standard OAuth discovery (RFC 9728 PRM +
RFC 8414 AS metadata + `/oauth/*`). Local MCP servers do not, so they cannot
be published.

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
    machinery. No arbitrary remote command execution.
R6. Secure auth is the default for remotely published MCP tools; operator
    approval/revocation; unknown client = no tool access; no unauthenticated
    fallback.
R7. RFC 9728 PRM, AS discovery, PKCE, resource indicators (RFC 8707),
    audience isolation, issuer binding, CIMD hardening (SSRF), backward-
    compatible DCR. Proven security libraries; no hand-rolled OAuth crypto.
R8. Route-specific authorization and explicit grants. Validate before
    forwarding; never forward an external bearer to an unauthenticated
    upstream; tunnel enrollment is not end-user authorization.
R9. Preserve MCP semantics (streaming, cancellation). Qualify legacy MCP
    versions and 2026-07-28 separately.
R10. An existing MCP gateway may be published as one upstream; no Ocliv-side
    aggregation/routing/orchestration.
R11. **Persistent endpoint**: relaunching the publisher re-establishes the
    same endpoint with no re-enrollment, re-configuration, or re-approval.
R12. **Free**: the default path requires no paid or hosted service.
R13. **Publication-level boundary first**: the initial implementation
    authorizes at the route/publication level. Per-tool enforcement is out of
    scope until the implementation actually inspects and authorizes MCP tool
    calls (see §Scope limits).

## Selected architecture: shared relay-side authorization module (A)

A new `internal/authz` package inside the relay, configured once per relay.
The relay is the Authorization Server for C3 routes.

```
client -> relay /r/<id>/... -> [authz module] -> local MCP (publisher host)
                                       ^ issuer key / grants (relay DB)
```

Rejected alternatives (kept for the record):
- **B embedded publisher-side module** — fragments the per-relay boundary;
  R11 depends on publisher-local state.
- **C external-IdP passthrough** — violates R12/the no-mandatory-service rule;
  retained only as an **optional** mode (Auth0 evaluated first).

## 1. Operator approval flow (R6, R8)

The relay authenticates the **operator** with the identity it already trusts:
the tenant's enrollment (tunnel) key, which the management plane authenticates
today. OAuth **client registration is not tool access**.

```
1. operator: ocliv mcp publish 8765
   -> relay creates a managed route (mode ocliv-managed), prints endpoint
2. client:   DCR POST /r/<id>/oauth/register  -> client_id (NO access)
3. client:   GET /r/<id>/oauth/authorize      -> pending grant, no code issued
4. operator: ocliv auth pending               -> lists pending clients
   operator: ocliv auth approve <client_id>   -> grant ACTIVE (tenant-scoped)
5. client:   GET /r/<id>/oauth/authorize      -> 302 + code (PKCE)
6. client:   POST /r/<id>/oauth/token         -> access token (aud=route, sub=client)
7. client:   POST /r/<id>/mcp with bearer     -> authorized at publication level
```

- `ocliv auth pending|approve|revoke|list|status` are management-plane
  commands authenticated by the operator's enrollment key and scoped to its
  tenant.
- Approval is **per tenant + per publication + per client**. A client approved
  on route A cannot use the token on route B (audience binding).
- The client's registered metadata (name, logo) is display-only; it never
  grants access.
- Deny by default: an unapproved client gets no code, no token, no tool call.

## 2. Publication-level boundary (R13)

The first implementation enforces **one boundary: the publication**.

- A valid, unexpired, unrevoked token with `aud` = this route, issued to an
  **approved** client, grants access to the route.
- **No per-tool claims, scopes, or tool allowlists are enforced in this
  implementation.** The ADR and the UI must not claim per-tool enforcement.
- Per-tool authorization is a later phase, and only if the implementation
  inspects each MCP `tools/call` (method + params + tool name) and authorizes
  it against a scope→tool policy. Until then, route-level is the honest
  boundary.

## 3. Revocation, durable state, rotation, backup (R11)

- **Immediate grant revocation**: `ocliv auth revoke <client_id>` flips the
  grant to revoked in the relay DB; the authorizer checks grant status on
  **every** request, so revocation is effective immediately (no reliance on
  token expiry).
- **Immediate client revocation**: revoking a client disables its
  registration and all its grants; existing tokens fail closed at admission.
- **Durable state** (`schemaV8`, relay DB): `authz_clients`,
  `authz_grants`, `authz_codes`, `authz_issuer_key`. Survives relay restart and
  publisher relaunch (R11).
- **Issuer key rotation**: `ocliv auth rotate-key`. The relay generates a new
  Ed25519/RS256 key, publishes it in JWKS alongside the old key for a
  configured grace window, then retires the old key. Tokens signed by a
  retired key fail closed. Rotation is audited.
- **Backup/restore**: the issuer key and all authorization state live in the
  relay DB, so the existing `ocliv relay backup`/`restore` must include the
  `authz_*` tables. Restoring a backup without the issuer key invalidates all
  tokens — the restore path must warn and, on request, re-issue a new key.
  Operators must treat the relay DB as a secret (it already holds enrollment
  verifiers).

## 4. Discovery, CIMD/SSRF, issuer binding, PKCE, DCR (R7)

- **Route-scoped PRM** (RFC 9728):
  `/.well-known/oauth-protected-resource/r/<route-id>/mcp` →
  `resource` = the route URL, `authorization_servers` = [route AS metadata].
- **Route-scoped AS metadata** (RFC 8414):
  `/.well-known/oauth-authorization-server/r/<route-id>/oauth` →
  `issuer`, `authorization_endpoint`, `token_endpoint`,
  `registration_endpoint`, `jwks_uri`, `scopes_supported`,
  `code_challenge_methods_supported: ["S256"]`,
  `resource_indicators_supported: true`.
- **Issuer binding**: the AS metadata `issuer` must exactly equal the route's
  expected issuer string; every accepted token's `iss` must equal it. A
  mismatched issuer is rejected before any upstream forwarding.
- **PKCE**: S256 required on every code flow; `code_verifier` checked at token
  exchange; plain/no-verifier rejected.
- **Resource indicators** (RFC 8707): the client sends `resource` = the route
  URL; the token's `aud` is the route URL; a token for another resource is
  rejected on this route.
- **CIMD (client-initiated metadata) hardening**: every field a client supplies
  (redirect URIs, client name, logo_uri, client_uri, software_id, contacts) is
  untrusted. The relay:
  - validates redirect URIs (exact allowlist; reject private/link-local/loopback
    addresses, wildcards, and non-HTTPS schemes except a loopback redirect for
    native clients);
  - **never fetches** client-supplied URLs (no SSRF): no logo/client URI
    retrieval, no metadata URL fetching;
  - stores the metadata for display/audit only.
- **DCR (RFC 7591)**: backward-compatible — the existing `upstream-oauth` DCR
  path and its tests are unchanged; the managed mode implements the same
  `registration_endpoint` shape so existing MCP clients work unchanged.
- **Proven libraries**: `ory/fosite` or `go-oauth2/oauth2` for the flow;
  `golang-jwt/jwt/v5` or `lestrrat-go/jwx` for tokens/JWKS. No hand-rolled
  crypto or token verification.

## 5. Loopback threat model (corrected)

**Loopback is not a security boundary.** A local MCP server bound to
`127.0.0.1` is reachable by every other process on that host.

- The relay's authorization is the gate for **external** access.
- **Local bypass** is a real risk: any local process can reach the MCP server
  directly. Mitigations, in order of strength:
  1. bind the MCP server to a **Unix socket** with `0600` owned by a dedicated
     user (the relay forwards over the socket);
  2. or a network namespace / host firewall rule restricting the port to the
     relay's UID;
  3. or the MCP server validates a **relay-injected per-route credential**
     (a shared secret or a relay-signed JWT) on every request.
- The relay **always** injects an upstream identity header
  (`X-Ocliv-Upstream-Sub` / `X-Ocliv-Route`) and **never** forwards the external
  bearer. A server that does not validate the injected credential is only as
  strong as its local exposure — stated honestly, not papered over.

## 6. Route identity, hijacking, mode changes (R11)

- **Stable route identity**: route IDs are stable per (host, profile, name);
  republishing the same `--name` rebinds the same route.
- **Approval state persists** in the relay DB across publisher restarts and
  relay restarts (R11).
- **Reject route ownership changes**: the publication record binds the owner
  key + tenant. A republish under a different key/tenant for an existing route
  is rejected (hijacking defense) unless the operator explicitly unpublishes
  first.
- **Reject incompatible auth-mode changes**: changing an existing publication's
  auth mode (e.g. `upstream-oauth` → `ocliv-managed`) is rejected. The operator
  must unpublish and republish; the route ID is reissued and the old approvals
  do not carry over.
- **Enrollment ≠ authorization**: a valid tunnel key proves the publisher is
  enrolled; it never grants end-user tool access.

## 7. Preserve upstream-OAuth; stay bounded

- The existing `upstream-oauth` mode, its strict discovery verification, and
  its tests are **unchanged**. `upstream-oauth` remains a first-class mode for
  C2.
- The default deployment is **self-contained**: relay + TLS edge + tunnel;
  no external service, no subscription, no extra process.
- **Explicitly deferred** (do not overengineer the first implementation):
  per-tool permissioning, multi-IdP federation, enterprise IAM/SSO, org-wide
  policies, custom claim mapping.

## Reusable Go components

| Component | Location | Reuse |
|---|---|---|
| Bounded stdio→HTTP MCP adapter | `internal/mcp/mcp.go` | R5: `publish --stdio -- CMD` wraps it; child lifecycle, scrubbed env, caps, fail-closed retire inherited. |
| MCP JSON-RPC envelope | `internal/mcp/jsonrpc.go` | unchanged. |
| Visitor token / session / CSRF | `internal/access/access.go` | consent-session cookies, CSRF, safe-method checks. |
| Route admission + OAuth path routing | `internal/relay/relay_mcp_ingress.go` | extend `admitPathRoute` with a managed-auth branch. |
| Publication lifecycle (stable route IDs) | `internal/store` + `internal/relay` | R11/R13. |
| Management audit + key attribution | `internal/store.AuditKey` (schemaV7) | audit DCR, approvals, revocations, denials. |
| Enrollment / identity | `internal/identity` | operator identity for `ocliv auth`. |
| Backup / restore | `internal/cli` relay backup | must include `authz_*` tables + issuer key. |
| CLI dispatch + port alias | `internal/cli/cli_mcp.go` | add `--auth ocliv-managed`, `--stdio`; keep the alias. |

## Code-edit notes

1. **`internal/authz/` (new)**: `issuer.go` (key, JWKS, mint/verify),
   `store.go` (clients, grants, codes, key), `handlers.go` (PRM, AS metadata,
   authorize, token, register, revoke, jwks), `authorizer.go` (admission:
   issuer, audience, expiry, grant status, tenant, publication).
2. **`internal/store/store.go`**: `schemaV8` (`authz_clients`, `authz_grants`,
   `authz_codes`, `authz_issuer_key`); forward-only; same binary+DB rollback
   note as V7.
3. **`internal/relay/relay_mcp_ingress.go`**: managed routes route
   `/.well-known/*` and `/r/<id>/oauth/*` to the authz module; require a valid
   bearer on `/r/<id>/mcp`; inject upstream identity; never forward the
   external bearer; reject owner/mode changes on republish.
4. **`internal/cli/cli_mcp.go` / `cli_mcp_publish.go`**: `--auth
   ocliv-managed` (default for C3), `--stdio` (starts `mcp.Adapter`).
5. **`internal/cli/cli_authz.go` (new)**: `pending|approve|revoke|list|status`
   and `rotate-key`, authenticated by the operator's enrollment key.
6. **`internal/cli/cli_status.go`**: endpoint + auth mode + client/grant
   status.

## Security boundaries

1. Loopback is not isolation — see §5; the operator must use a Unix socket,
   namespace/firewall, or validate the injected credential.
2. The authz module validates the bearer on **every** `/mcp` request.
3. The external bearer is never forwarded upstream; a relay-minted upstream
   identity header is injected instead.
4. Issuer binding (metadata `issuer` == expected == token `iss`), audience
   binding (token `aud` == this route), PKCE S256, resource indicators.
5. Tenant isolation: a grant is scoped to one tenant + one publication.
6. Enrollment (tunnel key) ≠ end-user authorization. Deny by default.
7. Revocation is immediate (checked per request), not expiry-dependent.
8. CIMD: client-supplied metadata is untrusted; no SSRF; redirect URI
   validation with private-address rejection.
9. Approval/revocation/issuance/rotation are audited with `AuditKey`.
10. stdio adapter: operator-pinned command/args/dir/env; no remote selection.

## Test cases

Unit (`internal/authz`)
- Token mint/verify: signature, `iss`, `aud`, `exp`, `sub`, tenant, route.
- Issuer binding: a token with a wrong `iss` is rejected.
- Audience isolation: a token for route A is rejected on route B.
- Tenant isolation: a grant in tenant X is rejected for tenant Y.
- PKCE: missing/invalid `code_verifier` → denied; S256 enforced.
- DCR: registration, duplicate, invalid redirect URI (private address, wildcard,
  non-HTTPS) → rejected; no implicit grant.
- **SSRF**: a client-supplied `logo_uri`/`client_uri`/metadata URL is never
  fetched (assert no outbound request).
- Revocation: a revoked client/grant is denied on the next request
  immediately.
- Rotation: after `rotate-key`, old-key tokens fail and new-key tokens pass.

Independent security tests (separate package, red-before/green-after)
- Deny-by-default: no approval → no code, no token, no tool call.
- Publication-level boundary: an approved token reaches the upstream; an
  unapproved one does not.
- Upstream credential: assert the upstream never receives the external bearer.
- Owner/mode change: republish under a different key or a different auth mode
  → rejected.
- Backup/restore: restore without the issuer key → tokens invalidated + warn.

Integration (`tests/integration`)
- **Acceptance**: publish a local MCP server with no OAuth in one command →
  external HTTPS endpoint → no bearer 401 → approved client 200 `tools/list`.
- **R11**: kill the publisher, relaunch the same command → same endpoint, no
  re-enrollment, no re-approval.
- **R5**: `publish --stdio -- CMD` → adapter serves MCP; child killed on
  shutdown; oversize body rejected; no remote command selection.
- **Negative**: unapproved client → 401/403, zero upstream execution; expired
  token → denied.
- **Regression**: existing `upstream-oauth` strict-discovery tests unchanged and
  green; legacy MCP version and 2026-07-28 qualified separately.
- **R10**: publish an existing MCP gateway as one upstream; tools/list returns
  the gateway's own tools.

## Bounded implementation plan

**Phase 1 — authentication core (no relay wiring).**
`internal/authz`: issuer + store + handlers + authorizer; `schemaV8`;
independent security tests (above). Library-based flow; no hand-rolled crypto.
*Exit: unit + independent security tests green.*

**Phase 2 — relay wiring.**
Managed routes, admission, bearer validation, upstream identity injection,
owner/mode-change rejection, audit. *Exit: integration admission tests green.*

**Phase 3 — operator + publisher UX.**
`--auth ocliv-managed`, `--stdio`, `ocliv auth *`, `ocliv status`.
*Exit: acceptance + R11 tests green.*

**Phase 4 — external qualification (gate).**
Full flow against the public edge: discovery → DCR → pending → approve →
authorize → token → `tools/list` → `tools/call`; negative paths; R11 relaunch;
backup/restore. **No production deployment until this passes.**

**Phase 5 — optional mode C (Auth0 passthrough)**, then per-tool scopes only
if a concrete need exists.

## Acceptance criterion

After one-time relay setup and publisher enrollment:

```
ocliv mcp publish 8765
```

produces a stable HTTPS endpoint for a previously unauthenticated local MCP
service. An unknown client gets no tool access; an operator-approved client
gets authenticated access at the publication level. Relaunching the publisher
restores the same endpoint with no further setup. No external IdP, proxy, or
adapter is required, and the path costs nothing to run.

## Explicitly out of scope (first implementation)

- Per-tool permissioning/scopes (deferred; not claimed).
- Multi-IdP federation, enterprise IAM/SSO, org-wide policy, custom claims.
- Any change to `upstream-oauth` discovery strictness or its tests.
- Any new mandatory container, external service, or per-publisher IdP.
- Zero-configuration public hosting claims: DNS, reachable public ingress, and
  a hosted relay are still required.
- The IR controller as the first validation target — use a harmless local MCP
  service with read-only tools.
