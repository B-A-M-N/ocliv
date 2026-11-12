# ADR: Authenticating local MCP servers that lack native OAuth

- Status: Proposed — design only, no implementation
- Date: 2026-11-11
- Scope: how to publish local MCP servers (e.g. `/opt/ir-controller`) that
  have no native OAuth discovery, without weakening Ocliv's strict upstream
  OAuth verification.

## Context

Ocliv's purpose is secure publication of MCP services from our machines to
external orchestrators (ChatGPT and other MCP clients). Today a publishable MCP
server must serve standard OAuth 2.0 discovery and protocol endpoints:

- `/.well-known/oauth-protected-resource/mcp` (RFC 9728)
- `/.well-known/oauth-authorization-server` (RFC 8414)
- `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/revoke`

The relay forwards those paths verbatim to the publisher's upstream
(`internal/relay/relay_mcp_ingress.go:395-433`) and validates the AS metadata
strictly. Local MCP servers have no OAuth discovery, so they cannot be
published. That is a core requirement, not an edge case: the value is exposing
*our own* local tools, most of which will never grow an OAuth stack.

Hard constraints:

- Strict upstream OAuth discovery must not be weakened.
- The relay's "the relay performs no OAuth itself" property should not be
  casually reversed — it is what keeps the relay a dumb, auditable pipe.
- Prefer established, maintained OAuth/OIDC components over a hand-rolled AS.

## Decision drivers

- External clients require RFC 9728 PRM + RFC 8414 AS metadata,
  authorization-code + PKCE, and RFC 7591 dynamic client registration.
- Client registration, consent, audience validation, token lifecycle,
  least-privilege tool authorization, upstream identity, and local-bypass
  resistance must each be answered explicitly.
- Minimal operational footprint on the publisher machine.
- No change to the relay's security model.

## Approach A — publisher-side authentication adapter

A gateway on the publisher machine fronts the local MCP server:

```
external client -> relay /r/<id>/... -> adapter (public) -> local MCP (127.0.0.1)
                                       |  PRM + AS metadata
                                       |  /oauth/authorize|token|register|revoke
                                       |  token validation on /mcp
                                       +-> upstream identity header -> MCP server
```

The adapter is the upstream the relay already understands; **no relay change**.
The local MCP server stays unmodified and loopback-only.

### A1 — thin gateway in front of an established IdP (recommended)

- Established AS/IdP: **Keycloak**, **Authentik**, **Zitadel**, or
  **ory/hydra** (API-only OAuth2 AS). These own client registration, consent,
  token issuance/lifecycle/rotation/revocation, and JWKS.
- A thin gateway (Go, ~300-500 LOC, or a reverse proxy with a JWT filter) serves
  the PRM + AS metadata, proxies `/oauth/*` to the IdP, and validates the IdP's
  access token on `/mcp` before proxying to the loopback MCP server.
- Upstream identity: the gateway injects a header (e.g. `X-Ocliv-Upstream-Sub`)
  derived from the validated token; the MCP server trusts it because it is
  loopback-only and the gateway is the sole caller.
- Local bypass: the MCP server binds 127.0.0.1 only; the gateway is the only
  process that can reach it. A 0600 Unix socket is even stronger.
- Least-privilege tools: the gateway maps token scopes/claims to tool allowlists
  (e.g. `ir:blast` vs `ir:emulate`) before proxying.

### A2 — self-contained adapter on an OAuth library

- Build the adapter directly on **ory/fosite** (maintained Go OAuth2 framework)
  or an equivalent library, serving discovery + authorize/token/register itself.
- Fewer moving parts than A1, but we own the AS: client storage, consent screen,
  token signing, rotation, and revocation become our code. This is "building an
  authorization server" with training wheels — the driver prefers established
  components, so A1 is favored unless an IdP is deemed too heavy.

## Approach B — relay-managed OAuth

The relay itself serves PRM + AS metadata and the `/oauth/*` endpoints for
`managed-oauth` routes, authenticates the client (via an IdP or local
credentials), and forwards MCP to the publisher's loopback upstream with an
injected identity header.

```
external client -> relay (AS + MCP forward) -> local MCP (127.0.0.1)
```

### Consequences

- The relay stops being a dumb pipe: it becomes a security-critical OAuth issuer.
  A bug in the relay's OAuth is full public exposure across every route.
- Client registration/consent/token storage/rotation become relay features
  (new tables, new crypto, new attack surface, new upgrade coupling).
- The local MCP server must trust the relay's injected header; the relay is the
  sole caller, so this is acceptable, but it inverts the current trust model.
- One AS for all routes (operational simplicity) at the cost of one very
  high-value target.

## Comparison

| Dimension | A1 thin gateway + established IdP | A2 self-contained adapter | B relay-managed OAuth |
|---|---|---|---|
| Relay changes | none | none | large (new AS, tables, crypto) |
| New security-critical component | gateway (thin) + established IdP | adapter (owns AS) | the relay itself |
| Client registration / consent | IdP (mature) | our code | our code |
| Token lifecycle / rotation / revocation | IdP (mature) | our code | our code |
| Audience / issuer validation | IdP + gateway | adapter | relay |
| Least-privilege tools | gateway scope->tool map | adapter | relay |
| Upstream identity | gateway header | adapter header | relay header |
| Local-bypass resistance | loopback-only MCP | loopback-only MCP | loopback-only MCP |
| ChatGPT / MCP client compatibility | standard OAuth discovery | standard OAuth discovery | standard OAuth discovery |
| Operational footprint | IdP + gateway | gateway only | relay only |
| Time to first secure publish | medium (IdP setup) | medium-small | large |
| Attack surface added | small (thin gateway) | medium | large (relay) |

## Security boundaries (both approaches)

1. The MCP server binds loopback (or a 0600 Unix socket); never `0.0.0.0`.
2. The OAuth layer is the only path to the MCP server; it validates the token
   on every `/mcp` request, not just at login.
3. The MCP server independently validates the injected upstream identity, or
   the OAuth layer is provably the sole caller and the MCP server is
   loopback-only.
4. Audience is pinned to the route; issuer is pinned to the AS; tokens are
   short-lived; refresh/rotation is the IdP's job (A1) or ours (A2/B).
5. Dynamic client registration is constrained: allowlisted redirect URIs, PKCE
   required, no implicit grant.
6. Consent is explicit and auditable.
7. Tool authorization is least-privilege (scopes/claims -> tool allowlist).
8. No external bearer is ever forwarded upstream verbatim.
9. Strict upstream discovery is unchanged; `upstream-oauth` stays the default
   and any new mode is explicit and separate.

## Recommendation

**Approach A1**: a thin publisher-side gateway in front of an established IdP
(Keycloak / Authentik / Zitadel, or ory/hydra for an API-only AS). It keeps the
relay a dumb pipe, puts client registration/consent/token lifecycle in
maintained components, and preserves strict discovery. A2 is the fallback if
standing up an IdP is unacceptable. **Do not** choose B unless a concrete
requirement forces a single centralized AS; the relay's current "no OAuth"
property is a security feature, not a limitation.

## Explicitly out of scope (this ADR)

- No implementation of any new auth mode.
- No change to `upstream-oauth` discovery or its strictness.
- No selection of a specific IdP product until a concrete upstream is chosen.

## Open questions

1. Which IdP (Keycloak vs Authentik vs Zitadel vs hydra) for the first real
   upstream?
2. Does the first real upstream need per-tool scopes, or is route-level access
   enough?
3. Who operates the IdP — the relay host, or each publisher machine?
4. Is a Unix-socket upstream acceptable to the relay's forwarding, or must it
   stay TCP loopback?
