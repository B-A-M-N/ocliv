# Management MCP: identity provider requirements ($0 path)

Skybridge (`src/server.ts`) refuses to start without `OCLIV_OAUTH_ISSUER`,
`OCLIV_OAUTH_AUDIENCE`, and `SERVER_URL` (all HTTPS). Token verification is
JWKS-only (`node_modules/skybridge/dist/server/auth/verify.js` via
`createJwksVerifier`). There is no password, static-token, or HS256 mode,
and adding one would weaken the boundary the server exists to enforce.

## Why the IdP cannot be eliminated with existing infrastructure

- Ocliv relay: Ed25519 tunnel identities, no JWT issuance. Not an OIDC issuer.
- Lab fixture (`tests/staging/mcp-oauth-lab`): HS256, no `jwks_uri`.
  The server throws at startup against it. Promoting it to production would
  be a lab credential minted into a production trust root. Prohibited.
- Any loopback mini-issuer that auto-approves logins mints operator-bound
  tokens for anyone who completes the flow: anonymous access with extra
  steps. Prohibited.
- Conclusion: a third-party OIDC issuer is mandatory. The cheapest compliant
  form is a free-tier hosted issuer (operator signup, ~10 minutes, $0).

## Exact issuer checklist (all mandatory)

1. Public HTTPS issuer with OIDC/OAuth discovery serving `jwks_uri`.
2. Asymmetric JWT signatures (RS256/ES256). No shared-secret mode exists.
3. `aud` bindable to the Skybridge public URL (`OCLIV_OAUTH_AUDIENCE`).
4. Custom scopes mintable: `ocliv:read` and `ocliv:write` (scope-gated per
   tool in `src/core/ocliv.mjs:authorize`, unit-tested). Consumer-Google-style
   issuers that only mint their own scopes are incompatible without a code
   change to scope mapping.
5. PKCE S256 on the code flow (enforced by the IdP; relay + server pass it
   through untouched).
6. Client onboarding ChatGPT can use: DCR (`registration_endpoint` in
   discovery, passed through to ChatGPT) OR a pre-registered client whose
   ID/secret ChatGPT's custom-MCP form accepts.
7. `sub` stable per operator; operator allowlists it via
   `OCLIV_ALLOWED_SUBJECTS` (subject-gating verified live, 11/11 checks).

## $0 candidates (verified against primary docs via direct fetch, 2026-11-02)

- **Auth0 Free — PRIMARY.** All checklist items verified in Auth0 docs:
  - $0, no card, 25k MAU. Custom API scopes per API verified; pricing
    implies baseline API limits on Free ("higher API limits" is the paid
    uplift) — our user auth-code flow uses zero M2M tokens.
  - RFC 8707 `resource` supported via the "Resource Parameter Compatibility
    Profile" tenant toggle (+ "Include Issuer in Authorization Responses"
    toggle), Dashboard → Settings → Advanced. `resource` then defines the
    token audience; API identifiers must be absolute URIs — our MCP route
    URL qualifies verbatim. Standard `/authorize` flow + refresh grant.
  - DCR for MCP: dedicated guide, tenant toggle (default off), DCR-created
    apps get per-API "Default Permissions for Third-Party Applications"
    (baseline APIs + scopes — this is where `ocliv:read`/`ocliv:write`
    are granted). No plan gate documented on the DCR toggle (only the
    ACL hardening is Enterprise-only); confirm in console.
  - RS256 default + `jwks_uri` discovery are Auth0-standard mechanics;
    verify live against the tenant discovery doc after signup.
  - `sub` (`auth0|<id>`) is stable per user for `OCLIV_ALLOWED_SUBJECTS`.
- **Logto Cloud free tier — RULED OUT.** Per operator correction, Free
  lacks API resources and third-party OAuth apps — the exact two features
  this integration needs. (Docs research had wrongly attributed Pro
  allowances to Free.)
- **ZITADEL Cloud free tier — FALLBACK.** Verified: $0, 25k DAU/mo. Gaps:
  no DCR page in docs, scopes are `urn:zitadel:*`-namespaced roles —
  free-form `ocliv:read` minting unproven, likely needs a code change.
- Ruled out: Google/Microsoft consumer (no custom scopes, no DCR),
  any password/static-token scheme, the lab fixture, self-hosted IdPs.

## Minimal operator actions (pick one issuer)

1. Sign up at auth0.com (Free, no card). Create tenant (region near you).
2. Dashboard → Applications → APIs → Create API. Identifier = the exact
   future Skybridge public route URL (I supply it after first publish;
   MUST be an absolute URI). Name `ocliv-mgmt`.
3. In the API → Permissions tab, add `ocliv:read` and `ocliv:write`.
4. Same API → Settings → Default Permissions for Third-Party
   Applications: Authorized for User-Delegated Access, select both scopes.
5. Dashboard → Settings → Advanced: enable DCR toggle,
   "Resource Parameter Compatibility Profile", and
   "Include Issuer in Authorization Responses". Save.
6. Create your user (User Management → Users), note your `user_id`
   (`auth0|…`) for `OCLIV_ALLOWED_SUBJECTS`.
7. Hand back: tenant domain, API identifier (= audience), your `sub`.
   If the DCR toggle is plan-gated in console, stop and tell me —
   fallback is a pre-registered Native app with exact ChatGPT callback
   URLs in its allowlist (standard feature, still $0).

## Then the publisher host does alone (no further operator steps)

1. Set `OCLIV_OAUTH_ISSUER/AUDIENCE/SERVER_URL` (SERVER_URL placeholder OK).
2. `ocliv mcp publish --local http://127.0.0.1:PORT/mcp --auth
   upstream-oauth --name ocliv-mgmt` → learn stable route URL (route IDs are
   stable per host/profile/name; republish keeps the ID).
3. Set `SERVER_URL` to the route URL, restart Skybridge, republish.
4. Verify public discovery → JWKS → auth → initialize/tools/list/read-only
   calls; deliver the ChatGPT URL + Default `ocliv:read`, Base empty,
   `offline_access` only if refresh is wanted.
