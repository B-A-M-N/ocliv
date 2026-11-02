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

- **Logto Cloud free tier — PRIMARY.** Verified in docs:
  - Free plan exists (billing page: upgrade triggers only past quota).
    Use a production Free tenant, not a dev tenant (dev tenants delete
    user accounts after 90 days; production Free/Pro/Enterprise persist).
  - API resources are RFC 8707 indicators with free-form permissions
    (e.g. `read`/`write`); mint literally `ocliv:read`, `ocliv:write` as
    one API resource whose identifier = Skybridge public URL. Audience
    restriction matches checklist item 3 exactly.
  - "Dynamic app (CIMD)" is built for MCP: OAuth clients connect with no
    pre-registration; client uses a public HTTPS URL as `client_id`
    (IETF draft CIMD). No DCR endpoint needed on either side.
  - Quotas (3 free API resources — we need 1; 50K tokens) dwarf this
    deployment's usage. Confirm exact MAU/token numbers in console.
  - Still to verify at runtime (needs the account): PKCE S256 enforcement
    (OAuth 2.1 standard; expected) and refresh-token issuance.
- **ZITADEL Cloud free tier — FALLBACK.** Verified: $0, 25k DAU/mo, custom
  domain. Gaps: no DCR page in docs (likely console/API app creation only),
  and scopes are `urn:zitadel:*` namespaced roles — free-form `ocliv:read`
  minting is unproven and likely needs a scope-mapping code change.
- **Auth0 free tier — FALLBACK.** RS256 + custom API scopes/audience via
  API config fit, but open RFC 7591 DCR is absent: needs a pre-registered
  client, viable only if ChatGPT's form accepts static client ID/secret.
- Ruled out: Google/Microsoft consumer (no custom scopes, no DCR),
  any password/static-token scheme, the lab fixture, self-hosted IdPs
  (new heavyweight components against the $0/simplicity mandate).

## Minimal operator actions (pick one issuer)

1. Sign up free tier; create tenant/project.
2. Create API/resource with identifier = future Skybridge public URL;
   define scopes `ocliv:read`, `ocliv:write`; grant the operator both.
3. Confirm discovery URL + `jwks_uri` + (DCR endpoint XOR static client).
4. Hand back: issuer URL, audience, subject (`sub`), client ID/secret if
   static. Never paste tokens into chat; values go to server env only.

## Then the publisher host does alone (no further operator steps)

1. Set `OCLIV_OAUTH_ISSUER/AUDIENCE/SERVER_URL` (SERVER_URL placeholder OK).
2. `ocliv mcp publish --local http://127.0.0.1:PORT/mcp --auth
   upstream-oauth --name ocliv-mgmt` → learn stable route URL (route IDs are
   stable per host/profile/name; republish keeps the ID).
3. Set `SERVER_URL` to the route URL, restart Skybridge, republish.
4. Verify public discovery → JWKS → auth → initialize/tools/list/read-only
   calls; deliver the ChatGPT URL + Default `ocliv:read`, Base empty,
   `offline_access` only if refresh is wanted.
