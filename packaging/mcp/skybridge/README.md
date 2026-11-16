# Ocliv MCP Hosting (Skybridge)

This project is a **real Skybridge MCP server + React MCP view source package**, not a prompt, visual mockup, or ping fixture. It deliberately does not use Lovable, devdesktop, Kontrol, or the user's PC.

## Current state

The Ocliv control adapter, publisher controller, approvals, and their tests run under Node **22+** (qualified on v22.22.3; `engines` requires `>=22`). The Skybridge server and React view target Skybridge 2.1.0. The signed management adapter matches the relay implementation (routes and JSON contracts below verified against `internal/relay` source plus 81 green unit tests). Read-only management calls through an authenticated ChatGPT/Auth0 connector were reported working on 2026-11-02, but no dated, redacted request/response evidence is on file in this checkout, so that integration is classified **UNVERIFIED** until re-demonstrated. Deployment and ChatGPT UI registration remain operator actions (see SPEC hard gates).

## MCP tools

| Tool | Behavior | Permission |
|---|---|---|
| `get-ocliv-status` | Read actual Ocliv management status | `ocliv:read` |
| `list-publications` | Read endpoint list, render an inline React view | `ocliv:read` |
| `verify-publication` | Real MCP initialize, initialized, tools/list handshake; no fake green status | `ocliv:read` |
| `request-approval` | Create an `AWAITING_OPERATOR` request; only the owner-only local approval socket can approve or deny it | `ocliv:write` |
| `publish-service` | Publish or reattach an allowlisted loopback service | `ocliv:write` plus approval |
| `resume-service` | Restart a stopped publisher and rebind its retained route identity | `ocliv:write` plus approval |
| `stop-service` | Gracefully stop its publisher and retain the route offline | `ocliv:write` plus approval |
| `unpublish-service` | Stop its publisher and revoke the exact publication | `ocliv:write` plus approval |

All tools additionally require the verified OAuth subject to match `OCLIV_ALLOWED_SUBJECTS`. Credentials are never placed in MCP tool output or UI state. The OAuth provider must issue access tokens with the configured audience and scopes.

Publisher targets are configured on the publisher host with
`OCLIV_SERVICES_JSON`. Each entry fixes a name, a loopback `/mcp` URL, and an
explicit auth mode (`ocliv-managed` or `upstream-oauth`); remote tool callers
can select only one of those entries. `OCLIV_PROFILE` may select the named
enrollment profile used by spawned publishers. A stop closes the lease and
keeps the stable route offline; resume republishes the same owner/name
identity. Unpublish is the separate destructive action.

Write tools remain disabled unless `OCLIV_WRITE_ENABLED=true` and
`OCLIV_APPROVAL_SOCKET` names a local Unix socket. Review requests with
`node src/operator-approval-cli.mjs list`, then approve or deny the exact ID
with the same CLI. The socket is mode `0600`; decisions and credentials never
pass through MCP tool arguments. The MCP surface exposes request IDs and
status only.

## Build and run on a hosted development environment

Requires Node **22+**, npm, an actual Ocliv **management** API accessible from the deployment, and a compatible OAuth identity provider that issues JWT access tokens and publishes OAuth discovery + JWKS.

```sh
npm ci                         # when a lockfile has been generated in a networked environment
# or on a fresh workspace without a lockfile:
npm install
cp .env.example .env          # configure all required variables securely
npm test
npm run check
npm run dev                    # local DevTools; localhost:3000/mcp
npm run deploy                 # Alpic CLI authorization + hosted deployment required
```

Before running, set `SERVER_URL` to the Skybridge app origin, `OCLIV_PUBLIC_RESOURCE_URL` and `OCLIV_OAUTH_AUDIENCE` to the exact published route URL, plus `OCLIV_OAUTH_ISSUER`, `OCLIV_ALLOWED_SUBJECTS`, `OCLIV_RELAY_URL`, and the publisher key settings. Enable `OCLIV_WRITE_ENABLED=true` only after staging qualification. On Alpic, set these as **server-side environment secrets**, not frontend variables. **Never reuse the Ocliv management key as a public MCP probe token.**

Important: `OCLIV_CONTROL_URL` is the HTTPS origin of Ocliv's management API. It is **not** a published `/r/.../mcp` tool endpoint. That published endpoint is what `verify-publication` can probe, if returned by the management API and in the exact hostname allowlist.

If Ocliv has no network-reachable management API yet, that is a hard integration blocker: hosting a Skybridge UI cannot create the missing relay-side management interface or make a private machine reachable automatically.

## Security tests

`npm test` runs the adapter tests with an in-process fake **test HTTP transport** (not a fake production server). It covers invalid configuration, denial of unauthorized subjects/scopes, path injection, credential exclusion, publish/unpublish confirmation, redirects, true JSON-RPC MCP handshake, and refused probe auth. Tests never contact live services or change Ocliv state.

## Deployment and ChatGPT registration

Use Skybridge/Alpic to create a public HTTPS `/mcp` endpoint. Configure an OAuth identity provider; it is **not appropriate to select No Authentication** for a hosting manager. In ChatGPT, custom app creation must be available to the workspace, otherwise registration cannot be completed from the app source alone. Existing devdesktop integration remains untouched.

## Known issues / required matching work

1. Ocliv's control-plane routes are matched (`src/core/ocliv-native.mjs` + tests); do **not** guess routes in production — extend only against the real relay.
2. Dependency installation/build runs on Node 22+ (qualified on v22.22.3; full suite green).
3. Complete deployment with Alpic, then the end-to-end OAuth/host/MCP qualification gates in SPEC.
4. Production write scopes additionally require the single-use, user-bound, expiring approval workflow (`request-approval` + operator-private code channel); text confirmation alone is **not** proof of human approval. Keep `OCLIV_WRITE_ENABLED=false` until that channel is provisioned.

See [SPEC.md](SPEC.md) for design, trust boundaries and release gates.
