# Ocliv MCP Hosting — implementation specification

## Problem, user, value proposition
Provide one conversational, authenticated control surface for operating MCP services already enrolled in Ocliv. The operator should be able to inspect public endpoints, publish a known service safely, remove an endpoint with confirmation, and verify an actual MCP protocol handshake. This is **not** a replacement for the Ocliv relay, nor a wrapper around a ping fixture.

## Why an MCP app?
The assistant can turn an instruction such as "show my published MCP servers and verify the broken one" into read-only tool calls and render a concise list with interactive verification. Publishing or unpublishing requires explicit approval. The host does not know Ocliv's enrolled services, service lifecycle, or network reachability without a real backend.

## UX flows
- Inspect: user asks for status or publications → tool reads management control API → view lists endpoints.
- Verify: user asks to check a publication or clicks Verify MCP → tool retrieves its published URL from control API → checks exact allowlist → sends initialize / notifications/initialized / tools/list → reports result.
- Publish: user identifies an **existing enrolled** Ocliv service → confirms PUBLISH → tool sends controlled authenticated-access publish to Ocliv management API → reports actual upstream acknowledgement.
- Unpublish: user identifies publication ID → confirms same ID → tool invokes delete on management API → only reports success if control API explicitly confirms it.

## Skybridge tools and view
- `get-ocliv-status` (read-only)
- `list-publications` (read-only; `list-publications.tsx` view)
- `get-publication` (read-only, exact route ID)
- `verify-publication` (read-only, public network contact)
- `request-approval` / `list-approvals` (single-use human-approval grants; metadata only in listings, never codes)
- `publish-service` / `unpublish-service` (require redeemed approval + OCLIV_WRITE_ENABLED=true; disabled by default)
- Approval trust note: the code is returned in the tool result, which the
  model can read — so the gate is operator visibility in the chat transcript
  (human sees each request and can stop it) plus single-use action binding,
  scope gating, allowlist, and default-off writes. It is an audit/consent
  trail, not out-of-band human consent.

## Security / authority boundaries
1. MCP caller → OAuth JWT with issuer, audience, scopes, **operator subject allowlist**. No anonymous management tools.
2. MCP handler — Ocliv signed management API (`ocliv-mgmt-v1` Ed25519 over the bare relay origin + exact paths) via the publisher-side agent key, which never leaves this host. No static management Bearer token exists.
3. Management response → normalized publication records; discard unknown fields, credentials, internal addresses.
4. Published MCP probe → exact public hostname allowlist, HTTPS only, no redirects, separate optional probe bearer. Never send management credential to a public endpoint.
5. No arbitrary shell execution, local process access, remote PTY, or coupling to Kontrol, devdesktop, or Lovable.
6. Writes disabled by default; enable only after contract/staging verification. Fail closed on missing configuration, unknown JSON contracts, network failure, failed OAuth, or missing explicit confirmation.

## Ocliv control API contract (VERIFIED against the real relay)
Management is Ocliv's signed Ed25519 protocol (`ocliv-mgmt-v1`), not the
earlier assumed Bearer/JSON control API. The native adapter
(`src/core/ocliv-native.mjs`) signs every call with the publisher's
enrolled agent key (`OCLIV_AGENT_KEY_FILE`, `key-`-prefixed key ID) and
maps relay responses to typed records. Live-verified against a real
relay through the public Funnel edge (2026-11-02).

| Operation | HTTP method | Required response |
|---|---|---|
| Status | local composition (relay reachability + list) | `{ relay, relayReachable, publications: {active,pending,revoked}, listError }` — never tunnel liveness |
| List | `GET /v1/agent/mcp-routes` (signed) | `{ publications: [{ route_id, external_host, profile, pub_name, lease_id, created_at, revoked_at, verified_at, lease_state, session_live }] }` → `{ id, label, profile, state, leaseState, sessionLive, publicUrl, leaseId }` (durable state and relay-observed reachability are separate fields; active ≠ reachable) |
| Get | filter of owned list by exact route ID | Single typed publication; `NOT_FOUND` otherwise |
| Verify | public OAuth+MCP handshake (no relay key used) | discovery + 401-on-anonymous required; the registration endpoint is advertised but never exercised by verify (DCR is onboarding-only, not part of verification); with a resource-bound `OCLIV_VERIFY_TOKEN` (JWT aud = publication URL), authenticated initialize + notifications/initialized + tools/list; without a bound token, `OAUTH_REQUIRED`, never verified, and no authenticated probe is sent |
| Unpublish | `DELETE /v1/agent/mcp-routes/{id}` (signed, one-time nonce) | `{ status: "deleted" }` + re-list must not contain the id (`UNCONFIRMED` otherwise) |

Publication `state` is durable publication state only
(`active` = verified binding, `pending` = unverified, `revoked` =
tombstoned). There is deliberately no publish operation: publishing
needs a live local publisher lifecycle, not a management call.

## Hard release gates
- [x] Native signed management adapter, boundary rules, 81 Node tests green (Node v22.22.3)
- [x] TypeScript compilation (`tsc --noEmit` clean) and `skybridge build` (server)
- [x] Public OAuth/MCP handshake against the live Funnel edge with real JWT (2026-11-02: PRM 200 exact resource, anon 401, `tools/call ping` → `pong:ocliv-oauth-lab-1`, revoked JWT → 401)
- [ ] Signed list/status/verify through the Skybridge connector against the real relay — reported 2026-11-02 but no dated, redacted evidence on file: UNVERIFIED until re-demonstrated
- [ ] React view bundle (`skybridge/vite` subpath missing from installed skybridge 2.1.0 — scaffold/SDK skew, view optional)
- [ ] OAuth provider configured for the hosted app, unauthorized MCP request returns 401
- [ ] Live unpublish approval test in an isolated staging service (adapter implemented + unit-tested, never run live)
- [ ] Deploy with server-only secrets; inspect logs and `/mcp` and playground
- [ ] Register the deployed URL in ChatGPT, contingent on workspace support

Do not claim READY or DEPLOYED unless every applicable gate is proven.
