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
- `publish-mcp` (mutating, open-world; authenticated-only access)
- `unpublish-mcp` (destructive, open-world)
- `verify-publication` (read-only, public network contact)

## Security / authority boundaries
1. MCP caller → OAuth JWT with issuer, audience, scopes, **operator subject allowlist**. No anonymous management tools.
2. MCP handler → trusted Ocliv management API, via static HTTPS origin + explicit exact API paths + server-only management bearer secret.
3. Management response → normalized publication records; discard unknown fields, credentials, internal addresses.
4. Published MCP probe → exact public hostname allowlist, HTTPS only, no redirects, separate optional probe bearer. Never send management credential to a public endpoint.
5. No arbitrary shell execution, local process access, remote PTY, or coupling to Kontrol, devdesktop, or Lovable.
6. Writes disabled by default; enable only after contract/staging verification. Fail closed on missing configuration, unknown JSON contracts, network failure, failed OAuth, or missing explicit confirmation.

## Ocliv control API contract (REQUIRES REAL VERIFICATION)
The Ocliv control plane API could not be read during this build. No endpoint route is invented or assumed correct: each method's path must be set from the deployed Ocliv management API.

| Operation | HTTP method | Required response |
|---|---|---|
| Status | GET configured path | `{ "status": "healthy" }` (actual status may differ) |
| List | GET configured path | `{ "publications": [{ "id": "...", "status": "...", "publicUrl": "https://...", "serviceId": "...", "label": "..." }] }` |
| Get | GET configured path with `{id}` | Single publication object |
| Publish | POST configured path | `{ "publication": { "id": "...", ... } }` |
| Unpublish | DELETE configured path with `{id}` | `{ "deleted": true }` or `{ "success": true }` |

Publish input: `{ "serviceId": "...", "label": "...", "kind": "mcp", "access": "authenticated" }`.

This is an **adapter contract**, not a claim that the current Ocliv daemon implements these routes or payloads. Integration must adapt to real Ocliv responses, with contract tests, before any live write is authorized.

## Hard release gates
- [x] Management adapter, boundary rules, pure Node tests
- [x] Skybridge 2.1.0 server/view source assembled
- [ ] Skybridge dependency installation with Node >=24, TypeScript compilation and build
- [ ] OAuth provider configured, verified issuer/audience/scope, unauthorized MCP request returns 401
- [ ] Confirm actual Ocliv management API endpoints and payload contracts; live read-only smoke test
- [ ] Verify live publish/unpublish in an isolated staging service after operator approval
- [ ] Verify published endpoint initialize/initialized/tools/list with real auth
- [ ] Deploy to Alpic with server-only secrets; inspect logs and `/mcp` and playground
- [ ] Register the deployed URL in ChatGPT, contingent on workspace support

Do not claim READY or DEPLOYED unless every applicable gate is proven.
