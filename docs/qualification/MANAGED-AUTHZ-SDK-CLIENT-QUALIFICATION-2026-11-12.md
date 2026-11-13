# Managed auth — real MCP SDK client qualification (2026-11-12, pass 3)

Third external pass: the preceding passes drove the flow with curl.
This pass closes that gap — the OFFICIAL Python MCP SDK client
(`mcp` package, `mcp.client.auth.oauth2`) drove the complete flow
against the relay over the public funnel edge, including the browser
consent leg in a real browser.

## Setup

```
code        : release-hardening tree (f0a7196 + the per-route throttle fix)
binary      : sha256 919e9c15febc83372540f13e515688e0419c9e5df56ac0dc45b09f3af0b2e3fe
staging DB  : /tmp/ocliv-qual3 (fresh, isolated; production untouched)
public edge : https://pop-os.tail8d285a.ts.net (trusted cert)
route       : YuhlMeqLxi_36JDDoqczpw (published via the bare managed alias)
harmless upstream: loopback qual_ping fixture with an execution counter
```

## What the SDK did, unprompted

Driving `ClientSession` at the public route, the SDK on its own:

1. sent an unauthenticated request, read the **401 `WWW-Authenticate` challenge**;
2. fetched the challenge's `resource_uri` (the route-scoped RFC 9728 PRM);
3. followed PRM to the route's RFC 8414 AS metadata;
4. registered itself via **DCR** (its own `client_id`, loopback redirect);
5. built the authorize URL with **PKCE S256 + state + resource**;
6. (browser leg) rendered the relay's consent page — a real Chrome
   session submitted the operator's pairing credential;
7. exchanged the code at the token endpoint and **received an access
   token AND a refresh token**;
8. completed `initialize`, `tools/list` → `["qual_ping"]`, and
   `tools/call` → `pong:ocliv-qual-1`.

The upstream execution counter moved exactly once (the authorized
`tools/call`); every unauthorized step moved it zero.

## Other gates re-verified on the live path this pass

| Gate | Result |
|---|---|
| Unpublish with durable grant retirement (P5-7) | publication row removed; all 4 grants `active` → `revoked`; route → 404 |
| Cross-route throttle contention (finding B extras) | new: flood on route A no longer denies route B (key now carries the route); regression `TestAuthzThrottleScopesPerRoute` red-before (429) / green-after (201) |

## Still not verified

- The TypeScript MCP SDK client (only the Python SDK was driven here).
- Refresh exercised by the SDK itself across a real 1-hour window
  (the SDK holds the refresh token; the grant's rotation behavior is
  separately qualified over the public path in pass 2).
- ChatGPT/registration flows, CIMD, and production promotion.
