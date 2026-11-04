# Composed demo — Ocliv, Metis, and Locus

Contract for the reproducible three-project demonstration in
[`tests/staging/composed/`](../tests/staging/composed/README.md). It
records the topology, which project owns which boundary, the request and
auth paths, and exactly what the committed harness proves — and what it
does not.

The harness publishes a **real Metis MCP server** through a **real Ocliv
relay** behind a local TLS edge, and proves the authenticated route
contract end to end on one host. The Locus inference leg is present in
the architecture but is **not exercised**: Locus is an external,
operator-gated dependency.

## Topology

```
visitor / MCP client
  │  Authorization: Bearer <RS256 JWT>
  │  MCP-Protocol-Version: 2024-11-05
  ▼
Ocliv public TLS edge            https://<public-host>:<edge-port>
  │  (Caddy in deployment; socat stand-in in the harness)
  ▼
Ocliv relay                      loopback, path route /r/<route-id>/mcp
  │  exact-Host admission, route/lease binding, byte-identical forward
  ▼
Ocliv agent                      outbound WSS + yamux tunnel (publisher side)
  │
  ▼
Metis MCP server                 http://127.0.0.1:<metis-port>/mcp
  │  validates iss/aud/scope itself
  │
  └─► Metis Muse worker ──► Locus (inference gateway) ──► model provider
                              e.g. http://127.0.0.1:<locus-port>/v1
```

Locus is **behind** Metis, not in front of the Ocliv edge. The Ocliv edge
never talks to Locus, and a request can reach Locus only when a Metis
worker issues an inference call.

Project boundaries:

| Boundary | Owner | Contract |
|---|---|---|
| Public TLS termination and exact-Host routing | Ocliv (edge + relay) | one host authority; only route-shaped `/r/<id>/mcp` reaches the tunnel |
| Route lifecycle, lease, publication durability | Ocliv relay + `ocliv mcp publish` | route ID is an opaque identifier, never a credential |
| Application authorization | Metis (upstream OAuth resource server) | the `Authorization` header reaches Metis **byte-identically**; Ocliv neither demands nor consults visitor credentials on this route |
| Tool surface and worker lifecycle | Metis | 15 `metis_*` tools; `metis_provision`/`metis_terminal*` drive a Muse worker |
| Model inference | Locus | OpenAI-style `/v1`; Metis's Muse worker is configured to use it |

## Request path

1. A visitor sends an MCP JSON-RPC request to
   `https://<public-host>/r/<route-id>/mcp` with a bearer JWT and
   `MCP-Protocol-Version: 2024-11-05`.
2. The TLS edge terminates and forwards to the loopback relay; the relay
   admits the request only for the configured `--mcp-host` and the exact
   route shape.
3. The relay resolves route → publication → live lease → agent session.
   An unknown or expired route is `404`; an inactive lease is `503`
   (never forwarded).
4. The agent forwards the request to the local MCP server. Application
   `Authorization` is passed through unchanged; Ocliv's own
   `X-Ocliv-Authorization` is stripped and never reaches the app.
5. Metis validates the token itself. On success it answers, and the
   response travels back through the same chain.

## Auth model

- Tokens are RS256 JWTs from the issuer configured in
  `METIS_MCP_ISSUER`; Metis fetches keys from `METIS_MCP_JWKS_FILE`.
- Metis requires: exact `iss`, non-empty `sub`, `aud` equal to the exact
  resource URL, unexpired `exp` (60 s leeway), and one of
  `metis:message | metis:provision | metis:input | metis:stop` in
  `scope`/`scp`.
- The audience must equal the route URL Ocliv mints. The publisher hands
  that URL to the server through `--resource-file` (Metis reads
  `METIS_MCP_RESOURCE_FILE`), so the advertised resource and the
  validated audience are the same value by construction.
- Strict discovery is the default: the publisher fetches the route's
  RFC 9728 protected-resource metadata through the live route and
  refuses to serve unless `resource` equals the published URL exactly.
  An unreachable or mismatched document deletes the route and fails
  closed.
- A wrong-audience or missing bearer is rejected by Metis with `401`.
  The relay does not decide application authorization on this route.
- Metis accepts `MCP-Protocol-Version: 2024-11-05` and `2026-07-28` and
  rejects `2025-06-18` with `400`.

Lab trust material: the harness generates a one-day CA, a `127.0.0.1`
SAN server certificate, an RSA signing key, and a JWKS inside a private
temp dir. `OCLIV_CACERT` makes the Ocliv CLI trust the lab edge; no TLS
verification is ever disabled.

## The Locus leg (not exercised)

In the full demo, Metis's Muse worker is configured to call Locus as its
inference gateway. The configuration is an isolated `XDG_CONFIG_HOME`
tree — a `musecfg` profile whose `settings.json` carries, in shape:

```jsonc
{
  "schema_version": 1,
  "provider": "meta",
  "model": "deepseek-v4-flash",
  "providers": { "meta": { "api_key": "<locus-local-placeholder>" } },
  "endpoint_transport": {
    "base_url": "http://127.0.0.1:<locus-port>/v1",
    "http_headers": { "X-FI-Local-Client": "hermes" },
    "auth": "bearer"
  }
}
```

The API key is a Locus-local placeholder, not a provider secret; real
provider credentials live in Locus, not in the Muse profile. A
`trust.json` marks the demo project directory `trusted`.

Operational notes for the Locus leg:

- Locus is **operator-gated**. A Locus instance may already be running
  on the host; a harness must not restart, stop, reconfigure, or probe
  it destructively.
- A live gateway does not expose `/health` (returns `404`). `/v1/models`
  and `/staging/v1/models` return `200` and are the read-only
  reachability probes.
- Reachability is not inference proof. Only a completed Muse worker turn
  that produces an artifact proves the Locus leg.

`run-composed.sh` accepts `LOCUS_BASE_URL` (and an opt-in
`LOCUS_READONLY_PROBE=1` single `GET /v1/models`), but never starts or
manages Locus, and always prints:

```text
Locus inference leg: NOT VERIFIED (operator-gated)
```

## What the harness proves

Observed on a real run of `tests/staging/composed/run-composed.sh`
against a Metis binary built from Metis master and an Ocliv binary built
from this tree:

- publish through `ocliv mcp publish --auth upstream-oauth` reaches an
  active route and reports verified OAuth discovery;
- the resource binding handoff contains exactly the route URL;
- RFC 9728 protected-resource metadata answers `200` and names the
  published resource;
- `tools/list` through the public route with a valid bearer returns
  `200` and exactly the 15 `metis_*` tools;
- a wrong-audience bearer returns `401`; a missing bearer returns `401`;
- `MCP-Protocol-Version: 2026-07-28` returns `200`;
  `2025-06-18` returns `400`;
- the whole path runs with all state in a private temp dir outside the
  repository, no secret printed, and no writes to Locus.

## What it does not prove

| Item | Status |
|---|---|
| Metis Muse worker → Locus inference | `NOT VERIFIED (operator-gated)` — not exercised |
| Public DNS, ACME issuance, real Caddy edge, internet reachability | `NOT VERIFIED (operator-gated)` — the edge is a loopback socat stand-in |
| Revoke/unpublish through the public route | not exercised here; covered by the repo's integration suites |
| Live production IdP (Auth0 etc.) | `NOT VERIFIED` — tokens come from the committed test IdP |
| ChatGPT workspace registration and real remote client | `NOT VERIFIED (operator-gated)` |
| Multi-tenant scale, soak, capacity | not in scope |

Local green is not public qualification. Each row above stays as labelled
until it is exercised against the real component, with dated evidence.
