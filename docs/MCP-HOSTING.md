# Hosting MCP servers on Ocliv

Ocliv exposes an already-running local MCP server through a public relay
so a remote MCP client (e.g. ChatGPT with a custom MCP connection) can
reach it. The MCP machine makes only outbound authenticated connections;
it needs no inbound firewall opening, VPS, or Tailscale.

Topology: local MCP server (loopback) → `ocliv mcp publish` (tunnel +
optional stdio adapter) → public relay (TLS edge + route ingress) →
remote MCP client with upstream OAuth. (Anonymous fixtures are
local-only via `mcp serve` and are refused by `mcp publish`: an
unprotected public tool endpoint is never created implicitly.)

## Client quickstart (hosted relay)

1. Install the `ocliv` binary and enroll once:
   `ocliv login --relay https://<relay-host> --code-file -`
2. Run a local MCP server on loopback, serving exactly `/mcp`
   (e.g. `http://127.0.0.1:8765/mcp`).
3. Publish it:
   `ocliv mcp publish --local http://127.0.0.1:8765/mcp --auth upstream-oauth`
   The command prints one stable endpoint when the tunnel is attached
   AND the route is registered, e.g.
   `https://<relay-host>/r/<route-id>/mcp`. Treat the route ID as an
   opaque identifier, not a secret: it authorizes nothing by itself.
   Before serving, publish proves the upstream OAuth resource binding
   by fetching the discovery document through the live route. If
   discovery is unreachable, publish warns (`resource binding NOT
   verified`) and continues; pass `--strict-discovery` to delete the
   route and fail closed instead, so an unproven binding never serves.
4. Point the MCP client at that URL with your OAuth issuer/audience/
   scopes. The relay forwards `Authorization` byte-identical for your
   upstream server to validate; Ocliv visitor credentials are neither
   demanded nor consulted on this route.
5. Check health anytime: `ocliv mcp doctor` (lease, route, local
   service, and MCP protocol status separately; never prints secrets).
6. Ctrl+C shuts down cleanly: the route is deleted, then the lease is
   closed, each outcome reported. Revoking the lease denies the route
   immediately (HTTP 503, no further forwarding).

Remote publication of stdio MCP servers (`--stdio`) is currently
disabled: the stdio bridge cannot enforce upstream authentication yet
(P0-1, P0-2). Publish an HTTP-native loopback MCP server with `--local`
instead. For loopback-only local use, `ocliv mcp expose -- COMMAND`
still adapts an operator-selected stdio child (it never becomes remotely
reachable); see `internal/mcp/mcp.go` for its bounds.

Anonymous fixtures are local-only: `mcp publish --auth fixture-anonymous`
is refused because the profile cannot bound an arbitrary local server.
Run safe demos with `mcp serve --auth fixture-anonymous` on loopback,
never as a public route.

## Self-hosting the relay (public IP)

1. Point DNS A/AAAA at the relay machine; serve it with the
   single-host edge (`packaging/caddy/Caddyfile.single-host`, normal
   ACME HTTPS — no wildcard DNS needed for `/r/<route-id>/mcp`).
2. Run the relay loopback-only with the exact external hostname, so the
   route resolver has one Host to match and everything else fails closed:
   `ocliv relay serve --listen=127.0.0.1:8080 --data /var/lib/ocliv --domain <domain> --mcp-host <relay-host>`.
   Omitting `--mcp-host` disables path-route ingress entirely (route
   creation then fails closed with 409). The MCP host may be the same
   FQDN that serves agent control (single-host edge): the relay keeps
   the two authorities separated by exact host plus strict path split,
   admitting only route-shaped `/r/<route-id>/mcp` paths through
   visitor routing.
3. Make public ingress independently reachable (TLS valid, Host routed)
   BEFORE enrolling agents or publishing routes.
4. The Caddy edge must overwrite (never append) `X-Forwarded-For` /
   `X-Forwarded-Proto` and strip `X-Forwarded-Host`. The relay routes on
   `r.Host` and rejects unknown authorities; SNI/Host consistency is
   enforced at this edge. Do not publish relay operator/management
   endpoints at the tool-hosting ingress beyond what the relay itself
   gates by authority.

## Behind CGNAT / no public IP

Without a public IPv4 address (or public IPv6, or an external ingress
provider), a home relay cannot be directly publicly reachable — no
tunnel software changes that. Options: an externally reachable relay
(hosted or self-hosted with a public address), or a separate ingress
provider in front of the relay. Do not promise public reachability
otherwise.

## Lab-only Funnel

Tailscale Funnel is a replaceable ingress adapter for developer testing
only — never part of user onboarding. Attach it at the RELAY ingress
(in front of the relay's loopback listener), select a single-host route,
and run the same publish flow through it. Funnel termination is edge
TLS only: it does not prove origin-server mTLS client-certificate
verification, and removing Funnel changes no Ocliv tunnel behavior.

## What is and is not verified

Local gates (build, vet, unit, integration, race on the touched
packages) cover: exact-Host single-host routing, route/lease binding,
profile/mode mismatch denial, header boundary (Authorization preserved,
Ocliv credentials stripped), mode-at-allocation with strict resume
equality, idempotent publish, route cleanup, and revocation denial.

NOT VERIFIED until exercised against real infrastructure: public DNS +
ACME issuance, cross-network TLS/SNI behavior, ChatGPT endpoint
registration and tool calls (initialize, tools/list, tools/call),
token expiry/revocation against a live IdP, and any OAuth discovery
against the path-based route URL. Until the live OAuth path is proven
with the actual client, keep the path route as the proven-local route
shape and treat wildcard `https://<lease>.t.<domain>/mcp` as the
production shape for OAuth discovery.
