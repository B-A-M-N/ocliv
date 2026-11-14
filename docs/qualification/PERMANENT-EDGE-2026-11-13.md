# Permanent (non-Tailscale) edge qualification - 2026-11-13

Scope: the product-direction correction that Tailscale Funnel is
temporary STAGING infrastructure and not a product dependency. The
supported permanent deployment is ordinary DNS + Caddy single-host edge
on public TCP 443 + outbound-WSS publishers, with no Funnel, Tailscale,
tunnel provider, or external identity provider anywhere in the
client-to-relay or publisher-to-relay path.

**This file is deliberately separate from `QUALIFICATION.md` and from
`GATE3-PUBLIC-FUNNEL.md`.** All earlier HTTPS evidence was gathered
through the Tailscale Funnel edge. None of it qualifies a permanent edge,
and nothing below reuses it as such. Funnel evidence remains in
`QUALIFICATION.md` (Round 47 and the SAPRE sections) and is labelled
staging there.

## Verified (configuration level)

Reproduce with `scripts/verify-single-host-edge.sh` (7 assertions + a
negative control) and `go test ./packaging/caddy/`.

| Claim | Evidence |
|---|---|
| The single-host edge binds TCP 443 and needs no other port | `caddy adapt` on `packaging/caddy/Caddyfile.single-host` (`caddy:2-alpine`) yields exactly one HTTP server: `listen: [":443"]`, no `http_port` |
| Issuance uses TLS-ALPN-01 on 443, not HTTP-01 | Same adaptation: the ACME issuers carry no challenge override (Caddy default is TLS-ALPN-01 on the TLS port) |
| A host where another service owns :80 can run it unmodified | Follows from the two rows above: there is no :80 server and no HTTP-01 dependency |
| The trusted-edge header contract is present | `reverse_proxy 127.0.0.1:8080` with `header_up X-Forwarded-For {remote_host}`, `header_up X-Forwarded-Proto {scheme}`, and `header_up -X-Forwarded-Host` |
| Setting global `http_port` is a trap, not a fix | Adapting with `http_port 8080` switches the issuers to `challenges.http.alternate_port: 8080`, i.e. HTTP-01 on an alternate port, silently adding a second forwarded port. Documented as an explicit do-not-do |
| What `setup` / `relay init` renders IS the reviewed file | `packaging/caddy/templates.go` go:embeds `Caddyfile.single-host`, `Caddyfile`, and `Caddyfile.tunnel`; `TestEmbeddedTemplatesMatchOnDiskFiles` pins the embed to the on-disk source, so a divergent second template cannot appear unnoticed |
| The single-host edge carries nothing from the tunnel namespace | `TestSingleHostTemplateHasNoTunnelNamespace` (no `on_demand_tls`, no ask endpoint, no `*.t.`) |
| The on-demand tunnel edge keeps its abuse guard | `TestTunnelTemplateKeepsAskGuard` - failing-first proven: deleting the `ask http://127.0.0.1:8080/v1/internal/ask` line turns it red; template restored byte-for-byte afterwards |
| `ocliv setup --auto` can render the single-host edge at all | Commit `f0bc949`: `runSetupRender` hardcoded `--edge tunnel` and `verifyWildcardDNS` ran unconditionally, which both produced the wrong ingress for MCP hosting and blocked a single-host deployment on a wildcard record it never needs. `--edge single-host|wildcard|tunnel` now selects it; the wildcard proof is gated to the tunnel-namespace edges |

## NOT VERIFIED

Nothing below has been exercised on real infrastructure.

- Live ordinary-DNS + ACME issuance on the permanent edge. The adapter
  proves the configuration, not that any host can obtain a certificate.
- Public reachability of TCP 443 for any candidate host. The designated
  relay (`.170`) is off-network: no ARP or ICMP on the LAN, tailnet
  offline 20h+, and zero TCP ports open at its public IP.
- The acceptance test: a remote MCP client on a normal public domain
  over HTTPS completing managed authentication and `tools/call`, with no
  Tailscale for any participant.
- A hosted assistant's endpoint registration and tool calls.
- `packaging/caddy/Caddyfile.single-host.local` (loopback smoke-test
  variant of the single-host edge) - written but UNVALIDATED and
  uncommitted. The command that would have run `caddy validate` on it was
  refused by the destructive-action guard (it also carried an unnecessary
  `mv`); that guard forbids retrying, rephrasing, or routing around, so
  it is left for the operator. `docs/SETUP.md` no longer references the
  file for that reason.

## Blockers (operator-gated, none locally actionable)

1. Relay host. `.170` is off-network. `10.9.66.193` was probed but is not
   the Pi and is not authorized for this; it has been left clean and is
   not a substitute.
2. Public DNS record for the test hostname. No dynv6 token in this
   session.
3. Funnel cleanup. `sudo tailscale funnel reset` needs the operator's
   password (no passwordless sudo here). One entry remains,
   `pop-os.tail8d285a.ts.net` to `127.0.0.1:18082`, with nothing
   listening, so it is serving HTTP 502 publicly.

## Actions required to finish the qualification

1. Bring the relay host back, or designate a host with a real public DNS
   name and inbound 443.
2. Validate and commit `Caddyfile.single-host.local` (one read-only
   `caddy validate` command), then a loopback end-to-end run with no DNS
   and no ACME exercises the single-host path before any public exposure.
3. On a public host: `ocliv setup --auto --hostname NAME --acme-email E
   --token-file T --edge single-host`, publish a harmless local MCP server
   with `--auth ocliv-managed`, and drive the full managed OAuth flow
   (challenge, DCR, one operator approval with the single-use pairing
   credential, token, `tools/list`, `tools/call`) from a client with no
   Tailscale anywhere. Assert the upstream execution counter moves only on
   authorized calls, exactly as the staging runbooks require.
4. `tailscale funnel reset` once the permanent edge is proven, and record
   it here.

**Verdict: NOT QUALIFIED.** The permanent edge's configuration is proven
and now pinned by tests; the edge itself has never been exercised on real
infrastructure, and no public reachability has been demonstrated.