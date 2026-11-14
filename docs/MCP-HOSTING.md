# Hosting MCP servers on Ocliv

Ocliv exposes an already-running local MCP server through a public relay
so a remote MCP client can reach it. The MCP machine makes only
**outbound** authenticated connections (WSS + yamux, Ed25519 identities);
it needs no inbound firewall opening on its own account, no VPS, and —

**Tailscale is not a product dependency.** Tailscale Funnel was used
only as temporary *staging* infrastructure for qualification evidence.
The permanent, supported deployment is ordinary public HTTPS: a normal
DNS name, Caddy as the TLS edge on public TCP 443, the relay bound to
loopback behind it, and publishers connecting outbound. No Funnel, no
Tailscale connection, and no third-party tunnel provider appears anywhere
in the client-to-relay or publisher-to-relay path. Nothing in Ocliv
turns Funnel on automatically; if a host has it configured for testing,
tear it down when the test is over (`tailscale funnel reset`) — see
*Lab-only Funnel* below.

Topology (permanent edge): local MCP server (loopback) →
`ocliv mcp publish` (outbound tunnel + route registration) → public relay
(loopback relay behind a Caddy TLS edge) → remote MCP client.

Two authorization profiles exist, and which one you use is a property of
your **upstream server**, not of Ocliv:

| Profile | Flag | Use when |
|---|---|---|
| Upstream OAuth | `--auth upstream-oauth` | your local MCP server has its own native OAuth |
| Relay-managed OAuth | `--auth ocliv-managed` | your local MCP server has **no** native OAuth (the relay is the Authorization Server) |

Anonymous fixtures are local-only (`mcp serve`) and are refused by
`mcp publish`: an unprotected public tool endpoint is never created
implicitly.

## Quickstart A — upstream OAuth (server already authenticates)

1. Install the `ocliv` binary and enroll once:
   `ocliv login --relay https://<relay-host> --code-file -`
2. Run a local MCP server on loopback serving exactly `/mcp`
   (e.g. `http://127.0.0.1:8765/mcp`).
3. Publish it:
   `ocliv mcp publish --local http://127.0.0.1:8765/mcp --auth upstream-oauth`
   The command prints one stable endpoint:
   `https://<relay-host>/r/<route-id>/mcp`. The route ID is an opaque
   identifier, not a secret — it authorizes nothing by itself.
   Before serving, publish proves the upstream OAuth resource binding by
   fetching the discovery document through the live route. If discovery
   is unreachable or invalid, publish deletes the route and fails closed,
   so an unproven binding never serves (`--strict-discovery` is accepted
   for back-compat and is the default). Explicit dev-only
   `--dev-allow-unverified-discovery` warns and serves the URL marked NOT
   VERIFIED — never register that URL with a hosted assistant.
   The discovery document must name the published route URL exactly.
   Because the route URL is minted at registration (after the MCP server
   started), pass `--resource-file PATH` and point the server at the same
   path: the publisher atomically writes the canonical URL there before
   probing, so the server advertises exactly that resource.
4. Point the MCP client at that URL with your OAuth issuer/audience/
   scopes. The relay forwards `Authorization` byte-identical for your
   upstream server to validate; Ocliv visitor credentials are neither
   demanded nor consulted on this route.
5. Check health anytime: `ocliv mcp doctor` (lease, route, local service,
   and MCP protocol status separately; never prints secrets).
6. Ctrl+C shuts down cleanly: the lease closes and the publication is
   RETAINED offline (503), so the next `publish --name SAME` rebinds the
   identical URL — no client re-registration. Permanent removal is
   explicit: `ocliv mcp unpublish --lease ID` (or
   `--publication-id ID`). Revoking the lease tombstones the publication
   permanently (404, never revived).

## Quickstart B — relay-managed OAuth (local server has no OAuth)

Use this when your local MCP server is a plain HTTP MCP server with no
authentication of its own. The relay acts as the Authorization Server for
that one route: it terminates OAuth, validates the bearer on every tool
request, and injects a relay-minted upstream identity so the external
bearer never reaches your server.

```
# on the machine running the local MCP server:
ocliv mcp publish --local http://127.0.0.1:8765/mcp --auth ocliv-managed --name my-tools
```

`ocliv mcp 8765` is the same thing: the bare port alias **defaults** to
`--auth ocliv-managed`, and an explicit `--auth` (any value, including
`upstream-oauth`) passes through untouched.

The publication then needs ONE operator approval, after which the client
session is durable:

1. A standard MCP client hits the route, gets `401` with an
   RFC 6750 `WWW-Authenticate: Bearer resource_metadata="…/.well-known/
   oauth-protected-resource/r/<route-id>/mcp"` challenge, follows it to
   the route-scoped protected-resource and authorization-server metadata,
   registers itself (DCR), and renders the consent page.
2. The operator approves that client once:
   `ocliv authz approve --data <relay-data-dir> --client <client-id> --tenant <t> --route <route-id>`
   which prints a single-use, expiring pairing credential.
3. The client submits that credential on the consent form and receives an
   authorization code → access **and refresh** token pair.
4. `tools/list` / `tools/call` work against your upstream. The current
   access token lives one hour; the **refresh token rotates and rejects
   replay**, so the operator does not re-approve every hour. Operator
   revocation (`ocliv authz revoke`) is terminal.

Route identity is durable per publication NAME: the bare alias derives
the name from the service it publishes, so a publisher restart keeps the
same route id and URL (strictly 503 → 401 while the lease is closed), and
`--name` still wins when you want an explicit identity.

Unpublishing retires the route's operator approvals in the same
transaction as the route itself (the grant rows become `revoked` and
remain for audit; the client registrations are preserved), so an approval
never outlives the route it authorized.

## stdio MCP servers

Publishing a **stdio** MCP server is supported **only with
relay-managed authorization**:

```
ocliv mcp publish --stdio --auth ocliv-managed -- /usr/local/bin/my-mcp-server --flag value
```

The child is started locally, pinned by the argv you typed — no remote
client can select executables, arguments, directories, or environment —
and runs behind a bounded adapter bound to loopback only. The relay
terminates authorization for the route, so the external bearer never
reaches the child. The route URL is registered and served only after the
local MCP session is verified.

The other stdio shapes are refused, deliberately:

| Command | Why refused |
|---|---|
| `publish --stdio --auth upstream-oauth` | the stdio adapter has no upstream OAuth to verify, so the resource binding cannot be proven |
| `mcp serve --stdio` | serve has no route, so a stdio child would be unreachable |
| `publish --stdio` with no command after `--` | there is nothing to run |

For purely local use, `ocliv mcp expose -- COMMAND` still adapts an
operator-selected stdio child and never becomes remotely reachable.
`mcp serve --auth fixture-anonymous` is the local-only demo path — never
a public route.

## Self-hosting the relay on ordinary public HTTPS

Requirements you can actually verify before enrolling anything:

1. **DNS** — an A (and/or AAAA) record for the relay host, resolving
   publicly to the relay machine's address, and *only* that. Confirm from
   off-LAN (`getent hosts <relay-host>`, then probe the returned address).
2. **Caddy edge** — serve the host with the single-host edge
   (`packaging/caddy/Caddyfile.single-host`, normal ACME HTTPS). No
   wildcard DNS is needed for `/r/<route-id>/mcp`.
   **Only TCP 443 must be forwarded.** Verified by adapting this exact
   file with `caddy adapt`: it produces one HTTP server listening on
   `:443` and no `http_port`, and its ACME issuers carry no challenge
   override, so issuance uses TLS-ALPN-01 on 443. Port 80 is *not*
   required by this edge, so a host where another service owns :80
   (e.g. Pi-hole) can run it unmodified.
   Do **not** "fix" a port-80 conflict by setting Caddy's global
   `http_port`: adapting that change switches the issuers to
   `challenges.http.alternate_port`, i.e. HTTP-01 on the alternate
   port, which silently adds a second forwarded port and breaks the
   ordinary 443-only deployment. If something else owns :80, leave this
   Caddyfile alone — it does not use it.
3. **Relay, loopback only** — run it behind that edge with the exact
   external hostname:
   `ocliv relay serve --listen=127.0.0.1:8080 --data /var/lib/ocliv --domain <domain> --mcp-host <relay-host>`
   The relay refuses a non-loopback listener. `--mcp-host` is the exact
   public FQDN serving `/r/<route-id>/mcp`; **omitting it disables
   path-route ingress** (route creation fails closed with 409).
   `--relay-host` overrides the control authority when the public
   hostname is not `relay.<domain>`. If the edge terminates on a non-443
   port, add `--mcp-port <port>` so minted URLs carry it.
4. **Reachability, proven before agents** — make public ingress
   independently reachable (valid TLS, correct Host) BEFORE enrolling
   agents or publishing routes. A 421 on the agent path means the Host is
   wrong; a 421 on `/r/.../mcp` means `--mcp-host` is wrong.
5. **Header discipline** — the edge must overwrite (never append)
   `X-Forwarded-For` / `X-Forwarded-Proto` and strip `X-Forwarded-Host`.
   The relay routes on `r.Host` and rejects unknown authorities.

### Diagnosing the path, in order

Work outside-in, and stop at the first layer that fails — each layer has
its own fix, and skipping ahead produces wrong conclusions:

| Symptom | Layer | What it means | Fix |
|---|---|---|---|
| `getent hosts <host>` returns nothing / the wrong address | DNS | the record is absent or not yet propagated | wait for propagation, or correct the record; a dynamic-DNS provider token belongs in `DYNV6_TOKEN`/`--token-file`, never argv |
| DNS resolves, but TCP 443 times out from off-LAN | Firewall / port forward | the host is reachable but the port is not | forward **443 only** at the router (the single-host edge needs no other port, and issuance uses TLS-ALPN-01 on 443); verify from an external vantage, not from inside the LAN (NAT loopback makes in-LAN tests pass falsely) |
| TCP 443 connects but the certificate is invalid or self-signed | TLS / ACME | issuance did not complete | confirm Caddy's ACME order — this edge uses TLS-ALPN-01 on 443, so an order failure means port 443 was not reachable at issuance time; check the Caddy log for the order error |
| TCP 443 + valid TLS, but the route 404s | Relay routing | unknown/expired route, or dead lease | republish; check `mcp doctor` |
| Route 503 + `Retry-After` | Publication | lease inactive/offline | reconnect the agent/publisher |
| `setup --auto` stops after DNS with a stated reason | Detection | CGNAT, missing token, or no viable path | read the printed reason and fix that prerequisite; **Ocliv cannot bypass CGNAT** — you need an externally reachable relay |

`ocliv setup --auto` performs the detection read-only and persists the
relay URL only after a verified match; `ocliv status` / `ocliv doctor`
name the state (RELAY DISCONNECTED, AUTH REQUIRED, RECONNECTING, ROUTE
OFFLINE) with the next action. Exit codes distinguish them: `3` local
target unreachable, `4` auth/enrollment, `5` relay TLS/reachability,
`6` protocol verification failed, `7` quota/lease.

### Behind CGNAT / no public address

Without a public IPv4 (or public IPv6, or a genuinely external ingress
provider), a home relay cannot be directly publicly reachable — no
tunnel software changes that. Options: run the relay on an externally
reachable host, or use a separate ingress provider in front of it.
Ocliv does not claim to bypass that limitation, and `setup --auto` says
so when it detects it.

## Lab-only Funnel (temporary staging infrastructure)

Tailscale Funnel was used only to gather qualification evidence on a
throwaway edge. It is **never** part of onboarding, never a product
requirement, and never assumed by any documented flow above: the same
relay binary, the same Caddy single-host config, and the same publish
flow run on ordinary public HTTPS, and that is the supported shape.
Funnel termination is edge TLS only — it does not prove origin-server
mTLS client-certificate verification. If a host still has it configured
for an old test, reset it when the test is done
(`sudo tailscale funnel reset`) and confirm the port is gone.

## What is and is not verified

Local gates (build, vet, unit, integration, race on the touched
packages) cover: exact-Host single-host routing, route/lease binding,
profile/mode mismatch denial, the header boundary (`Authorization`
preserved, Ocliv credentials stripped), mode-at-allocation with strict
resume equality, idempotent publish, route cleanup, and revocation
denial.

**Permanent-edge qualification: NOT VERIFIED.** The layered evidence
below was gathered over the Tailscale Funnel staging edge and over public
HTTPS through that same Funnel. Both are *temporary staging* results and
are deliberately kept distinct from a permanent Caddy/ACME edge, which
has not been exercised: ordinary-DNS + ACME issuance, public port 443
reachability, and a hosted-assistant registration remain unproven. Do
not promote the staging evidence into a permanent-edge claim.
Permanent-edge evidence and its blockers are recorded separately in
[docs/qualification/PERMANENT-EDGE-2026-11-13.md](qualification/PERMANENT-EDGE-2026-11-13.md).

Several *configuration-level* facts about the permanent edge **are**
verified, and they are the only permanent-edge claims here that do not
rest on staging:

- `packaging/caddy/Caddyfile.single-host`, adapted with a real
  `caddy 2-alpine` `caddy adapt`, yields exactly one HTTP server
  listening on `:443`, no `http_port`, and ACME issuers with no
  challenge override, so the permanent edge binds **443 alone** and
  issues via TLS-ALPN-01 on 443. The same adapter proves the
  tempting-looking "fix" for a busy :80 (global `http_port`) would
  instead force HTTP-01 on an alternate port, adding a second forwarded
  port.
- What `ocliv setup --edge single-host` and `relay init` render is that
  exact file (`templates.go` go:embeds it, pinned by
  `TestEmbeddedTemplatesMatchOnDiskFiles`), and it carries the
  trusted-edge header contract and nothing from the tunnel namespace.
- `ocliv setup` could not select the single-host edge at all until
  `f0bc949`; it hardcoded the tunnel edge and blocked single-host on a
  wildcard record it never needs.

These are configuration proofs from the adapter and from tests, **not** a
live ACME issuance and not evidence that any host's 443 is externally
reachable; those remain NOT VERIFIED.

Staging evidence in hand (Funnel edge, isolated stack, relay rebuilt from
HEAD, official Python MCP SDK 1.28.1 and the official TypeScript SDK):
the full managed OAuth flow end to end; `tools/list` and `tools/call`
reaching a harmless upstream; token revocation (RFC 7009) stopping a
token with no upstream execution; refresh rotation with replay rejection
(400); same-key restart preserving the route id; cross-key takeover
refused terminally and auditably; unpublish retiring the route's
approvals in one transaction with the publication gone (404) while
client registrations and grant rows are preserved; and the
`resource_metadata` challenge being followed by the SDK **without** any
well-known fallback. Every denial left the upstream's execution counter
unmoved.

NOT VERIFIED until exercised against real permanent infrastructure:
public DNS + ACME issuance on the permanent edge, a hosted assistant's
endpoint registration and tool calls, token flows against a live IdP,
clean-host installation, and soak behavior. The wildcard
`https://<lease>.t.<domain>/mcp` shape remains the production shape for
generic tunnels; the path route is qualified for MCP hosting through the
staging edge only.

Five distinct levels — do not conflate them: (1) local stdio-to-HTTP
(`mcp expose`, loopback only); (2) authenticated HTTP MCP
(`mcp serve-http`, JWT from the configured external issuer, loopback
only); (3) public Ocliv publication (`mcp publish --local`, single-host
route); (4) real remote-client OAuth qualification (proven with the
relay-managed flow and fixture upstreams on the staging edge; live-IdP
and hosted-assistant proofs pending); (5) production infrastructure
qualification (pending).