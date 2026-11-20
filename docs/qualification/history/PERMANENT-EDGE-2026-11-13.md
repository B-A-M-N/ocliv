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

Reproduce with `scripts/verify-single-host-edge.sh` (8 assertions + two
negative controls) and `go test ./packaging/caddy/`.

**Correction of an earlier claim in this file (2026-11-13, same day).**
The first version of this document asserted that issuance uses
TLS-ALPN-01 because "the ACME issuers carry no challenge override
(Caddy default is TLS-ALPN-01 on the TLS port)". That claim was NOT
established: Caddy enables HTTP-01 and TLS-ALPN-01 by default, and an
issuer with no challenge override still attempts HTTP-01 over port 80
before falling back. Operator review caught that the adapted JSON
simply does not show the default. The template now explicitly disables
HTTP-01 (`disable_http_challenge` in the `issuer acme` block), the
verification script asserts the explicit disable instead of an absence,
and its negative controls adapt the same file with the pin removed
(issuer then NOT proven :80-free) and with the global `http_port` trap
(the disable survives; the trap is inert-but-misleading on this edge,
and a real HTTP-01 flip on any unpinned edge).

| Claim | Evidence |
|---|---|
| The single-host edge binds TCP 443 and needs no other port | `caddy adapt` on `packaging/caddy/Caddyfile.single-host` (`caddy:2-alpine`) yields exactly one HTTP server: `listen: [":443"]`, no `http_port` |
| Issuance is PINNED to TLS-ALPN-01 on 443, not HTTP-01 | Same adaptation: the ACME issuer is explicit (`module: acme`, contact email carried) and carries `challenges.http.disabled: true`. The negative control (same file with `disable_http_challenge` removed) shows the issuer then has NO challenges field, i.e. HTTP-01+TLS-ALPN-01 both live — so the assertion is non-vacuous |
| A host where another service owns :80 can run it unmodified | Follows from the two rows above: there is no :80 server and no HTTP-01 dependency |
| The trusted-edge header contract is present | `reverse_proxy 127.0.0.1:8080` with `header_up X-Forwarded-For {remote_host}`, `header_up X-Forwarded-Proto {scheme}`, and `header_up -X-Forwarded-Host` |
| Setting global `http_port` is a trap, not a fix | Adapting with `http_port 8080` on the pinned file keeps `challenges.http.disabled: true` (the pin survives) and adds an inert `alternate_port` plus an app-level `http_port: 8080`. On an unpinned edge the same line flips the issuer to HTTP-01 on the alternate port. Documented as an explicit do-not-do |
| What `setup` / `relay init` renders IS the reviewed file | `packaging/caddy/templates.go` go:embeds `Caddyfile.single-host`, `Caddyfile`, and `Caddyfile.tunnel`; `TestEmbeddedTemplatesMatchOnDiskFiles` pins the embed to the on-disk source, so a divergent second template cannot appear unnoticed; `TestSingleHostTemplatePinsTLSALPNChallenge` pins `disable_http_challenge` in the template (red-before the template fix) |
| The single-host edge carries nothing from the tunnel namespace | `TestSingleHostTemplateHasNoTunnelNamespace` (no `on_demand_tls`, no ask endpoint, no `*.t.`) |
| The on-demand tunnel edge keeps its abuse guard | `TestTunnelTemplateKeepsAskGuard` - failing-first proven: deleting the `ask http://127.0.0.1:8080/v1/internal/ask` line turns it red; template restored byte-for-byte afterwards |
| `ocliv setup --auto` can render the single-host edge at all | Commit `f0bc949`: `runSetupRender` hardcoded `--edge tunnel` and `verifyWildcardDNS` ran unconditionally, which both produced the wrong ingress for MCP hosting and blocked a single-host deployment on a wildcard record it never needs. `--edge single-host|wildcard|tunnel` now selects it; the wildcard proof is gated to the tunnel-namespace edges |

## NOT VERIFIED

Nothing below has been exercised on real infrastructure.

- Live ordinary-DNS + ACME issuance on the permanent edge. PARTIALLY
  RETRACTED: the production Pi now serves a real ACME certificate over
  `bamnlabs.dynv6.net` and answered a strict-TLS challenge probe (see
  the public edge state below) — but only from a LAN vantage, so
  off-LAN issuance/reachability remains unproven.
- ~~Public reachability of TCP 443 for any candidate host~~ RETRACTED
  for the LAN vantage: the designated relay (`.170`) is back online
  with Caddy on 443. An off-LAN client's reachability is still NOT
  VERIFIED (hairpin NAT caveat below).
- The acceptance test: a remote MCP client on a normal public domain
  over HTTPS completing managed authentication and `tools/call`, with no
  Tailscale for any participant.
- A hosted assistant's endpoint registration and tool calls.
- `packaging/caddy/Caddyfile.single-host.local` (loopback smoke-test
  variant of the single-host edge) - passed its one read-only
  `caddy validate` today through the normal in-band guard ("Valid
  configuration") and is now RUN end-to-end at loopback by
  `scripts/verify-single-host-loopback.sh` (see the executed section
  below). It is committed with that harness, which depends on it.
  `caddy validate` alone was NOT a working-edge proof: the variant
  carried `auto_https off`, which also disables certificate
  automation, so `tls internal` materialized no policy and every
  handshake died with a TLS internal-error alert. Fixed to
  `auto_https disable_redirects` (the same global block the production
  single-host file uses); found by the loopback run, not by the
  syntax check.

## Executed at loopback (2026-11-13, no DNS / no ACME / no Tailscale)

Reproduce with `scripts/verify-single-host-loopback.sh` (docker, go,
curl, python3; a throwaway client container with `--add-host` stands in
for the resolver, since the Go CLI cannot `--resolve` like curl and
this box has no root to edit /etc/hosts). The relay runs loopback-only
behind a real Caddy serving `Caddyfile.single-host.local` (internal CA,
`:8443`), and every client check verifies TLS STRICTLY against the
extracted internal CA — no `-k` anywhere. Live result, 9/9 PASS:

| Check | Result |
|---|---|
| relay health ready on loopback | PASS |
| edge up, strict-TLS readiness with the extracted internal CA | PASS |
| `GET /v1/agent/challenge` over the edge | 405 (relay answered - TLS + Host + proxy path live) |
| smuggled `Host: evil.test` at the EDGE | empty 200 - no Caddy site matched, nothing proxied (outer fail-closed) |
| smuggled `Host: evil.test` at the RELAY directly | 421 `misdirected: agent control requires the relay hostname` (inner defense in depth) |
| `GET /r/<unknown>/mcp` on the right host | 404 (non-disclosing) |
| client WITHOUT the internal CA | TLS failure (closed by default) |
| enrollment exchange through the edge (`ocliv login --cacert`) | exit 0 |
| agent attach through the edge (`ocliv <port>`, WSS + yamux) | `"status":"ACTIVE"`, route live generation 1, lease id minted |

Findings from this run (both fixed/recorded, none in the production
template): the fixture's `auto_https off` bug above; the loopback edge
needs `--relay-host` set to the apex for agent paths (without it every
agent-path request 421s - the single-host shape shares one hostname for
control and routes); `relay doctor` dials port 443 by design and cannot
be the oracle for a non-443 loopback edge (the strict-TLS control-path
probes replace it here); the visitor/MCP publication legs need a real
upstream with an auth profile and stay for the public run.

## Public edge state (2026-11-13 evening, Pi `.170` RECOVERED)

The operator brought `.170` back and ran the funnel reset. Read-only
capture over SSH plus probes from this host (LAN vantage — see caveat):

| Item | State |
|---|---|
| Units | `ocliv-relay`, `caddy`, `pihole-FTL`, `tailscaled`, `ssh` all active |
| Relay health (loopback 18080) | live `ok`, ready `ok` |
| Installed binary | `/usr/local/bin/ocliv`, sha256 `0d47481f2e2b7cbff34df57a713f0e39849be92cd85deabd5f256be07a00d0b1` (the 2026-11-11 hardening build), mtime 2026-11-11 |
| Ports | Caddy `:443`; Pi-hole `:80` (LAN + tailnet, NOT Caddy — the coexistence constraint holds unmodified); relay `127.0.0.1:8080`; health `127.0.0.1:18080` |
| Public probe `https://bamnlabs.dynv6.net/v1/agent/challenge` | HTTP 405, TLS verification OK (real ACME cert, DNS resolving, edge serving) |
| Public probe `https://bamnlabs.dynv6.net/` | HTTP 421 — visitor traffic on the control authority is supposed to 421 |
| Route `rdZp9IR6xkQKtpu_nLtUEw/mcp` (retired publication) | HTTP 404 — non-disclosing, consistent with the unpublish |
| Funnel (this box) | `sudo tailscale funnel reset` run by the operator; `tailscale funnel status` now `No serve config` — the stale 502 exposure is GONE |

CAVEAT: the public probes ran from the LAN through the router's
hairpin NAT, so they prove DNS + certificate + edge + relay, but NOT
that an off-LAN client can reach 443. That oracle still needs a probe
from another network.

## Blockers (operator-gated)

1. ~~Relay host offline~~ RESOLVED: `.170` is back (state above).
   `10.9.66.193` was probed but is not the Pi and is not authorized for
   this; it has been left clean and is not a substitute.
2. Public DNS record for the test hostname. No dynv6 token in this
   session (the existing `bamnlabs.dynv6.net` record already serves the
   production edge — see above).
3. ~~Funnel cleanup~~ RESOLVED by the operator: reset run, scope was
   confirmed as the single reported entry immediately beforehand, and
   status is now `No serve config`.
4. Off-LAN reachability of port 443 (hairpin NAT proves nothing
   external) — probe from another network.
5. The acceptance run: publish an authenticated MCP endpoint through
   this live edge and drive tools/call from a client with no Tailscale,
   with the upstream execution counter as the denial oracle.
6. Deployment decision: the three commits of this pass
   (`2e5543b`, `4e6bd16`, `9ff3c39`) touch no store schema, so the Pi
   update is a binary-only swap (current sha `0d47481f…` -> new build),
   rollback = restore the previous binary from `/usr/local/bin/ocliv.bak-*`
   plus a DB backup first. NOT PERFORMED — awaiting the operator's word.

## Actions required to finish the qualification

1. ~~Bring the relay host back~~ DONE: `.170` is online (state above).
2. ~~Validate and commit `Caddyfile.single-host.local` + loopback
   end-to-end~~ DONE: validated through the in-band guard, committed,
   and run 9/9 by `scripts/verify-single-host-loopback.sh`.
3. Off-LAN reachability: probe `https://bamnlabs.dynv6.net/v1/agent/challenge`
   from another network (expect a relay 4xx, never a TLS error).
4. The acceptance run on the live edge: publish a harmless local MCP
   server with `--auth ocliv-managed`, and drive the full managed OAuth
   flow (challenge, DCR, one operator approval with the single-use
   pairing credential, token, `tools/list`, `tools/call`) from a client
   with no Tailscale anywhere. Assert the upstream execution counter
   moves only on authorized calls, exactly as the staging runbooks
   require.
5. ~~`tailscale funnel reset`~~ DONE by the operator (recorded above).
6. Decide the Pi deployment of the three commits of this pass
   (binary-only swap; no schema change; DB backup first).

**Verdict: NOT QUALIFIED.** The permanent edge's configuration is proven
and pinned by tests; the edge itself is now partially exercised on real
infrastructure (real ACME certificate and control path, from a LAN
vantage); but off-LAN reachability and the authenticated MCP acceptance
run are still outstanding, so no public qualification is claimed.