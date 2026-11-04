# Ocliv — secure instant HTTPS hosting

Share `localhost:3000` over protected HTTPS, or publish a local MCP
server, without opening router ports on the sharing machine. The agent
makes an outbound authenticated connection to a relay; the relay
serves the public HTTPS edge (Caddy) in front of it.

## 60-second client quickstart

You need: the `ocliv` binary, a relay URL, and a one-time enrollment
code from the relay operator.

```sh
ocliv login --relay https://relay.example.net --code-file ./code.txt
ocliv 3000
# -> https://<id>.t.example.net  (protected by default)

ocliv mcp 3000 --name mytools
# -> https://<relay-host>/r/<route-id>/mcp  (OAuth enforced, never silent public)
# --name keeps YOUR publication identity across restarts; the route ID
# itself is opaque. Run `ocliv mcp list` for the exact public URL.
```

Useful while running it:

```sh
ocliv status     # lease, route, and the next action when unhealthy
ocliv doctor     # key, relay reachability, local service, DNS/TLS
```

`ocliv help` lists the five everyday commands first; relay, DNS, and
identity administration live under Advanced.

## What Ocliv is (and is not)

| Capability | State |
|---|---|
| Protected web tunnel (`ocliv PORT`) | Implemented, tested |
| Authenticated MCP publication (`ocliv mcp PORT`) | Implemented, tested locally |
| Named, retained endpoint identity (`--name`) | Implemented |
| Reconnect backoff with reset, dynamic-DNS refresh | Implemented |
| Backup / restore without resurrecting revoked authority | Implemented, tested |
| Self-hosted relay on your own domain (dynv6 + Caddy) | Implemented; needs public inbound IP, DNS, root — see [docs/SETUP.md](docs/SETUP.md) |
| Designated relay on Tailscale Funnel (`.20`, `pop-os-3.tail8d285a.ts.net`) | **QUALIFIED 2026-11-04** — full MCP OAuth E2E PASS through public HTTPS via Funnel (see [docs/qualification/QUALIFICATION.md](docs/qualification/QUALIFICATION.md), Round 47). Deployed binary sha256 `9d38bb1b2142b661fe5590584061bf696d6a1523bcaea5000d783ef5dd7e8e7a` on `.20` (`/usr/local/bin/ocliv`, PID 3350438 at qualification). |
| Permanent public ingress on `bamnlabs.dynv6.net` (DNS + router + Caddy) | **NOT QUALIFIED** — depends on dynv6 DNS, public inbound IP/router, and production Caddy. Funnel qualification does not establish this. |
| Shared public relay (no domain/VPS per user) | **BLOCKED — no operated relay exists yet** (see [docs/SHARED-RELAY.md](docs/SHARED-RELAY.md)) |
| Public ChatGPT registration of an Ocliv endpoint | **NOT VERIFIED** — local protocol path works; provider-side steps unproven |
| 24-hour soak, clean-host install proof | **NOT VERIFIED** |

A relay attachment is never presented as proof of public reachability:
`status`/`doctor` mark unverified facts UNKNOWN, never healthy.

## Self-hosting (advanced)

The sharing machine needs no inbound ports, but *some* machine must
serve public HTTPS. For your own relay you need a public IP (no CGNAT),
a DNS zone, and a host that can run Caddy + `ocliv relay serve`:

```sh
ocliv setup --check                          # diagnose first, changes nothing
ocliv setup --auto --hostname ZONE.dynv6.net --acme-email you@mail
```

See [docs/SETUP.md](docs/SETUP.md), [docs/HOME-HOST.md](docs/HOME-HOST.md),
[docs/VPS.md](docs/VPS.md), and [docs/OPERATOR.md](docs/OPERATOR.md).

## Layout

- `cmd/ocliv` — client + relay binaries (one Go module, no runtime deps beyond Caddy/systemd on relay hosts)
- `internal/relay`, `internal/agent` — tunnel transport (WSS + yamux, Ed25519, SQLite authority)
- `internal/cli` — user commands; `internal/setup` — self-host provisioning
- `packaging/caddy`, `packaging/systemd`, `packaging/install` — relay deployment
- `docs/` — operator and protocol documentation

## Security notes

- Tunnels are protected by default; `--public` is explicit and visible.
- `ocliv mcp` refuses to publish an MCP server without usable OAuth
  protection (`--auth upstream-oauth`); arbitrary stdio servers stay local-only.
- DNS tokens come from `DYNV6_TOKEN` or a `0600` file, never argv; transport
  errors are sanitized so tokens never reach logs or output.
