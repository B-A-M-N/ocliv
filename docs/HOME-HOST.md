# Ocliv relay on a home host behind a router (public IP, no VPS)

When your ISP gives you a public IPv4 address (even a dynamic one),
an always-on Linux box at home can be the relay. No VPS, no Tailscale,
no Funnel in the serving path. Publishers still need nothing but
`ocliv login` + `ocliv PORT`.

## Prerequisites

- Home router with admin access and a public WAN IPv4 address (check
  the router's status page; `100.64.x.x`, `10.x.x.x`, `192.168.x.x`,
  or `172.16-31.x.x` as the WAN address means CGNAT — stop here and
  use a VPS instead; port forwarding cannot work behind CGNAT).
- A Linux host on the LAN, reachable by you via SSH.
- A domain (or subdomain) you control, with DNS you can edit.
- Ports 80 and 443 forwardable (some ISPs block 80 inbound — see below).

## Setup

1. Pin the relay host's LAN address: in the router, bind its MAC to a
   static DHCP lease (e.g. `192.168.1.50`), or set a static IP outside
   the DHCP pool.
2. Forward TCP 80 and 443 from the WAN to that LAN address. Port 80 is
   needed only for ACME `http-01` issuance/renewal; 443 carries all
   tunnel traffic.
3. DNS: one `A` record, e.g. `relay.example.net` → your public IP.
   If the IP changes, lower the TTL (300s) and update the record, or
   use your registrar's dynamic-DNS updater. Stale DNS = failed
   issuance and failed clients; nothing in Ocliv can route around it.
4. On the relay host, install per
   [OPERATOR.md](/home/bamn/ocliv/docs/OPERATOR.md) public single-host
   deployment: `ocliv relay init --domain example.net --mcp-host
   relay.example.net --acme-email ops@example.net --out
   ./ocliv-relay-deploy`, Caddy `Caddyfile.single-host`,
   `systemctl enable --now ocliv-relay`.
5. Firewall on the relay host (`ufw` example): `ufw allow 80,443/tcp`
   and nothing else inbound. The relay itself stays on
   `127.0.0.1:8080`; Caddy is the sole public listener.

## ISP blocks port 80

ACME `http-01` needs inbound 80. If it is blocked, use the wildcard
edge instead: `ocliv relay init --edge wildcard --dns-provider
<name> --dns-env <ENV>` with a DNS API token (DNS-01 needs only
outbound HTTPS to your DNS provider). Wildcard also covers the
`*.t.example.net` generic-tunnel namespace that single-host does not.

## Rollback

`systemctl stop ocliv-relay`, delete the two port-forward rules, and
(public name now dark) optionally point DNS at a parked record. The
installer keeps the pre-upgrade binary at `/usr/local/bin/ocliv.prev`
(first candidate wins across re-runs); restore it manually if a new
binary misbehaves. Relay data lives in `/var/lib/ocliv` — back it up
per OPERATOR.md before wiping anything.

## External verification (required before PUBLIC READY)

From a machine off your LAN (phone on mobile data, no Wi-Fi):

```
curl -v https://relay.example.net/v1/agent/challenge
```

TLS must verify with default trust (no `-k`); a 4xx from the relay
proves DNS → 443 → Caddy → loopback relay. Then enroll a publisher,
run `ocliv PORT`, and load the issued URL from the same off-LAN
machine. Tailnet or loopback success never counts.

## Cleanup of the staging ingress

When the public edge verifies: `tailscale funnel reset` on any host
still exposing Funnel, remove lab CAs from clients
(`update-ca-certificates --fresh` after deleting the lab file),
revert `/etc/hosts` staging entries, and revoke pre-production lab
agent keys (`ocliv relay revoke-key`). Staging trust must not linger
alongside production trust.
