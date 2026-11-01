# Ocliv setup — self-hosted public relay without a VPS or domain

`ocliv setup --auto` bootstraps a public relay on ordinary hardware
using a free dynv6 hostname. It detects, syncs DNS, renders the
deployment, verifies, installs the edge, enrolls, and persists the
config so `ocliv 3000` and `ocliv mcp publish` just work afterwards.

## Prerequisites (the only unavoidable manual steps)

1. A free dynv6 account and hostname (e.g. `lab.dynv6.net`). Create
   the HTTP token for the zone at https://dynv6.com/keys.
2. The token available as `DYNV6_TOKEN` or an owner-only file:
   `printf '%s' "$TOKEN" > ~/.dynv6-token && chmod 600 ~/.dynv6-token`.
   Never pass it as a CLI argument (it would land in shell history).
3. If detection reports `nat-ipv4-needs-forward`: forward TCP 80 and
   443 in the router admin page to this host's LAN address.
4. An ACME contact email for certificates: `--acme-email you@addr`.
5. Root for the install steps (Caddy/systemd). Without root, setup
   prints the exact manual commands instead.

No Tailscale, Funnel, Cloudflare Tunnel, VPS, or purchased domain is
involved at any step.

## Command sequence

```sh
# 1. Diagnose only — changes nothing.
ocliv setup --check

# 2. Preview the DNS update (token redacted, nothing sent).
DYNV6_TOKEN=... ocliv setup --auto --hostname lab.dynv6.net --dry-run

# 3. Full bootstrap: DNS sync, tunnel-edge render, DNS verify,
#    relay_url persist, Caddy install, systemd enable, auto-enroll.
sudo -E DYNV6_TOKEN=... ocliv setup --auto \
  --hostname lab.dynv6.net --acme-email you@addr

# 4. From another network (no -k): expect relay 4xx, not TLS errors.
curl -v https://lab.dynv6.net/v1/agent/challenge
```

`sudo -E` preserves DYNV6_TOKEN for the root install steps.

## What setup does and does not do

Done automatically: egress/path detection, dynv6 A/AAAA sync, tunnel
Caddyfile + systemd unit render, local consistency check, DNS-match
verification, relay_url persistence, Caddy install with backup and
validate-restore, relay enable, enrollment (mint + exchange, which
also proves DNS → Caddy → relay end to end).

Still manual by design: creating the dynv6 account/token, the router
port forward, installing Caddy itself when missing, and revocation/
recovery decisions (below).

## Failure and recovery

| Symptom | Cause | Recovery |
|---|---|---|
| `cgnat-no-direct-ipv4` | Carrier-grade NAT | Serve over IPv6 if direct, else `setup --auto --provider oracle` (own OCI account, confirm-gated) |
| `nat-ipv4-needs-forward` persists | Forward missing/wrong | Forward TCP 80+443 to the LAN address in the report; re-run |
| `dns ... not resolving here yet` | Propagation | Wait, then re-run the same command; nothing half-written persists |
| `dns ... not to observed egress` | Stale record / wrong zone | Check the zone answers for this host (dig from another network); fix and re-run |
| `enrollment failed: relay unreachable` | Caddy/relay not serving | `systemctl status ocliv-relay`, `caddy validate`, `ocliv relay doctor` |
| ACME issuance fails | Port 80/443 blocked or DNS wrong | Verify inbound with the curl probe; port 80 is required for issuance |
| Caddy config replaced badly | Failed validate | Setup restores `/etc/caddy/Caddyfile.ocliv-bak` automatically |
| IP address changed (dynv6) | DHCP/PPPoE renewal | Re-run `setup --auto --hostname ...` (DNS-only update, no re-provisioning) |
| Relay down after reboot | Service not enabled | `systemctl enable --now ocliv-relay`; certificates renew automatically via Caddy |
| Key compromised | — | `ocliv relay revoke-key --key-id ...` on the relay host, then `ocliv logout` + re-enroll |

## Simulated vs live qualification

| Claim | Evidence class |
|---|---|
| Detection, DNS client, plan matrix, enroll exchange, ask guard, init render/check | Live unit/integration tests in-repo (run `go test ./...`) |
| Caddy/systemd executors | Live code, NOT run in-repo (need root + services); backup/restore paths review-only |
| `Caddyfile.tunnel` syntax | Structural checks only — run `caddy validate` before use (no caddy binary in CI here) |
| dynv6 wildcard `*.t` resolution | Unverified — zone did not exist at check time; verify with `dig` once the zone is live |
| First on-demand issuance | Unverified — needs public IP + DNS; the ask guard is tested, issuance is not |
| Oracle launch | Dry-run tested; live launch needs the operator's OCI account (BLOCKED-live) |
| Public HTTPS + tunnel end to end | NOT VERIFIED until the off-network curl probe passes |

A green `setup --auto` exit means the local chain verified (DNS
match, edge installed, enrollment exchanged). It never claims public
reachability — only the external probe does.
