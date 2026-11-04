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

# 2. Store the token in an owner-only file first (never on the
#    command line — it would land in shell history):
printf '%s' "$TOKEN" > ~/.dynv6-token && chmod 600 ~/.dynv6-token
#    Preview the DNS update (token redacted, nothing sent).
ocliv setup --auto --hostname lab.dynv6.net --token-file ~/.dynv6-token --dry-run

# 3. Full bootstrap: DNS sync, tunnel-edge render, DNS verify,
#    relay_url persist, Caddy install, systemd enable, auto-enroll.
sudo ocliv setup --auto --hostname lab.dynv6.net \
  --acme-email you@addr --token-file ~/.dynv6-token

# 4. From another network (no -k): expect relay 4xx, not TLS errors.
curl -v https://lab.dynv6.net/v1/agent/challenge
```

The token travels only via `--token-file` (0600, owned by root for
`sudo` runs) or the `DYNV6_TOKEN` environment variable set OUTSIDE the
invoked command (e.g. in a shell profile), never as an inline
`TOKEN=... ocliv ...` assignment, which shell history would persist.

## Certificate strategy (read before operating)

Two edges, two issuance models — do not confuse them:

- **Tunnel edge (default, `Caddyfile.tunnel`).** On-demand
  per-hostname certificates, each new `*.t.<domain>` tunnel hostname
  getting its own cert after the relay's ask guard approves the
  request. Ask guard tested; issuance itself is unverified against
  public ACME (see qualification table below).
- **Wildcard edge (`Caddyfile`, `--edge wildcard`).** One DNS-01
  wildcard certificate covering all tunnel hostnames. Needs a Caddy
  DNS-provider plugin and credentials (`--dns-provider/--dns-env`);
  `relay init --check` rejects a file with the dns line commented out.

Neither is free of limits: per-hostname issuance is bounded by public
rate limits, wildcard issuance by DNS-plugin availability. Pick one
edge per relay; the MCP single-host path needs no wildcard at all.

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
| IP address changed (dynv6) | DHCP/PPPoE renewal | `ocliv setup --refresh-dns --hostname ZONE` (DNS-only, no re-provisioning), or enable the refresh timer below |
| Relay down after reboot | Service not enabled | `systemctl enable --now ocliv-relay`; certificates renew automatically via Caddy |
| Key compromised | — | `ocliv relay revoke-key --key-id ...` on the relay host, then `ocliv logout` + re-enroll |

## Unattended DNS refresh (optional, relay operators only)

Home IPs change. Instead of re-running full setup, a timer can run
the DNS-only refresh every 15 minutes:

```sh
# 1. Restricted credential: readable only by the service user.
install -o ocliv -g ocliv -m 0600 /dev/null /etc/ocliv/dynv6.token
# paste the dynv6 HTTP token into that file (no trailing newline needed)

# 2. Explicit opt-in: without this env file the service fails closed.
printf 'OCLIV_DNS_HOST=bamnlabs.dynv6.net\n' | sudo tee /etc/ocliv/dns-refresh.env
sudo chmod 600 /etc/ocliv/dns-refresh.env

# 3. Install the units (shipped in packaging/systemd, inert by default)
#    and enable the TIMER, not the service.
sudo cp packaging/systemd/ocliv-dns-refresh.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ocliv-dns-refresh.timer

# 4. Observe: journalctl -u ocliv-dns-refresh.service
```

Properties: repeated runs are idempotent (update only on real address
change); a run that overruns its slot delays the next instead of
overlapping; neither Caddy nor the relay restarts on a DNS-only
change; failures go to the journal with a nonzero exit. The ordinary
`ocliv 3000` / `ocliv mcp 3000` client never needs systemd.

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
