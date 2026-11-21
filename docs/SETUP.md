# Ocliv relay setup — self-hosted public relay

`ocliv relay setup --auto` (alias: `ocliv setup --auto`) bootstraps a public
relay on ordinary hardware. It detects egress/NAT, syncs DNS, verifies
resolution, renders the deployment, installs pinned Caddy (with DNS-01 module
for the default `wildcard` edge) and systemd units, and starts the relay.
Each stage is independently verified and checkpointed so interrupted runs
resume cleanly.

**Role separation:** Relay setup NEVER enrolls a publisher identity or writes
publisher config on the relay host. After the relay is running, pair each
publisher machine via `ocliv pair https://<relay-host>` and approve on the
relay with `ocliv relay approve <CODE> --tenant <TENANT>`.

## Prerequisites (the only unavoidable manual steps)

1. A DNS zone (e.g. Cloudflare, Route53, dynv6, DuckDNS) with a wildcard
   record `*.t.<domain>` for the default `--edge wildcard` topology (or a
   single apex hostname for `--edge single-host`).
2. DNS credentials provided via environment variable or an owner-only `0600`
   file (`--token-file`). Never pass tokens as CLI arguments.
3. If detection reports `nat-ipv4-needs-forward`: forward TCP 443 to this
   host's LAN address (TCP 80 is only needed if you explicitly opt into the
   noncanonical `--edge tunnel` lab mode). If detection reports
   `cgnat-no-direct-ipv4`, serve over direct IPv6 or run on an externally
   reachable host (`ocliv relay setup --auto --provider oracle`).
4. An ACME contact email for certificates: `--acme-email you@addr`.
5. Root (`sudo`) for automatic Caddy + systemd installation. Without root,
   setup prints the exact manual commands instead.

## Command sequence

```sh
# 1. Diagnose only — changes nothing.
ocliv relay setup --check

# 2. Store the DNS token in an owner-only file (0600):
printf '%s' "$TOKEN" > ~/.dns-token && chmod 600 ~/.dns-token

# 3. Full relay bootstrap (default edge: wildcard — wildcard DNS + one
#    DNS-01 wildcard cert, no per-lease ACME, TCP 443 only):
sudo ocliv relay setup --auto --hostname relay.example.net \
  --dns-provider cloudflare --acme-email you@addr --token-file ~/.dns-token

#    Need single-host MCP path routes without wildcard DNS?
sudo ocliv relay setup --auto --hostname lab.dynv6.net \
  --edge single-host --acme-email you@addr --token-file ~/.dns-token

# 4. From another network (no -k): expect relay 4xx, not TLS errors.
curl -v https://relay.example.net/v1/agent/challenge

# 5. On each publisher machine, pair and publish:
ocliv pair https://relay.example.net
#    (approve on the relay: ocliv relay approve <CODE> --tenant default)
ocliv host 8765 --name personal-tools
```

## Certificate strategy (read before operating)

Three edges, three issuance models. Pick with `--edge`, one per relay:

- **Wildcard edge (`Caddyfile`, `--edge wildcard`, production default).**
  Wildcard DNS (`*.t.<domain>`) + ONE DNS-01 wildcard certificate covering all
  `<lease>.t.<domain>` tunnel hostnames, with zero per-lease DNS updates or
  per-lease ACME issuance. `ocliv relay setup` installs pinned Caddy with the
  requested `--dns-provider` module automatically when run as root.
- **Single-host edge (`Caddyfile.single-host`, `--edge single-host`).**
  ONE public apex hostname carries agent control, unlock pages, and path-based
  MCP routes `/r/<route-id>/mcp`. ACME issuance is pinned to TLS-ALPN-01 on
  443 (`disable_http_challenge`), requiring no port 80 and no wildcard DNS.
- **Tunnel edge (`Caddyfile.tunnel`, `--edge tunnel`, noncanonical lab/compatibility mode).**
  On-demand per-hostname ACME certificates gated by the relay's ask endpoint.
  Subject to public ACME rate limits (~50 certs/week/domain) and requires TCP
  80 + 443; kept only for lab/compatibility use.

**Ports.** Forward TCP 443 always. Neither the default `wildcard` edge nor
`single-host` requires TCP 80; only the noncanonical `--edge tunnel` lab mode
uses TCP 80.

## What setup does and does not do

Done automatically: egress/path detection, dynv6 A/AAAA sync,
edge Caddyfile (the one `--edge` selected) + systemd unit render, local
consistency check, DNS-match verification, relay_url persistence, and —
as root — the COMPLETE clean-host install: service account, binary,
launcher, `/etc/ocliv/relay.env` (0600), `/var/lib/ocliv` (0700,
service-owned), Caddyfile install with backup and validate-restore,
Caddy enable/reload, relay unit install, relay enable, enrollment
(mint + exchange, which also proves DNS to Caddy to relay end to end).
For the tunnel and wildcard edges, a fresh `*.t.<domain>` probe hostname
must resolve here too; the single-host edge needs only the apex and is
not blocked on a wildcard record it never uses.

Still manual by design: creating the dynv6 account/token, the router
port forward, installing Caddy itself when missing, and revocation/
recovery decisions (below).

A later step's failure rolls the whole install back to the previous
state (files restored, the first-candidate binary restored, a data dir
this run created is removed — a pre-existing one never is, and the
service account is never deleted). An existing destination WITHOUT the
`# managed by ocliv setup` marker is refused, not overwritten.

## Failure and recovery

| Symptom | Cause | Recovery |
|---|---|---|
| `cgnat-no-direct-ipv4` | Carrier-grade NAT (Ocliv cannot bypass CGNAT on its own) | Serve over IPv6 if direct, else host the relay on an externally reachable machine (e.g. `setup --auto --provider oracle`, own OCI account, confirm-gated) |
| `nat-ipv4-needs-forward` persists | Forward missing/wrong | Forward TCP 443 (plus TCP 80 only if using `--edge tunnel`) to the LAN address in the report; re-run |
| `dns ... not resolving here yet` | Propagation | Wait, then re-run the same command; nothing half-written persists |
| `dns ... not to observed egress` | Stale record / wrong zone | Check the zone answers for this host (dig from another network); fix and re-run |
| `enrollment failed: relay unreachable` | Caddy/relay not serving | `systemctl status ocliv-relay`, `caddy validate`, `ocliv relay doctor` |
| ACME issuance fails | Port blocked or DNS wrong | Verify inbound with the off-network curl probe. For the default single-host edge, 443 alone suffices (HTTP-01 explicitly disabled, TLS-ALPN-01 on 443); for `--edge tunnel`, also allow 80 (HTTP-01 fallback) |
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
