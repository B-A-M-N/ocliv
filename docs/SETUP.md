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
3. If detection reports `nat-ipv4-needs-forward`: forward TCP 443 (and
   80 if you keep the default tunnel edge) in the router admin page to
   this host's LAN address. See *Ports* below.
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

# 3. Full bootstrap: DNS sync, edge render (see --edge below), DNS
#    verify, relay_url persist, Caddy install, systemd enable,
#    auto-enroll.
sudo ocliv setup --auto --hostname lab.dynv6.net \
  --acme-email you@addr --token-file ~/.dynv6-token

#    Hosting MCP servers on ONE public hostname instead? Pick the
#    single-host edge (needs no wildcard record, and only TCP 443):
sudo ocliv setup --auto --hostname lab.dynv6.net \
  --acme-email you@addr --token-file ~/.dynv6-token --edge single-host

# 4. From another network (no -k): expect relay 4xx, not TLS errors.
curl -v https://lab.dynv6.net/v1/agent/challenge
```

The token travels only via `--token-file` (0600, owned by root for
`sudo` runs) or the `DYNV6_TOKEN` environment variable set OUTSIDE the
invoked command (e.g. in a shell profile), never as an inline
`TOKEN=... ocliv ...` assignment, which shell history would persist.

## Certificate strategy (read before operating)

Three edges, three issuance models. Pick with `--edge`, one per relay:

- **Tunnel edge (`Caddyfile.tunnel`, `--edge tunnel`, setup's default).**
  On-demand per-hostname certificates: each new `*.t.<domain>` tunnel
  hostname gets its own cert after the relay's ask guard approves the
  request. Ask guard is tested; issuance itself is unverified against
  public ACME (see the qualification table below). This is the
  production shape for generic `ocliv 3000` tunnels.
- **Single-host edge (`Caddyfile.single-host`, `--edge single-host`).**
  ONE public apex hostname carries agent control, unlock pages, and the
  path-based MCP routes `/r/<route-id>/mcp`. ACME issuance PINNED to
  TLS-ALPN-01 on 443 (the template's issuer carries
  `disable_http_challenge`, so the edge never needs port 80 and a host
  where another service owns :80 — Pi-hole — can run it unmodified), and
  no wildcard DNS record or DNS plugin. This is the edge for MCP
  hosting; `docs/MCP-HOSTING.md` documents it. Proven by adapting the
  file with a real `caddy adapt`: one server listening on `:443`, no
  `http_port`, and `challenges.http.disabled: true` on the ACME issuer.
  The pin is deliberate: Caddy enables HTTP-01 and TLS-ALPN-01 by
  default, so an issuer with NO challenge override is not proof of
  anything (it still attempts HTTP-01 over :80 first).
  `scripts/verify-single-host-edge.sh` asserts the explicit disable
  with a negative control that removes it. Live issuance on a public
  host remains NOT VERIFIED. (A loopback smoke-test variant of this
  edge, for exercising the single-host path with no DNS and no ACME,
  is not yet committed: it exists in the working tree as
  `packaging/caddy/Caddyfile.single-host.local` and still needs a
  `caddy validate` before it can be documented here.)
- **Wildcard edge (`Caddyfile`, `--edge wildcard`).** One DNS-01
  wildcard certificate covering all tunnel hostnames. Needs a Caddy
  DNS-provider plugin and credentials (`--dns-provider/--dns-env`);
  `relay init --check` rejects a file with the dns line commented out.
  Not reachable from `setup` without that plugin.

Each model is bounded differently: per-hostname issuance by public rate
limits, single-host by the one apex certificate you already need,
wildcard by DNS-plugin availability. Choose one edge per relay.

**Ports.** Forward TCP 443 always. Forward TCP 80 as well only if you
keep the default tunnel edge (it can fall back to HTTP-01); the
single-host edge disables HTTP-01 explicitly and issues via TLS-ALPN-01
on 443, so it does not need port 80 and a host where another service
owns :80 (Pi-hole, for example) can run it unmodified. Do not "solve" a
busy :80 by setting Caddy's global `http_port`: on edges without an
explicit challenge pin that switches the issuer to HTTP-01 on an
alternate port, and on the pinned single-host edge it is inert —
either way it is never the fix.

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
| `cgnat-no-direct-ipv4` | Carrier-grade NAT | Serve over IPv6 if direct, else `setup --auto --provider oracle` (own OCI account, confirm-gated) |
| `nat-ipv4-needs-forward` persists | Forward missing/wrong | Forward TCP 80+443 to the LAN address in the report; re-run |
| `dns ... not resolving here yet` | Propagation | Wait, then re-run the same command; nothing half-written persists |
| `dns ... not to observed egress` | Stale record / wrong zone | Check the zone answers for this host (dig from another network); fix and re-run |
| `enrollment failed: relay unreachable` | Caddy/relay not serving | `systemctl status ocliv-relay`, `caddy validate`, `ocliv relay doctor` |
| ACME issuance fails | Port blocked or DNS wrong | Verify inbound with the off-network curl probe. For the single-host edge, 443 alone suffices (HTTP-01 explicitly disabled, TLS-ALPN-01 on 443); for the default tunnel edge, also allow 80 (HTTP-01 fallback) |
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
