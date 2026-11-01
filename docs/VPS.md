# Ocliv relay on a publicly addressable VPS (self-managed)

One VPS with a public IP is the simplest production relay: no LAN,
no port forwarding, no dynamic DNS. The relay still binds loopback
only; Caddy terminates public TLS.

## Prerequisites

- A VPS (1 vCPU / 1 GB RAM suffices for light use) running a
  systemd Linux distro, with a public IPv4 address (IPv6 optional
  but recommended: add the `AAAA` record too).
- A domain (or subdomain) you control, with DNS you can edit.
- SSH access as root (or a sudo user) for setup only.

## Setup

1. DNS first, before touching the VPS: `A` record
   `relay.example.net` → VPS public IPv4 (and `AAAA` → IPv6 if
   assigned). Wait for propagation (`dig +short relay.example.net`
   shows the VPS IP from an outside network). For generic tunnels
   (`ocliv 3000` → `*.t.example.net`) add a wildcard `A` record
   `*.t.example.net` → same IP and use the wildcard edge below.
2. Harden SSH: key-only auth, no password logins, no root password.
   `ufw allow OpenSSH` first so you cannot lock yourself out, then
   `ufw allow 80,443/tcp`, `ufw enable`. If your provider has a
   separate cloud firewall / security group, open 22 (your IP only),
   80, and 443 there too.
3. Copy this repo (or a release tarball) to the VPS, e.g.
   `/opt/ocliv`, and run as root:

   ```
   DOMAIN=example.net MCP_HOST=relay.example.net ./packaging/install/install.sh
   ```

   The installer refuses placeholder domains, validates hostnames,
   builds the binary, keeps the previous binary as `ocliv.prev`
   (first candidate wins across re-runs), writes root-owned
   `0600 /etc/ocliv/relay.env`, and installs the systemd unit without
   starting it. Re-runs are idempotent; conflicting re-runs fail
   closed.
4. Render the edge config on any machine with this repo:

   ```
   ocliv relay init --domain example.net --mcp-host relay.example.net \
     --acme-email ops@example.net --out ./ocliv-relay-deploy
   ```

   For the wildcard namespace instead:

   ```
   ocliv relay init --edge wildcard --dns-provider <name> \
     --acme-email ops@example.net --out ./ocliv-relay-deploy
   ```

   The wildcard edge requires a DNS-01 provider (no Cloudflare
   lock-in: any Caddy DNS plugin works; credentials stay in the
   provider's env var, never in the repo). Copy the rendered
   `Caddyfile` to `/etc/caddy/Caddyfile` (single-host file) and
   `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`
   before reloading Caddy.
5. `systemctl enable --now ocliv-relay`. Enroll publishers from the
   relay host: `ocliv relay issue-enroll --data /var/lib/ocliv
   --tenant NAME`; publishers `ocliv login` against
   `https://relay.example.net`.

## Rollback

- Bad binary: `mv /usr/local/bin/ocliv.prev /usr/local/bin/ocliv`
  and `systemctl restart ocliv-relay` (only the first pre-upgrade
  candidate is kept — verify the new binary before upgrading twice).
- Bad edge config: keep the previous working `/etc/caddy/Caddyfile`
  copy; `caddy validate` before every reload.
- Full retreat: `systemctl disable --now ocliv-relay`, remove DNS
  records, close provider firewall ports. Relay state in
  `/var/lib/ocliv` restores per OPERATOR.md backup/restore —
  restoring an older snapshot never resurrects revoked authority.

## External verification (required before PUBLIC READY)

From a network that is not the VPS provider's LAN and not your
Tailnet (phone on mobile data suffices):

```
curl -v https://relay.example.net/v1/agent/challenge
```

TLS must verify with default trust; a 4xx from the relay proves
DNS → 443 → Caddy → loopback relay. Then `ocliv PORT` on an enrolled
publisher and load the issued URL from the same off-network machine.
Funnel, tailnet, or loopback success never counts — see
[HOME-HOST.md](/home/bamn/ocliv/docs/HOME-HOST.md) for retiring the
staging ingress afterwards.
