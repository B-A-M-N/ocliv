# Ocliv Relay on a Publicly Addressable Linux VPS

One Linux VPS with a public IP is the simplest production relay: no LAN, no router port forwarding, and no dynamic DNS. The relay still binds loopback only; Caddy terminates public TLS.

## Prerequisites

- A `systemd`-based Linux VPS (`amd64` or `arm64`; 1 vCPU / 1 GB RAM suffices for light use) with a public IPv4 address (IPv6 optional).
- A domain (or subdomain) you control, with DNS you can edit.
- SSH access as `root` (or a `sudo` user) for setup.

## 1. Install the signed `ocliv` release binary

Download and verify the Ed25519-signed Linux release binary directly from GitHub Releases (no Go, Git, or Docker required):

```sh
curl -fsSL https://raw.githubusercontent.com/B-A-M-N/ocliv/master/packaging/install/install-relay.sh | sudo sh
```

## 2. Configure DNS & firewall

- Create an `A` record for `relay.example.net` pointing to the VPS public IPv4 (and `AAAA` if using IPv6).
- For the default `wildcard` edge (subdomain web tunnels + MCP routes), also create a wildcard `A` record `*.t.example.net` pointing to the same IP.
- Open TCP `443` (and SSH `22` restricted to your admin IP). Neither `wildcard` nor `single-host` requires TCP `80`.

## 3. Diagnose and provision with `ocliv setup`

```sh
# 1. Diagnose prerequisites without making changes:
ocliv setup --check

# 2. Store your DNS provider API token in an owner-only file (0600):
printf '%s' "$DNS_TOKEN" > ~/.dns-token && chmod 600 ~/.dns-token

# 3. Provision pinned Caddy + systemd relay unit + TLS (default wildcard edge):
sudo ocliv setup --auto \
  --hostname relay.example.net \
  --dns-provider cloudflare \
  --acme-email ops@example.net \
  --token-file ~/.dns-token
```

For single-host MCP routes without wildcard DNS, pass `--edge single-host` instead.

## 4. Verify external HTTPS (required before production use)

From an external network (e.g., phone on cellular data, never `-k`):

```sh
curl -v https://relay.example.net/v1/agent/challenge
```

TLS must verify with system roots; a `4xx` response from the relay proves `DNS → 443 → Caddy → loopback ocliv-relay`.

## 5. Enroll a publisher machine and host a service

```sh
# On the relay host (preferred — secure enrollment over SSH):
ocliv device add user@publisher --install

# On the publisher machine:
ocliv host mcp 8765 --name tools --trust chatgpt
ocliv status
```

If SSH is unavailable between the relay and publisher, fall back to interactive pairing (`ocliv pair https://relay.example.net` on the publisher, then `ocliv relay approve <CODE> --tenant default` on the relay).

## Rollback & Recovery

- **Binary rollback:** `ocliv update` and `install-relay.sh` validate binaries before swap; keep the prior binary as `/usr/local/bin/ocliv.prev` for immediate rollback (`mv /usr/local/bin/ocliv.prev /usr/local/bin/ocliv && systemctl restart ocliv-relay`).
- **State backup & restore:** Relay state lives in `/var/lib/ocliv/ocliv.db`. Use `ocliv relay backup` and `ocliv relay restore` per [OPERATOR.md](OPERATOR.md) — restoring an older snapshot never resurrects revoked keys, leases, publications, grants, or trust policies unless `--reset-authority` is explicitly passed.
- **Full teardown:** `systemctl disable --now ocliv-relay`, remove DNS records, and close firewall ports.
