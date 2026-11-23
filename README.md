# Ocliv

**Self-hosted HTTPS tunneling and OAuth-protected MCP hosting with zero inbound ports on publisher machines.**

Ocliv lets you expose local web apps (`localhost:3000`) and local Model Context Protocol (MCP) servers over trusted HTTPS through a relay you control. Publishers connect **outbound** over an authenticated WebSocket (`WSS` + `yamux`) tunnel—no router port forwarding, no inbound firewall rules, and no unauthenticated MCP exposure.

```text
  Browser / ChatGPT / MCP Client
               │  HTTPS (Caddy TLS edge)
               ▼
       ┌───────────────┐
       │  Ocliv Relay  │  Ed25519 auth · OAuth 2.1 · SQLite state
       └───────▲───────┘
               │  Outbound WSS + yamux (Ed25519-authenticated)
       ┌───────┴───────┐
       │ Ocliv Agent   │  Zero inbound listening sockets
       └───────┬───────┘
               │  127.0.0.1
               ▼
     Local App / MCP Server
```

---

## Key Features

- **Protected by default:** HTTP/WebSocket tunnels require access control unless `--public` is explicitly granted by tenant policy.
- **Authenticated MCP hosting:** Every published MCP route requires OAuth (`--auth ocliv-managed` or `--auth upstream-oauth`). Anonymous publication is refused.
- **Stable route identity:** Named publications (`--name`) preserve your public route across publisher restarts and reconnects.
- **Stdio-to-HTTP MCP bridging:** Expose local stdio MCP servers (`ocliv mcp publish --stdio ...`) through isolated per-client Streamable HTTP sessions.
- **Signed release supply chain:** Ed25519-signed release manifests, SHA-256 verification, pre/post-swap binary validation with automatic rollback, and monotonic anti-rollback protection.
- **Zero-trust backup & restore:** WAL-safe `VACUUM INTO` backups with rollback guards that refuse to resurrect revoked keys, leases, publications, or OAuth grants unless `--reset-authority` is explicitly requested.
- **Flexible edge modes:** Wildcard DNS (`wildcard`, default) for subdomain leases + MCP routes, or `single-host` mode for path-based MCP hosting on a single hostname without wildcard DNS.

---

## Quickstart (Publisher)

### 1. Install `ocliv`

Bootstrap on Linux with cryptographic verification (verifies Ed25519 manifest signature, SHA-256 digest, and binary commit):

```sh
curl -fsS https://relay.example.net/.well-known/install-client.sh | sh -s https://relay.example.net
```

Or update an existing installation:

```sh
ocliv install --relay https://relay.example.net
```

### 2. Pair with your relay

```sh
# On the publisher machine:
ocliv pair https://relay.example.net
# Prints a short display code (e.g. a1b2-c3d4-e5f6) and waits.
# Use `--no-wait` and later `ocliv pair resume` for asynchronous approval.

# On the relay host (operator):
ocliv relay approve a1b2-c3d4-e5f6 --tenant my-tenant
```

*(Headless / automated enrollment via `ocliv login --relay URL --code-file PATH` is also supported.)*

### 3. Publish a local service or MCP server

```sh
# Protected web tunnel (requires wildcard edge):
ocliv 3000
# -> https://<id>.t.example.net

# Managed-OAuth MCP server (works on both wildcard and single-host edges):
ocliv mcp publish --local http://127.0.0.1:8080/mcp --auth ocliv-managed --name mytools
# -> https://relay.example.net/r/<route-id>/mcp

# Stdio MCP server bridged to Streamable HTTP:
ocliv mcp publish --stdio --auth ocliv-managed --name mytools -- ./my-mcp-server
```

### 4. Approve an OAuth MCP client (e.g. ChatGPT)

When an OAuth client registers against a managed MCP route, it lands on a consent screen requesting a single-use pairing secret. Approve it on the relay host:

```sh
sudo ocliv authz pending --data /var/lib/ocliv
sudo ocliv authz approve --data /var/lib/ocliv --client <CLIENT_ID> --tenant <TENANT_ID> --route <ROUTE_ID>
```

### 5. Everyday diagnostics & profiles

```sh
ocliv status       # Active leases, routes, and actionable next steps
ocliv doctor       # Key integrity, relay reachability, local service, DNS/TLS
ocliv mcp list     # Live MCP route status and public URLs
```

Keep staging and production identities isolated using named profiles:

```sh
ocliv profile create production
ocliv profile use production
ocliv pair https://production.example.net
ocliv mcp list --profile production
```

---

## Self-Hosting a Relay

Publisher machines never need open ports, but the relay host needs a public IP (no CGNAT), DNS, and Caddy + `ocliv relay serve`:

```sh
# Diagnose host prerequisites without making changes:
ocliv relay setup --check

# Provision relay + Caddy (wildcard default):
sudo ocliv relay setup --auto --hostname example.net --dns-provider cloudflare --acme-email ops@example.net
```

Two production edge modes are supported:
- **`wildcard` (default):** Wildcard DNS (`*.t.<domain>`) + single DNS-01 wildcard certificate. Supports both HTTP/WS tunnels and MCP routes.
- **`single-host`:** Single public hostname with standard ACME TLS (no wildcard DNS required). Serves agent control and path-based MCP routes (`/r/<route-id>/mcp`).

See [docs/SETUP.md](docs/SETUP.md), [docs/HOME-HOST.md](docs/HOME-HOST.md), [docs/VPS.md](docs/VPS.md), and [docs/OPERATOR.md](docs/OPERATOR.md) for complete deployment guides.

---

## Security Model

- **Default-deny exposure:** Tunnels are private by default; `--public` requires explicit tenant policy opt-in (`ocliv relay tenants policy set <TENANT> --allow-public=true`).
- **Mandatory MCP authorization:** `ocliv-managed` terminates OAuth 2.1 (DCR, PKCE S256, rotating refresh tokens, revocation) at the relay and strips client bearer tokens before forwarding to local upstreams; `upstream-oauth` verifies resource metadata binding before serving.
- **Fail-closed credentials & state:** Private keys and environment files are loaded via single-FD `O_NOFOLLOW` with regular-file, `0600`, and ownership checks. Schema migrations are strictly forward-only.
- **Signed release trust root:** Release manifests are authenticated against an embedded Ed25519 trust root (`active` / `retiring` / `revoked` lifecycle), rejecting `dirty=true`, `non_production=true`, missing `govulncheck=pass`, or sequence rollbacks.

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model and security invariants.

---

## Building & Testing from Source

Requires Go 1.24+ (single Go module, `CGO_ENABLED=0`).

```sh
# Build binary:
go build -trimpath -o dist/ocliv ./cmd/ocliv

# Repository hygiene, formatting, vet, and test suites:
./scripts/check-repo-hygiene.sh
go vet ./...
go test ./... -count=1 -timeout=420s
```

---

## Documentation & Skills

| Resource | Purpose |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Relay installation, edge modes, and TLS setup |
| [docs/OPERATOR.md](docs/OPERATOR.md) | Day-2 operations, backups, restores, and key lifecycle |
| [docs/MCP-HOSTING.md](docs/MCP-HOSTING.md) | Publishing local HTTP and stdio MCP servers |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, authority boundaries, and crypto invariants |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Wire protocol and capability negotiation |
| [docs/qualification/CURRENT.md](docs/qualification/CURRENT.md) | Current verification ledger by exact commit SHA |
| [skills/ocliv-setup-and-ops/SKILL.md](skills/ocliv-setup-and-ops/SKILL.md) | Portable AI agent skill for setting up and troubleshooting Ocliv |

---

## Repository Layout

- `cmd/ocliv/` — Unified CLI and relay entrypoint
- `internal/` — Core Go packages (`access`, `agent`, `authz`, `cli`, `config`, `doctor`, `identity`, `installer`, `lease`, `limits`, `mcp`, `protocol`, `proxy`, `relay`, `setup`, `store`, `transport`)
- `packaging/` — Systemd units, Caddyfiles, and signed client bootstrap installer
- `scripts/` — Repository hygiene, reproducible release builder, and qualification harnesses
- `skills/` — Portable AI agent operator skills
- `tests/` — Integration suites and fixtures
- `docs/` — Operator, setup, security, protocol, and qualification documentation
