---
name: ocliv-setup-and-ops
description: Portable guide for discovering a user's environment and setting up, publishing, troubleshooting, and upgrading Ocliv relays, MCP publishers, and OAuth connectors (such as ChatGPT). Use when a user wants to install, configure, expose local MCP/HTTP services, connect an OAuth client, or troubleshoot Ocliv on any machine.
---

# Ocliv Setup, Publishing & Troubleshooting Guide

This skill is **environment-agnostic**: never hardcode hostnames, IPs, ports, or paths. Always discover the user's topology and goal first, then execute the minimal matching workflow.

---

## 1. Discovery First (Before Running Mutations)

Determine three facts from the user or read-only inspection:
1. **Role of this machine:**
   - **Relay host** (publicly reachable server/Pi running `ocliv-relay` + TLS edge like Caddy)
   - **Publisher host** (workstation/server running local MCP or HTTP services)
   - **Both**
2. **Edge / DNS topology:**
   - **`wildcard` (default):** Wildcard DNS (`*.t.<domain>`) + DNS-01 wildcard cert — supports both arbitrary HTTP/WS leases (`https://<name>.t.<domain>`) and MCP path routes.
   - **`single-host`:** One public hostname (`https://<host>`) without wildcard DNS — serves agent control + path-based MCP routes (`https://<host>/r/<route-id>/mcp`) via normal ACME TLS (HTTP-01 or TLS-ALPN-01).
   - **`tunnel`:** Explicit non-canonical lab/compatibility mode only.
3. **Existing state (read-only checks):**
   - Relay host: `systemctl status ocliv-relay`, `systemctl cat ocliv-relay`, Caddyfile location, DB path (typically `/var/lib/ocliv/ocliv.db`).
   - Publisher host: `which ocliv`, `~/.config/ocliv/config.toml`, `systemctl --user list-units '*ocliv*'`, local listening services (`ss -ltnp`).

**Safety rule:** Never mutate, migrate, or restart a live production `ocliv-relay` or its database without explicit user approval and a WAL-safe backup (`ocliv relay backup`) first.

---

## 2. Core Workflows

### A. Initial Relay Setup (Relay Host)
- Use the canonical guided setup: `sudo ocliv relay setup`
- Ensure the relay binds loopback only (e.g., `127.0.0.1:8080`) behind the TLS edge (Caddy), which must overwrite `X-Forwarded-For` / `X-Forwarded-Proto` and strip `X-Forwarded-Host`.
- If port 80 is occupied (e.g., by Pi-hole or another web server), move Caddy's HTTP listener off 80 and use TLS-ALPN-01 on 443 (single-host) or DNS-01 (wildcard).

### B. Enrolling a New Publisher Machine
1. Install `ocliv` via the relay's signed bootstrap installer (`install-client.sh`) or verified release binary.
2. Pair the publisher:
   - **Publisher:** `ocliv pair https://<relay-host>` (or `--no-wait` + `ocliv pair resume`)
   - **Relay operator:** `ocliv relay approve <DISPLAY_CODE> --tenant <TENANT> --data <DATA_DIR>`
3. Verify enrollment: `OCLIV_RELAY_URL=https://<relay-host> ocliv mcp list`

### C. Publishing a Local MCP Server (Managed OAuth)
1. Confirm the local MCP server responds on localhost **before** debugging Ocliv (see Section 3).
2. Publish:
   ```bash
   ocliv mcp publish --local http://127.0.0.1:<PORT>/mcp --auth ocliv-managed --name <NAME> --relay https://<relay-host>
   ```
3. Note the printed public URL: `https://<mcp-host>/r/<route-id>/mcp`.

### D. Connecting an OAuth MCP Client (e.g., ChatGPT)
1. Add `https://<mcp-host>/r/<route-id>/mcp` in the client with **OAuth** authentication.
2. When the client registers and lands on the Ocliv consent page asking for a **pairing credential**, run on the relay host:
   ```bash
   sudo ocliv authz pending --data <DATA_DIR>
   sudo ocliv authz approve --data <DATA_DIR> --client <CLIENT_ID> --tenant <TENANT_ID> --route <ROUTE_ID>
   ```
3. Paste the printed pairing secret into the consent page, then verify `tools/list` and `tools/call`.
4. To revoke access later:
   ```bash
   sudo ocliv authz revoke --data <DATA_DIR> --client <CLIENT_ID> --tenant <TENANT_ID> --route <ROUTE_ID>
   ```

---

## 3. Systematic Troubleshooting (Eliminate Guesswork)

Always isolate the failing layer in order: **External TLS → Relay Auth → Publisher Tunnel → Local Upstream**.

1. **External TLS / Reachability:**
   - Test from an external network (e.g., cellular, no VPN/LAN) against `https://<relay-host>/v1/agent/capabilities` (expect `200 OK` with normal system-trusted TLS, no `-k`).
   - Note: `/_ocliv/healthz` is an edge/loopback health route; hitting it externally returns `421 misdirected visitor requires tunnel auth` (which still proves TLS + relay reachability, while `/v1/agent/capabilities` returns `200`).
2. **Stale Publisher Relay URL:**
   - If `ocliv mcp list` tries to dial `127.0.0.1:<port>`, `~/.config/ocliv/config.toml` has a stale test URL. Override with `OCLIV_RELAY_URL=https://<relay-host>` or fix `config.toml`.
3. **OAuth Succeeds but Client Reports "No Tools Exposed":**
   - Test the local MCP upstream directly on localhost with a two-step MCP handshake (`initialize` → capture `mcp-session-id` → `tools/list`):
     ```bash
     HDR=$(mktemp)
     curl -sS -D "$HDR" -o /tmp/mcp-init.out -X POST \
       -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
       -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1.0"}}}' \
       http://127.0.0.1:<PORT>/mcp
     head -n 1 "$HDR"
     SID=$(grep -i '^mcp-session-id:' "$HDR" | awk '{print $2}' | tr -d '\r')
     curl -sS -X POST -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
       -H "mcp-session-id: $SID" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
       http://127.0.0.1:<PORT>/mcp | head -c 500
     rm -f "$HDR" /tmp/mcp-init.out
     ```
   - If `initialize` returns `500` on localhost (common with MCP aggregators/gateways when one downstream target port died or moved), inspect the backend logs and `ss -ltnp` rather than debugging Ocliv.
4. **Public HTTP/WS Lease Denied (`tunnel credential rejected`):**
   - Tenant policy defaults to `allow_public=false`. Enable only when intentionally exposing a public lease:
     `ocliv relay tenants policy set <TENANT> --allow-public=true --data <DATA_DIR>`

---

## 4. Safe Upgrades & Rollback

- Schema upgrades are **forward-only**: an older binary refuses a newer database schema.
- Always take a WAL-safe backup BEFORE replacing the relay binary:
  ```bash
  sudo ocliv relay backup --data <DATA_DIR> --out <BACKUP_PATH>
  sudo ocliv relay validate-backup --in <BACKUP_PATH>
  ```
- When serving a signed release bundle from a relay (`--release-manifest`, `--release-manifest-sig`, `--release-artifacts`), every artifact declared in `release-manifest.json` (e.g., both `amd64` and `arm64`) must exist in the artifact directory with matching SHA-256s.
- Rollback must restore **both** the previous binary and the guarded backup (`ocliv relay restore --relay-stopped`); never raw-copy SQLite files over a live database.
