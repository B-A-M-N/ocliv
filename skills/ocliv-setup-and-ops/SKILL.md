---
name: ocliv-setup-and-ops
description: Portable guide for discovering a user's environment and setting up, publishing, troubleshooting, and upgrading Ocliv relays, MCP publishers, Control Center UI, and OAuth connectors (such as ChatGPT and Gemini). Use when a user wants to install, configure, expose local MCP/HTTP services, connect an OAuth client, or troubleshoot Ocliv on any machine.
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
   - **`wildcard` (default):** Wildcard DNS (`*.t.<domain>`) + DNS-01 wildcard cert — supports both arbitrary HTTP/WS leases and MCP path routes.
   - **`single-host`:** One public hostname (`https://<host>`) without wildcard DNS — serves agent control + path-based MCP routes (`https://<host>/r/<route-id>/mcp`) via standard ACME TLS.
   - **`tunnel`:** Explicit non-canonical lab/compatibility mode only.
3. **Existing state (read-only checks):**
   - Relay host: `systemctl status ocliv-relay`, Caddy status, DB path (typically `/var/lib/ocliv/ocliv.db`).
   - Publisher host: `which ocliv`, `ocliv status`, `ocliv service list`, `systemctl --user list-units '*ocliv*'`.

**Safety rule:** Never mutate, migrate, or restart a live production `ocliv-relay` or its database without explicit user approval and a WAL-safe backup (`ocliv relay backup`) first.

---

## 2. Core Workflows

### A. Operator Control Center (Recommended for Everyday Use)
- Launch the local loopback-only graphical interface:
  ```bash
  ocliv ui
  ```
- Install a desktop application menu shortcut:
  ```bash
  ocliv ui --install-shortcut
  ```
- From Control Center, operators can add/enable/disable/repair services, copy canonical MCP URLs, approve/deny live ChatGPT OAuth login requests, revoke clients, and edit per-agent MCP permissions with checkboxes.

### B. Initial Relay Setup & Publisher Enrollment
1. Relay host:
   ```bash
   sudo ocliv setup --auto --edge-mode single-host --hostname <YOUR_HOST> --acme-email <EMAIL>
   ```
2. Enroll a publisher machine over SSH (no code copying):
   ```bash
   ocliv device add user@publisher-host --install
   # Or on the same host:
   ocliv device add --local
   ```

### C. Publishing a Local MCP Server (Service-Name-First)
```bash
ocliv host mcp <PORT> --name <NAME> --trust chatgpt
ocliv status <NAME>
ocliv mcp url <NAME>
ocliv mcp check <NAME>
```

### D. Connecting ChatGPT (Native Transaction-Bound OAuth — No Pairing Secrets)
1. Paste the URL from `ocliv mcp url <NAME>` into ChatGPT (**Settings → Connectors / Apps → Add MCP Server**, Authentication: **OAuth**).
2. When ChatGPT opens the Ocliv authorization page, approve the exact live transaction in **Ocliv Control Center** (**Access & Connections**) or via CLI:
   ```bash
   ocliv service pending <NAME>
   ocliv service approve <NAME> --challenge <CHALLENGE_ID>
   ```
3. To revoke a client later:
   ```bash
   ocliv revoke client <CLIENT_ID> --service <NAME>
   ```

### E. Connecting Gemini / Google
```bash
ocliv connect google <NAME> --type gemini --approve --secret-out ~/gemini-secret.txt
```
(For Google Connected Apps with domain verification, run `ocliv google verify-domain` first and use `--type connected-app`.)

---

## 3. Systematic Troubleshooting

Always isolate the failing layer in order: **External TLS → Relay Auth → Publisher Tunnel → Local Upstream**.

1. **Stale service binding or `HOST_MISMATCH`:**
   - Run `ocliv service reconcile <NAME> --json` (or click **Repair** in Control Center) to atomically repair the local binding without interrupting healthy live tunnels.
2. **External TLS / Reachability:**
   - Run `ocliv mcp check <NAME>` (or test `https://<relay-host>/v1/agent/capabilities` off-LAN expecting `200 OK`).
   - Apex `/` returning `421` is by design on single-host edges.
3. **OAuth succeeds but client reports no tools:**
   - Run `ocliv doctor <NAME>` and verify the local MCP server responds to `initialize` + `tools/list` on `127.0.0.1:<PORT>/mcp`.

---

## 4. Safe Upgrades & Forward-Only Recovery

- Schema upgrades are **forward-only** (Schema V24): an older binary refuses a newer database schema.
- Always take and validate a WAL-safe backup BEFORE replacing the relay binary:
  ```bash
  sudo ocliv relay backup --data <DATA_DIR> --out <BACKUP_PATH>
  sudo ocliv relay validate-backup --in <BACKUP_PATH>
  ```
- Recovery is **roll-forward** using the guarded restore (`ocliv relay restore --relay-stopped`) with the current/candidate binary — never raw-copy SQLite files and never reinstall an older binary against a migrated schema.
