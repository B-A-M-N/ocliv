# Connecting Ocliv MCP Servers to ChatGPT and Gemini

This guide covers the exact, end-to-end steps to register an Ocliv-hosted MCP server with **ChatGPT** and **Gemini (Google)** using Ocliv's native self-hosted OAuth 2.1 authorization server — **no Auth0, no external IdP, and no manual pairing-secret copying required**.

> New to terminals, MCPs, or self-hosting? Start with the plain-English [Beginner's Manual](FOR_BEGINNERS.md) first, including its section on **the real dangers of MCPs** and safe operating habits.

---

## Prerequisites

1. **Public HTTPS Relay** running `ocliv-relay` behind Caddy with a valid public TLS certificate (either `wildcard` default or `single-host` edge mode). See [docs/SETUP.md](SETUP.md).
2. **Enrolled Publisher** machine connected to your relay (`ocliv device add user@host --install`, or `ocliv device add --local`).
3. **Published MCP Service** running locally and hosted via Ocliv:
   ```sh
   # Managed OAuth (recommended when your local MCP server has no OAuth of its own):
   ocliv host mcp 8765 --name mytools --trust chatgpt

   # Or for a stdio MCP server:
   ocliv host mcp --stdio --name mytools --trust chatgpt -- /path/to/mcp-server
   ```
4. **Verify readiness before registering with any remote assistant:**
   ```sh
   ocliv status mytools
   ocliv mcp url mytools
   ocliv mcp check mytools
   ```
   Confirm `status` reports `SERVING` / `READY` and `mcp check` reports transport + OAuth discovery `PASS`.

> **Service-name-first operations:** Always pass your service name (`mytools`) to `ocliv status`, `ocliv mcp url`, `ocliv mcp check`, `ocliv service pending`, `ocliv service approve`, `ocliv trust`, and `ocliv connect`. Ocliv's canonical resolver maps the service name deterministically to its bound publication without requiring you to memorize route IDs.

---

## Part 1: Registering an MCP Server with ChatGPT

Ocliv implements the full MCP OAuth 2.1 + PKCE S256 + RFC 7591 Dynamic Client Registration (DCR) + RFC 8707 Resource Indicator flow natively.

### 1. Trust ChatGPT's redirect URI on your service

If you did not pass `--trust chatgpt` when hosting, add it now:

```sh
ocliv trust mytools chatgpt
```

This creates a route-scoped trust policy pinning ChatGPT's exact HTTPS OAuth callback URI (`https://chatgpt.com/connector_platform_oauth_redirect`).

### 2. Copy your canonical MCP URL

```sh
ocliv mcp url mytools
```

Example output:
```text
https://relay.example.com/r/jr8x2Txyoa1jPs22CROuBQ/mcp
```

### 3. Add the connector in ChatGPT

1. Open **ChatGPT** → **Settings** → **Connectors / Apps** (enable Developer Mode if your plan requires it for custom MCP servers).
2. Click **Create** / **Add MCP Server**.
3. Enter:
   - **Name:** `mytools` (or any display name)
   - **MCP Server URL:** `https://relay.example.com/r/jr8x2Txyoa1jPs22CROuBQ/mcp`
   - **Authentication:** **OAuth**
4. Click **Create / Connect**.

ChatGPT discovers `/.well-known/oauth-protected-resource/r/<route-id>/mcp`, registers itself via DCR, and opens Ocliv's authorization page in your browser.

### 4. Approve the exact authorization transaction natively (no pairing secrets)

On your publisher machine, inspect the pending authorization transaction:

```sh
ocliv service pending mytools
```

Verify the displayed `client`, `name`, and `redirect` URI match your ChatGPT connection, then approve that exact transaction by its challenge ID:

```sh
ocliv service approve mytools --challenge <CHALLENGE_ID>
```

*(In an interactive terminal you can also run `ocliv service approve mytools` and confirm at the prompt; non-interactive scripts require an explicit `--challenge` and fail closed otherwise.)*

The browser page completes automatically over POST-only same-origin completion, redirects back to ChatGPT with the PKCE-bound authorization code, and ChatGPT exchanges it for an access token + rotating refresh token pair.

### 5. Day-2 lifecycle (disable/enable & revocation)

- **Temporarily pause without re-authorizing:**
  ```sh
  ocliv stop mytools
  # ...later...
  ocliv start mytools
  ```
  The public route URL, durable service identity, and active OAuth grants remain intact.
- **Deny a pending request:**
  ```sh
  ocliv service approve mytools --challenge <CHALLENGE_ID> --deny
  ```
- **Revoke an active ChatGPT client immediately:**
  ```sh
  ocliv revoke client <CLIENT_ID> --service mytools
  ```
- **Remove the ChatGPT trust policy:**
  ```sh
  ocliv untrust mytools chatgpt
  ```

---

## Part 2: Registering an MCP Server with Gemini (Google)

Gemini and Google Connected Apps use a confidential OAuth client (`client_id` + one-time `client_secret`) bound to your exact MCP route. Ocliv manages registration, secret delivery, rotation, and revocation through `ocliv connect google`.

### Option A: Gemini MCP connector (`--type gemini`)

1. Register and approve a confidential OAuth client for your service:
   ```sh
   ocliv connect google mytools --type gemini --approve --secret-out ~/mytools-gemini-secret.txt
   ```
   *(If your Gemini integration requires a specific callback URL, pass `--redirect https://...`. Use `--json --secret-out PATH` for machine-readable output.)*
2. Ocliv validates your live discovery metadata, registers the confidential client on your relay over the Ed25519-signed management channel, records the `provider_bindings.google` metadata on your canonical `mytools` service record, and writes the one-time `client_secret` to `~/mytools-gemini-secret.txt` (`0600`).
3. In your **Gemini** MCP connector configuration, enter:
   - **MCP Server URL:** from `ocliv mcp url mytools`
   - **Client ID:** printed by `ocliv connect google`
   - **Client Secret:** contents of `~/mytools-gemini-secret.txt`
4. Complete the OAuth connection in Gemini, then securely delete the temporary secret file (`rm ~/mytools-gemini-secret.txt`).

### Option B: Google Connected App with domain verification (`--type connected-app`)

If your Google integration requires domain verification via `/.well-known/google-connected-apps`:

1. Publish your Google domain verification token on the relay first:
   ```sh
   ocliv google verify-domain --help
   ```
2. Run `ocliv connect google` with `--type connected-app`:
   ```sh
   ocliv connect google mytools \
     --type connected-app \
     --verification-token-file /path/to/token.txt \
     --approve \
     --secret-out ~/mytools-google-secret.txt
   ```
   Ocliv verifies `/.well-known/google-connected-apps` returns valid `application/json` matching your token before registering the client.

### Managing, rotating, and revoking a Gemini / Google binding

- **Check current binding status:**
  ```sh
  ocliv connect status mytools
  ```
- **Rotate credentials cleanly (atomic cutover revoking the previous client):**
  ```sh
  ocliv connect google mytools --type gemini --approve --update --secret-out ~/mytools-gemini-secret-new.txt
  ```
- **Revoke the Gemini / Google client immediately:**
  ```sh
  ocliv connect revoke mytools
  ```
  *(Once revoked, Ocliv refuses to silently resurrect the revoked grant; pass `--reconnect` explicitly to mint a fresh client.)*

---

## Troubleshooting

| Symptom | Check & Fix |
| :--- | :--- |
| `ocliv status mytools` shows `HOST_MISMATCH` or stale binding | Run `ocliv service reconcile mytools` to atomically repair the local binding to the uniquely compatible publication. |
| `ocliv mcp check mytools` fails discovery or TLS | Confirm Caddy is running on the relay (`sudo systemctl status caddy`), DNS resolves publicly off-LAN, and port 443 is reachable. |
| ChatGPT stalls on the authorization page | Run `ocliv service pending mytools` and approve the exact challenge with `ocliv service approve mytools --challenge <ID>`. |
| `ocliv connect google` fails with `not authoritatively published` | Ensure the service is started (`ocliv start mytools`) and `ocliv mcp check mytools` passes before running `connect google`. |
| Need to inspect all historical/disabled routes on the relay | Run `ocliv mcp list` for full administrative inventory (historical `HOST_MISMATCH` and revoked routes are kept there for audit while excluded from ordinary service-name discovery). |

---

## Agent-Facing Management Boundary & Canonical Local Integration

- **Canonical local MCP management integration:** **AgentGateway** (`ocliv mcp manage` stdio target, exposing the 20-tool control plane) is the canonical local agent integration. Any legacy standalone registered Ocliv MCP entry outside AgentGateway is retired — remove stale standalone entries rather than running parallel management servers.
- **Shared-principal boundary (AgentGateway stdio):** All callers sharing a local AgentGateway stdio connection share the same management principal (`transport_isolation: "shared-local-stdio"`, `caller_isolation: "shared_local_stdio_no_per_remote_caller_isolation"`). This is safe only when every caller using that transport is intentionally authorized to share the same management authority. For independently isolated per-remote-agent authorization, deploy the Skybridge integration (`integrations/skybridge/`) behind verified `ocliv-ingress-v2` assertions.
- **Canonical human operator interface:** Use **Ocliv Control Center (`ocliv ui`)** for adding services, connecting ChatGPT/Gemini, approving visitor logins, and managing per-service agent permissions.
