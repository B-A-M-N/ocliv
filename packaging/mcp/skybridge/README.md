# Ocliv Hosting Management — Skybridge

A separate OAuth-gated MCP management app for **Ocliv**. Does not modify the Go relay or expose its local administrative interface.

## Prerequisites

- Node.js **24+** and `npm install` (install dependencies and retain the resulting lockfile).
- Existing Ocliv CLI on the same host as the enrolled publisher; no remote shell.
- A real OAuth IdP issuing signed JWT **access** tokens with issuer, audience, `ocliv.manage` scope, and the allowlisted operator's `sub`. Configure the identity provider before public ingress.
- One or more explicitly allowlisted, locally running, OAuth-protected native HTTP MCP servers.

## Configure

Copy `.env.example` to `.env` and set its values using secure local secret storage (do not commit `.env`). Ensure `OCLIV_HOME` is the same isolated HOME as the publisher's enrollment. Skybridge OAuth integration is fail-closed: missing issuer, audience, subject, or Ocliv binary causes startup to fail. Do not use any `--dev-allow-unverified-discovery` override. The app does not implement an OAuth server.

`OCLIV_SERVICES_JSON` is a JSON array of static operator-approved `{name, localUrl, resourceFile?}` entries. URLs must use `127.0.0.1` or `[::1]`, an explicit port, exactly `/mcp`, and no userinfo, query, or fragment. New service targets require changing this operator-controlled configuration. No remote caller can supply a URL or process command.

```
npm install
npm run typecheck
npm test
npm run dev
```

With a compatible IdP configured, Skybridge serves `/mcp`, and DevTools on `/`. **Do not put the app on Funnel or a public Alpic tunnel before checking OAuth access controls and revocation**. This app is the management *control plane*, not a published public tool fixture. The existing `pop-os.tail8d285a.ts.net` URL remains the Ocliv relay and is not automatically the URL of this Skybridge app.

## Security model

- Every tool requires OAuth (signed access token, issuer, audience, `ocliv.manage`) and a matching operator `sub`.
- All mutations require exact `PUBLISH <name>` or `REVOKE <publicationId>` text after human confirmation; callers cannot bypass server-side checking.
- Publishing uses a fixed binary, allowlisted target, and Ocliv's strict OAuth discovery; no shell or extra CLI flags from user input.
- Revocation checks ownership from Ocliv's live list, revokes exact ID, re-queries state. A failed recheck is not reported as success.
- Discovery/CLI output is sanitized at the API boundary; no key material is returned.
- A publisher subprocess must remain alive to keep the publication online; restarting the app does not automatically republish. Ocliv's retained route becomes offline until republished.

## Validation levels

1. Unit tests: parsing, target allowlist, publication IDs, and defensive behavior.
2. Typecheck/build: Skybridge API compatibility on Node 24+.
3. Local integration: real CLI with a private enrolled publisher; no public ingress needed.
4. OAuth: assert unauthenticated=401, wrong scope=403, wrong user denied; authorized operations pass.
5. External: verify public TLS/host/auth from off-LAN and actual host-tool call. **Not yet claimed.**

This is an independent app: Ocliv's existing Funnel ping endpoint is not the Skybridge endpoint and it does not prove ChatGPT app registration.
