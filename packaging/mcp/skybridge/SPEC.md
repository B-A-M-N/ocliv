# Ocliv Hosting Management — Skybridge MCP App

## Value proposition
Operators manage their own hosted Ocliv MCP services from a conversational assistant without shell command composition. The underlying relay is not changed. The assistant interprets intent; Ocliv retains its authoritative admission, enrollment, and OAuth checks.

## Core actions
1. List enrolled operator's publications and display their bound/unbound/revoked state.
2. Publish a **preallowlisted local** HTTP MCP service with explicit operator confirmation.
3. Diagnose a publication with `ocliv mcp doctor`, distinguishing local qualification from external OAuth/ChatGPT checks.
4. Permanently revoke a specific publication by verified publication ID with explicit operator confirmation.

## UX flows
- First view: compact list of publications with name, route and state, plus non-authoritative URL if configured.
- Publish: user names allowlisted service → assistant explains public exposure → user supplies exact `PUBLISH <name>` → tool reports verified-discovery readiness or failure.
- Verify: user identifies publication → doctor tool runs → report local verdict with external limitations.
- Revoke: user selects exact publication → assistant explains irreversible revocation → user supplies exact `REVOKE <publicationId>` → tool rechecks relay state.

## Architecture
- Skybridge `list-publications` view and three tools: `publish-service`, `verify-publication`, `revoke-publication`.
- No new Ocliv management listener or relay protocol changes.
- Local subprocess adapter invokes a fixed Ocliv CLI binary, never an arbitrary shell command.
- Allowlisted IP-literal loopback MCP targets only; process lifetime supervised by the app.
- OAuth mandatory for all tools (audience, issuer, scope `ocliv.manage`), additionally allowlisted subject. No anonymous development bypass.
- Ocliv native publisher enforces its own upstream OAuth resource binding. Never enable `--dev-allow-unverified-discovery`.

## Non-goals
- Generic tunnel management, shell execution, dynamic DNS, IdP implementation, account registration, production ingress, or arbitrary remote URL proxying.

## External prerequisites
- Node.js 24+ and Skybridge dependencies.
- OAuth IdP with JWT access tokens, JWKS discovery and appropriate scope/subject/audience.
- Existing enrolled Ocliv publisher and its exact HOME; Ocliv binary and a real auth-protected local MCP service.
- ChatGPT app registration permission remains independent of working MCP protocol.

## Status
Source scaffold and CLI adapter tests can be performed independently. Deployment and real OAuth/ChatGPT qualification require operator-provided IdP configuration and ChatGPT permission; they must not be represented as complete without evidence.
