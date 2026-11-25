---
name: ocliv-operate
description: |
  Operate, qualify, and promote Ocliv (self-hosted localhost-to-HTTPS
  tunnel) on the production Pi or staging. Use when asked to deploy,
  promote, roll back, diagnose relay/agent/Caddy/OAuth issues, run
  pre-flight, or review Ocliv release readiness. Encodes real 2026-11
  deployment lessons: artifact/source alignment, forward-only schema V24
  recovery, guarded restore, native transaction-bound OAuth approval,
  OCL-011 canonical service resolution, OCL-012/013 20-tool MCP control
  plane, and read-only pre-flight discipline.
---

# Ocliv operate

Repo: `/home/bamn/ocliv` (`AGENTS.md` is the binding contract).
Never mutate production without an explicit operator decision.

## Current release behavior (Schema V24)
- **Native self-hosted OAuth is the canonical default** (no Auth0 or external
  identity provider required; optional federated OIDC is supported via
  `ocliv trust NAME --issuer ...` only when explicitly opted in).
- **Local Ocliv Control Center (`ocliv ui`):** Loopback-only authenticated
  graphical interface for managing services, approving visitor OAuth requests,
  revoking clients, and editing agent permissions without manual JSON editing.
- **Service-name-first operations & canonical resolver (OCL-011):** Pass
  human-readable service names (`ocliv status NAME`, `ocliv mcp url NAME`,
  `ocliv mcp check NAME`, `ocliv service pending NAME`, `ocliv service approve NAME`,
  `ocliv service reconcile NAME`). Explicit route IDs resolve only that exact ID;
  valid local bindings take precedence over label matching; historical `HOST_MISMATCH`
  and revoked routes are excluded from ordinary name discovery (retained in
  `ocliv mcp list`); genuine ambiguity fails closed.
- **Agent-facing MCP control plane (OCL-012/013):** Both `ocliv mcp manage` and
  `integrations/skybridge` expose the closed 20-tool control plane gated by
  per-principal, immutable-service-ID durable operator permissions (`0600`
  `agent-permissions.json`). Unadvertised legacy tools are rejected fail-closed.
  Note: for local agents running with unrestricted shell access under the same
  OS user account, an MCP permission file cannot constrain direct CLI/file access;
  use an isolated OS/execution identity when a hard security boundary is required.
- **Visitor authorization workflow (zero pairing secrets copied):**
  1. Publish via Control Center (`ocliv ui`) or `ocliv host mcp PORT --name NAME --trust chatgpt`.
  2. Client (e.g. ChatGPT) initiates standard OAuth against `ocliv mcp url NAME`.
  3. Approve the exact transaction in Control Center (**Access & Connections**) or via
     `ocliv service pending NAME` → `ocliv service approve NAME --challenge <cns_...>`.
     Never use legacy pairing unless explicitly recovering via `--legacy-pairing --client <id>`.
- `ocliv mcp PORT` defaults to managed OAuth; explicit `--auth` passes
  through. `publish --stdio` is valid only as `--auth ocliv-managed`
  through the bounded adapter.
- Single-host publishing does not require Tailscale (loopback relay + Caddy TLS edge).

## Iron rules
1. **Artifact must match source.** Never deploy a binary built from an older
   or dirty working tree. Build from the exact HEAD in a clean detached worktree
   (`scripts/release/build-release.sh --production`), record SHA-256, and verify
   on the target host. Never transfer soak or qualification receipts across
   different commits or binaries.
2. **Schema V24 is forward-only.** `store.Open` migrates forward; an older
   binary refuses a newer DB (`unknown state schema version`). There is NO
   paired binary+database downgrade once the DB advances. Recovery is
   roll-forward: guarded `ocliv relay restore` (migrates backup to V24) +
   candidate binary. Never reinstall an older binary after migration.
3. **Use the guarded restore, never `cp -a` of the DB.** The restore guard
   refuses resurrection of revoked keys/leases/publications/managed
   clients/grants/tokens/trust policies/visitor policies.
4. **Restore preserves availability, not post-backup state.** `--reset-authority`
   additionally retires the JWT signing key, managed authority, pending
   consents/OIDC tx, trust/visitor policies, and wipes encrypted OIDC secrets.
5. **Read-only pre-flight first; hard stop before mutation.** Check
   `/health/live`, `/health/ready`, installed binary digest, candidate digest,
   and live DB schema via read-only Python `sqlite3` (`uri mode=ro`).
6. **Staging before production, always.** Isolated dir (`0700`), separate DB,
   loopback ports, real target-arch binary.

## Secret hygiene
- Never print env file values, pairing secrets, refresh tokens, signing keys,
  or OIDC client secrets in logs or MCP tool responses.
- Never `sudo -n cat` files that may contain tokens.

## Evidence discipline
- Track verification strictly by exact commit SHA in `docs/qualification/CURRENT.md`.
- Record `NOT VERIFIED` for anything not actually exercised.
