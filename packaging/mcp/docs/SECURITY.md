# Ocliv MCP runtime — security notes (staging + self-host)

Ocliv transports and authenticates; it does not implement OAuth
identity issuance. Three boundaries stay separate:

1. Agent identity: only enrolled keys (Ed25519, one-time codes) can
   attach tunnels. Revoke with `ocliv access revoke` or relay-side key
   revocation; revocation denies new calls immediately (503) and the
   publisher exits instead of reconnecting on a revoked credential.
2. Visitor identity: path routes with `--auth upstream-oauth` bypass
   Ocliv visitor auth and forward `Authorization` byte-identical to the
   upstream server, which MUST validate issuer, audience, expiry, and
   scopes before executing tools. `--auth fixture-anonymous` is refused
   by `mcp publish`: anonymous endpoints are loopback-only (`mcp serve`).
3. Tool authority: publishing an MCP endpoint never grants shell,
   filesystem, or process control. The only executed command is the
   operator's own `ExecStart`; remote clients cannot select executables.

Credential handling:

- Tokens live in owner-only files or env, never in URLs, logs, or
  `--json` output. `mcp doctor` never prints secrets.
- The binding file (`MCP_RESOURCE_FILE`) carries a public URL, not a
  secret, but is written atomically (0600) so readers never see a tear.
- The lab CA bundle (`OCLIV_CACERT`/`MCP_CACERT`) only ADDS trust for a
  private edge; verification is never disabled (no `-k`, no
  `InsecureSkipVerify`, no HTTP fallback anywhere in this package).
- SQLite state (`/var/lib/ocliv/ocliv.db`), enrollment keys, and CA
  private keys are never included in a release archive.

Revocation and recovery: `access revoke` closes the lease and the
publisher removes its route on the way out. A restored database must
never roll back revocations — see `packaging/install/backup-restore.sh`
policy before restoring a relay.
