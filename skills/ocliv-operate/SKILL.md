---
name: ocliv-operate
description: |
  Operate, qualify, and promote Ocliv (self-hosted localhost-to-HTTPS
  tunnel) on the production Pi or staging. Use when asked to deploy,
  promote, roll back, diagnose relay/agent/Caddy/OAuth issues, run
  pre-flight, or review Ocliv release readiness. Encodes real 2026-11
  deployment lessons: artifact/source alignment, forward-only schema
  recovery, guarded restore, read-only pre-flight discipline.
---

# Ocliv operate

Repo: `/home/bamn/ocliv` (AGENTS.md is the binding contract). Production Pi:
`bamn@10.9.66.170` (LAN; Tailscale `100.95.10.57` only when LAN is down).
Never mutate production without an explicit operator decision.

## Iron rules
1. **Artifact must match source.** Never deploy a binary built from an older
   commit than the reviewed source. Build from the exact HEAD, record
   SHA-256, verify on the target host. If source changed after the binary was
   built, rebuild and re-qualify the delta — do not ship the stale binary.
2. **Schema V11 is forward-only.** `store.Open` migrates forward; an older
   binary refuses a newer DB (`unknown state schema version`). There is NO
   paired binary+database rollback once the DB advances. Recovery is
   roll-forward: guarded `relay restore` (migrates backup to V11) + candidate
   binary. Never reinstall the old binary after migration.
3. **Use the guarded restore, never `cp -a` of the DB.** The restore guard
   refuses resurrection of revoked keys/leases/publications/managed
   clients/grants/tokens (grant identity is the full
   tenant/route/client tuple). A hand-copied DB bypasses all of it.
4. **Restore preserves availability, not post-backup state.** New grants,
   sessions, publications created after the backup can be lost. Say so;
   `--reset-authority` additionally retires the JWT signing key and managed
   authority.
5. **Read-only pre-flight first; hard stop before mutation.** Health
   (`/health/live`, `/health/ready` on the loopback health port), installed
   binary digest, candidate digest, live DB schema via read-only Python
   `sqlite3` (`uri mode=ro`; `store.Open` NEVER called — it migrates).
   Stop before backup, binary swap, migration, restart.
6. **Staging before production, always.** Isolated dir (0700), separate DB,
   loopback ports, real target-arch binary. One narrow change → one focused
   red→green regression → broad gates once → commit.
7. **Docs rot is a safety hazard.** An outdated runbook that tells operators
   to do an impossible rollback is worse than none. Mark superseded
   procedures `SUPERSEDED — DO NOT EXECUTE` with a pointer to the current
   one. Verify every command in a runbook actually exists on the target
   (e.g. `sqlite3` is NOT installed on the Pi; use `python3`).

## Recurring failure patterns (diagnose these first)
- **"not enrolled" right after login** → the harness/subprocess env lost
  `HOME` (a path like `$HOME/ocliv-stage/...` becomes
  `$QUALHOME/ocliv-stage/...`). Use absolute paths; never export HOME for a
  whole SSH command block.
- **Relay "died" after qualification run** → publishers hold the leases; when
  the run ends they exit and the relay exits with them. Expected. Start the
  relay before harnesses that assume it's listening.
- **`Text file busy` replacing the binary** → a process still runs from that
  inode. Kill only specific PIDs from pid files (`pgrep -f`, verify, `kill`),
  never `pkill -f` with a broad pattern.
- **421 Misdirected on the apex** → by design: visitor traffic requires a
  tunnel hostname; route-shaped `/r/<id>/mcp` paths dispatch (404 unknown,
  401 unauthorized). Edge is healthy if TLS/ACME works and shapes dispatch;
  apex 421 is not an outage.
- **`relay doctor` does not report schema version.** Use read-only Python
  `sqlite3` with `mode=ro`.
- **Port in use in staging** → stale processes from an earlier run. Check
  `ss -ltnp`, specific PIDs, then proceed.
- **Stale logs mislead.** After a failed run, delete `pub-*.log`,
  `relay.log`, state dirs before retrying; timestamps in logs tell you which
  era they came from.
- **Health listener default is 127.0.0.1:18080** — staging relays must pass
  `--health-listen` with an isolated port or they collide with production.

## Secret hygiene
- Never print env file values; variable NAMES only.
- Never `sudo -n cat` a file that may contain tokens. If root-only data is
  needed, record it as an explicit operator action.
- Enrollment codes, pairing secrets, dynv6 tokens: file or TTY, never argv,
  never JSON share URLs.

## Evidence discipline
- Every disposition: FIXED (with red-before/green-after), VERIFIED NON-ISSUE,
  ACCEPTED RISK, DEFERRED, or BLOCKED — named with evidence.
- Record NOT VERIFIED for anything not actually exercised (off-LAN edge,
  ChatGPT registration, provider IdP, root-only reads).
- Off-LAN/public-edge baseline must be captured BEFORE promotion so a
  pre-existing edge failure is not misattributed to the new binary.

## Where the current procedure lives
- Promotion runbook: `docs/qualification/PROMOTION-RUNBOOK-2026-11-14.md`
  (source `19d46d8`, candidate `1ceaaff4…`).
- Superseded (do NOT execute): `docs/qualification/PRODUCTION-PROMOTION-PLAN.md`.
- Latest pre-flight: `docs/qualification/PREFLIGHT-2026-11-15.md`.
- Deep history: `AGENTS.md` remediation register.
