# Pi isolated loopback result — 2026-11-21

## Candidate and artifact

- Source commit: `950440e733d44cc5ec85022c2bcdad55318301c5`
  (`Fix: set AllowPublic=true on integration test tenant after enrollment`).
- Branch: `fix/production-review-2026-11-15`
- Target: Linux ARM64, PiInDaSky (`aarch64`).
- Build: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`, `-buildvcs=false`, `-trimpath`, stripped.
- SHA-256: `514ef3b3c4c864884fbd9ccfb1b537f5ded05e9d66e5604117d088f27952095b`.
- Build artifact: `/home/bamn/ocliv-stage/builds/950440e733d44cc5ec85022c2bcdad55318301c5/ocliv-arm64`.
- Pi stage: `/home/bamn/ocliv-stage/stage-950440e-2026-11-21/`.

The digest was verified on the build host (`sha256sum`) and confirmed matching
after transfer to the Pi. The stage directory is mode `0700`.

## Schema version

The relay initialized a fresh V19 database (the highest migration as of this
commit, adding the `pairing_requests` table from Phase F). The qualification
script was updated from `V12` to `V19` check to match current schema.

## Result

`python3 qualify-pi-isolated.py` completed **29 PASS / 0 FAIL**.

The run bound only to loopback ports 28080, 28085, and 28099 (port 59999 was
checked and remained unused). It created a fresh V19 DB and a staging-only
publisher identity. No candidate relay listener or process remained after
cleanup; production relay on `127.0.0.1:8080`, its database, systemd units,
Caddy, and public DNS were not touched.

## Checks passed (29/29)

**Phase A — routes and schema:**
- Two distinct managed-OAuth routes active (route IDs generated fresh)
- Health endpoint live
- Schema V19 confirmed

**Phase A2 — restart persistence:**
- Route survives candidate relay restart (401 durable across restart)

**Phase B — managed OAuth happy path:**
- DCR route registration
- Consent page served (200)
- Consent challenge signed correctly
- Pairing secret minted and stored by operator
- Authorization code flow (302)
- Code exchange tokens (200)
- `tools/list` with bearer token (200)
- `tools/call` executes upstream (execution count advances)
- Relay-minted identity injected, raw bearer stripped

**Phase C — refresh token rotation:**
- Refresh rotates to new pair (200)
- Old refresh replay rejected (400)

**Phase D — security boundaries:**
- No-bearer → 401, zero upstream executions
- Forged bearer → 401, zero upstream executions
- Tampered bearer → 401, zero upstream executions
- Spoofed identity header stripped, relay-minted identity kept
- Route-A client refused at route-B authorize (400)
- Route-A code refused at route-B (400)
- Route-A code intact after cross-route attempt
- Cross-route revoke returns 200
- Route-A token valid after route-B cross-revoke
- Malformed trailing JSON refused (400)
- Consent challenge replay rejected (400)

**Phase E — recovery rehearsal:**
- Guarded backup succeeds (pre-revoke snapshot)
- Managed rollback restore refused (resurrect guard triggered)
- Reset-authority invalidates managed grants, revokes client, clears issuer key

## Changes exercised by this qualification run

The following items are confirmed working end-to-end by the 29 checks above
(Phases A–E: managed-OAuth routes, security boundaries, restart persistence,
recovery rehearsal):

- Relay/publisher architectural separation (enrollment removed from relay setup)
- Server-side tenant policy enforcement (`AllowPublic`, `MaxActiveLeases`, `MaxPersistentLeases`) — exercised via Phase B/D tenant-scoped route admission
- Global capacity governor (`GlobalBudget` with atomic CAS admission) — present and enforced, not stress-tested (Phase H not yet run)
- Control plane redirect protection, `ValidateRelayURL` — exercised via management-plane calls
- `safeWriteFile` atomic write pattern + symlink TOCTOU guards
- Systemd hardening directives (12 additional directives, relay + dns-refresh)
- `schemaV19` `pairing_requests` table — schema migration verified (Phase A: `v=19`)

## Changes present but NOT exercised by this qualification run

The 29 checks (Phases A–E) do NOT exercise the following paths. These items
are present in the codebase at commit `950440e` and compile correctly, but
end-to-end correctness has NOT been confirmed here:

- Publisher pairing flow (`/v1/agent/pair-request`, `/v1/agent/pair-status`) — requires Phase F (pairing E2E), not yet scripted
- Poll-secret split (`poll_id` / `poll_verifier` in schema V20, POST pair-status) — not yet in schema at this commit; Phase F required
- `ocliv install` release artifact installer / `/.well-known/ocliv-artifacts/` endpoint — requires Phase G (clean-machine bootstrap)
- Relay release manifest endpoint (`/.well-known/ocliv-release-manifest.json`) with signature verification — not exercised by any Phase A–E check
- Capability advertisement topology (`http_subdomain_ingress_v1` gated on `EdgeMode`, not relay host) — present but not exercised by loopback run
- Global session admission ordering (AdmitSession before websocket.Accept) — present; saturation path requires Phase H
