# Ocliv Current Qualification Status

**Production Promotion Status:** **HOLD**

This document is the single entry point for current verification status. Dated
historical qualification records live under `docs/qualification/history/`, and
structured evidence/receipts live under `docs/qualification/receipts/`.

Evidence is tracked strictly by exact commit SHA and separated into three
independent tiers: **Source/Unit-Tested**, **Isolated Artifact E2E**, and
**Public/Off-LAN/Live**. Results from earlier commits are NEVER transferred
across schema migrations or security-boundary changes.

## Verified Evidence by Exact Commit SHA

| Commit SHA | Schema | Source / Unit & Race Matrix | Isolated Artifact E2E (Pi `10.9.66.170`) | Public / Off-LAN / Live | Notes |
|---|---|---|---|---|---|
| `950440e` | V19 | PASS | PASS (29/0 loopback) | NOT VERIFIED | Historical baseline (`history/PI-ISOLATED-RESULT-2026-11-21.md`); superseded |
| `8cce9af` | V20 | PASS | NOT VERIFIED | NOT VERIFIED | Superseded by Round 2 & Round 3 remediation |
| `2f635e470183ed464150bdaceb2c1e674313cc27` | V21 | PASS (full suite + race matrix) | **PASS 60/0/0** (0 SKIP, 0 FAIL, strict release mode) | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`3b59bfddd623b133cd6112b17b2e35186adc4ea38e0f9db35e217f608fb853d3`); Phases A–I all PASS on `10.9.66.170`; production `ocliv-relay` (PID 1577) and `caddy` (PID 1574) untouched |
| `11dead068fa06f4dc152b5950aad5f6e233fdd94` | V22 | PASS (unit + hygiene + vet) | **PASS 61/0/0** + **V19→V22 migration 10/0** + **soak harness smoke PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`3b9ba712670d2769929b93152b0fe5af46cccfe7f04b14c6cc255d5c06b0bb67`); superseded by `071d7ff` |
| `071d7ff16638a55684d21f02b3a0cf22d652bda2` | V22 | PASS (installer/store/relay/cli/setup/doctor/systemd + `dash` multi-key test + hygiene + vet) | **PASS 65/0/0** (`--smoke`) + **V19→V22 online-snapshot migration 12/0** + **20s live-workload soak PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`4e35a4016298dc7c2c0825025cdd5afc63d8b138f24d2d825bf44a927e8732a1`); superseded by `b574879` |
| `b574879605e4ec9b1bfd62b356d6b19b05c1126f` | V22 | PASS (`installer`/`relay`/`cli`/`store` + `dash` multi-key/symlink/seq tests + hygiene + vet) | **PASS 65/0/0** (`--smoke`) + **V19→V22 full `--reset-authority` contract migration 12/0** + **20s dual-lane soak PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`3b9988a69dfd99d0e0706f857887798e4dcac8424304a2a714b5100e921981f7`); superseded by `3db67e0` |
| `3db67e0bc9df1990d31a72ec9d7b65bb917ee0cf` | V22 | PASS (`installer`/`relay`/`cli`/`store` + `dash` fail-closed dirty/schema/protocol negatives + hygiene + vet) | **PASS 65/0/0** (`--smoke`) + **V19→V22 migration 12/0** + **20s dual-lane soak PASS** + **`--release-gate` guard PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`5297e7636a15126eec2c897cf8c4cee62e724c5aa9183b402b0adaf9acb04811`); fail-closed `dirty=false`/schema/protocol in both Go & shell installers, mandatory strict-mode protocol + `govulncheck` + SBOM byte hashing, all mutable/key/DB qualification state isolated in ephemeral `WORK_DIR` with strict retained-stage allowlist, deterministic soak 429 recovery + drain + derived pending bound + rolling-window trend gate + `--release-gate` mode, `sqlite_master`-checked migration digests + versioned `RESET_CONTRACT_VERSION=1`; production `ocliv-relay` (PID 1577) and `caddy` (PID 1574) untouched |

## Latest Isolated Pi Staging Receipt (`3db67e0` — non-production staging smoke)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `3db67e0bc9df1990d31a72ec9d7b65bb917ee0cf` (`dirty=false`, `govulncheck=pass`, `non_production=true` pending permanent offline production signing key & `cyclonedx-gomod`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `5297e7636a15126eec2c897cf8c4cee62e724c5aa9183b402b0adaf9acb04811`
- **Release Manifest SHA-256:** `feefd76aebab38bbe521e8bbbcad613b42b7cc94c6c215f83a89a116987e8cb3`
- **Signing Key ID:** `stage-ephemeral-3db67e0` (ephemeral external `0600` Ed25519 key, unlinked immediately after signing)
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/stage-3db67e0-2026-11-21/` (`qual-receipt.json`, `mig-receipt.json`, `soak-receipt.json`) — strict public allowlist verified (`I6 PASS`, zero `.key`/`.db`/`.pem`/`qc.txt` retained).
- **Isolated Staging Qualification (`qualify-pi-isolated.py --smoke --receipt-out ./qual-receipt.json`):** **PASS 65 / SKIP 0 / FAIL 0** (`ephemeral_state_retained: false`).
- **V19→V22 Online-Snapshot Migration Rehearsal (`rehearse-prod-migration.py --receipt-out ./mig-receipt.json`):** **PASS 12 / FAIL 0** (`reset_contract_version: 1`, `sqlite_master`-verified mandatory V22 tables, `preserved_diffs=[]`, all 8 reset authority counts `0`, restored-DB live relay `/health/ready == 200`).
- **Dual-Lane Workload Soak (`soak-isolated.py --duration 20 --warmup 5 --sample-interval 5 --receipt-out ./soak-receipt.json`):** **PASS** (`dataplane_ok_200=5`, `disconnect_failed_as_expected=true`, `reconnects_completed=1`, `route_expected_401=5`, `pair_ok=5`, `expired_still_pending=0`, FDs `15->15`, RSS `16044KB->16456KB`, `active_sessions=2`); `--release-gate` verified to refuse `--duration 20`.
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Staging Receipt (`b574879` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `b574879605e4ec9b1bfd62b356d6b19b05c1126f` (`dirty=false`, `govulncheck=pass`, `non_production=true` pending permanent offline production signing key & `cyclonedx-gomod`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `3b9988a69dfd99d0e0706f857887798e4dcac8424304a2a714b5100e921981f7`
- **Release Manifest SHA-256:** `9e2aef55cd59cd70404704546943a73a0c2ad7ccf60d91cf136a67942f8bf467`
- **Signing Key ID:** `stage-ephemeral-b574879` (ephemeral external `0600` Ed25519 key, unlinked immediately after signing)
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/stage-b574879-2026-11-21/` (`qual-receipt.json`, `mig-receipt.json`, `soak-receipt.json`)
- **Isolated Staging Qualification (`qualify-pi-isolated.py --smoke --receipt-out ./qual-receipt.json`):** **PASS 65 / SKIP 0 / FAIL 0**
- **V19→V22 Online-Snapshot Migration Rehearsal (`rehearse-prod-migration.py --receipt-out ./mig-receipt.json`):** **PASS 12 / FAIL 0** (full 64-hex canonical semantic digests identical across migration; post-`--reset-authority` `unchanged_ok=True` across all 6 identity/revocation categories and all 8 authority categories reset to `0`; restored-DB live relay `/health/ready == 200`).
- **Dual-Lane Workload Soak (`soak-isolated.py --duration 20 --warmup 5 --sample-interval 5 --receipt-out ./soak-receipt.json`):** **PASS** (`dataplane_ok_200=5` with exact echoed `soak_nonce` and advancing upstream hits, `disconnect_failed_as_expected=true`, `reconnects_completed=1`, `route_expected_401=5`, `pair_ok=5`, `unexpected_fail=0`, FDs `15->15` max `15` slope `0.0/hr`, RSS `15964KB->16492KB` median `16364KB`, `active_sessions=2`).
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Staging Receipt (`071d7ff` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `071d7ff16638a55684d21f02b3a0cf22d652bda2` (`dirty=false`, `govulncheck=pass`, `non_production=true` pending permanent signing key & `cyclonedx-gomod`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `4e35a4016298dc7c2c0825025cdd5afc63d8b138f24d2d825bf44a927e8732a1`
- **Signing Key ID:** `stage-ephemeral-071d7ff` (ephemeral external `0600` Ed25519 staging key, unlinked immediately after signing)
- **Pi Stage Directory:** `/home/bamn/ocliv-stage/stage-071d7ff-2026-11-21`
- **Isolated Staging Qualification (`qualify-pi-isolated.py --smoke`):** **PASS 65 / SKIP 0 / FAIL 0**
  - Phase G5 (`install-client.sh` in sanitized minimal PATH): explicitly excludes `go`, `git`, `caddy`, `docker`, `jq`, `ocliv`, `xxd`, and `python3`; valid signed install PASS, tampered manifest/sig/artifact rejected, and test-trust override without `OCLIV_ALLOW_TEST_TRUST=1` refused.
  - Phase H: real `--max-publisher-sessions=2`, `--max-http-streams=2` (2 held open, 3rd rejected 503 while `/health/ready=200`, release, recovers to 0), and `--max-ws-streams=2` (2 held 101, 3rd rejected 503 while `/health/ready=200`, close 1, 4th admitted 101, recovers to 0).
  - Phase I6: zero ephemeral secret files (`*.pem`, `qc.txt`) retained in stage directory.
- **V19→V22 Online-Snapshot Migration Rehearsal (`rehearse-prod-migration.py` against transactionally consistent read-only online snapshot of `stage-950440e` WAL DB):** **PASS 12 / FAIL 0** (`src_journal_mode=wal`, `src_schema=V19`, snapshot SHA-256 `70bad61c79ee9ff247979189cbf1034030a59a8b69d0862b0ad97a190114b104`; canonical sorted semantic SHA-256 digests identical across `tenants`, `agent_keys`, `leases`, `terminal_leases`, `mcp_publications`, `authz_clients`, `authz_grants`, `authz_revocations`; restored DB integrity/FK/schema/reset-authority verified + candidate relay `/health/ready == 200` on restored DB).
- **Live-Workload Soak Smoke (`soak-isolated.py --duration 20 --sample-interval 5 --receipt-out ./soak-receipt.json`):** **PASS** (`samples=5`, `reconnects_completed=1`, `route_expected_401=5`, `pair_ok=5`, `unexpected_fail=0`, FDs `13->13`, RSS `15632KB->16156KB`, `active_sessions=1`).
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Qualification Receipt (`11dead0` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `11dead068fa06f4dc152b5950aad5f6e233fdd94` (`dirty=false`, `govulncheck=pass`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `3b9ba712670d2769929b93152b0fe5af46cccfe7f04b14c6cc255d5c06b0bb67`
- **Release Manifest SHA-256:** `cfa6e7ea6613d6f2d4231352f21e9b5ed8c59a704ac4e2819385677e192acdb7`
- **Signing Key ID:** `stage-ephemeral-11dead0` (ephemeral external `0600` Ed25519 staging key)
- **Pi Stage Directory:** `/home/bamn/ocliv-stage/stage-11dead0-2026-11-21`
- **Strict Qualification (`qualify-pi-isolated.py`):** **PASS 61 / SKIP 0 / FAIL 0**
- **V19→V22 Migration Rehearsal (`rehearse-prod-migration.py` against read-only copy of `stage-950440e` DB):** **PASS 10 / FAIL 0** (`PRAGMA integrity_check=ok`, `foreign_key_check=[]`, keys/leases/publications/OAuth grants/revocations preserved, backup + validate-backup + restore `--reset-authority` PASS)
- **Soak Harness Smoke (`soak-isolated.py --duration 10`):** **PASS** (FDs `11->11`, RSS `14972KB->15348KB`, `process_ready=true`)
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Qualification Receipt (`2f635e4` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `2f635e470183ed464150bdaceb2c1e674313cc27` (`dirty=false`, `govulncheck=pass`, schema `V21`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `3b59bfddd623b133cd6112b17b2e35186adc4ea38e0f9db35e217f608fb853d3`
- **Release Manifest SHA-256:** `2762ee7904b3df0c767a773d4f7408e9251c519bf767292ce744a34bdfbb9e24`
- **Signing Key ID:** `stage-ephemeral-2f635e4` (ephemeral external 0600 Ed25519 staging key; real production signing key & CycloneDX SBOM tool remain outstanding for production release)
- **Pi Stage Directory:** `/home/bamn/ocliv-stage/stage-2f635e4-2026-11-21`
- **Qualification Result:** **PASS 60 / SKIP 0 / FAIL 0** (`qualify-pi-isolated.py` strict release mode)
  - Phases A, A2, B, C, D, E: managed OAuth, restart durability, security boundaries, rollback guard — **PASS**
  - Phase F: `pair --no-wait` → `relay approve` → `pair resume` → live publisher attach + V21 `poll_verifier`/`resolved_tenant_id` DB checks — **PASS**
  - Phase G: signed manifest/artifacts + sanitized minimal-PATH `dash` bootstrap (`install-client.sh`, no go/git/caddy/docker/jq/ocliv) + manifest/sig/artifact tamper rejection — **PASS**
  - Phase H: `--max-publisher-sessions=2` saturation (2 admitted, 3rd rejected before WS upgrade, disconnect + re-admit without leakage) — **PASS**
  - Phase I: role separation (zero relay DB/Caddy/DNS creds in publisher home, zero inbound listening sockets on publisher PID 287606) + live `relay revoke-key --key-id` — **PASS**
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Outstanding Promotion Gates (Required Before Lifting HOLD)

| Gate | Tier | Status |
|---|---|---|
| Production release build with permanent production Ed25519 trust-root key + CycloneDX SBOM (`cyclonedx-gomod`/`syft`) | Release Provenance | **NOT VERIFIED** |
| Off-LAN trusted-TLS public ingress verification (no `-k`) | Public / Off-LAN / Live | **NOT VERIFIED** |
| Official ChatGPT OAuth end-to-end acceptance | Public / Off-LAN / Live | **NOT VERIFIED** |
| 24-hour soak test | Public / Off-LAN / Live | **NOT VERIFIED** |
| Production schema/owner inventory & explicit operator promotion approval | Release Governance | **HOLD** |
