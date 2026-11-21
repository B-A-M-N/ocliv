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
| `11dead068fa06f4dc152b5950aad5f6e233fdd94` | V22 | PASS (unit + hygiene + vet) | **PASS 61/0/0** + **V19→V22 migration 10/0** + **soak harness smoke PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`3b9ba712670d2769929b93152b0fe5af46cccfe7f04b14c6cc255d5c06b0bb67`); adds V22 one-pending-per-key index, strict `OCLIV_ENV=development AND loopback` gate, `non_production` refusal, provenance SBOM startup verification, and Phase H 3-limit + `/health/ready` checks; production `ocliv-relay` (PID 1577) and `caddy` (PID 1574) untouched |

## Latest Isolated Pi Qualification Receipt (`11dead0`)

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
