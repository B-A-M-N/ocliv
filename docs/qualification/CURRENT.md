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

## Latest Isolated Pi Qualification Receipt (`2f635e4`)

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
