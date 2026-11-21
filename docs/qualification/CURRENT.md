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

| Commit SHA | Schema | Source / Unit & Race Matrix | Isolated Artifact E2E (Pi / Staging) | Public / Off-LAN / Live | Notes |
|---|---|---|---|---|---|
| `950440e` | V19 | PASS | PASS (29/0 loopback) | NOT VERIFIED | Historical baseline (`history/PI-ISOLATED-RESULT-2026-11-21.md`); does NOT cover V20/V21 pairing, release signing, capacity saturation, or role separation |
| `8cce9af` | V20 | PASS | NOT VERIFIED | NOT VERIFIED | Superseded by Round 2 & Round 3 remediation |
| Current branch HEAD | V21 | PASS (verified after final edit) | NOT VERIFIED | NOT VERIFIED | Adds V21 `resolved_tenant_id`, full release-signing trust chain, coherent relay release tuple, staged setup resume, `wildcard` default edge, readiness/capacity separation, terminal lease ephemera pruning, and real Phase F/G/H/I harness |

> **Non-transfer invariant:** Passing `950440e` (V19) does NOT qualify V21
> builds. A clean detached-worktree exact-SHA release build and fresh isolated
> Pi qualification run against that exact artifact are required before lifting
> HOLD.

## Outstanding Promotion Gates (Required Before Lifting HOLD)

| Gate | Tier | Status |
|---|---|---|
| Clean detached-worktree exact-SHA release build (`govulncheck`, SBOM, `SHA256SUMS`, Ed25519 `release-manifest.json.sig`) | Release Provenance | **NOT VERIFIED** |
| Exact-hash isolated Pi qualification (`qualify-pi-isolated.py`, zero SKIPs): Phases A–E + F (CLI pair → approve → resume → attach) + G (signed manifest/artifacts + tamper rejection) + H (`--max-publisher-sessions=2` saturation + release) + I (role separation + key revocation) | Isolated Artifact E2E | **NOT VERIFIED** |
| Off-LAN trusted-TLS public ingress verification (no `-k`) | Public / Off-LAN / Live | **NOT VERIFIED** |
| Official ChatGPT OAuth end-to-end acceptance | Public / Off-LAN / Live | **NOT VERIFIED** |
| 24-hour soak test | Public / Off-LAN / Live | **NOT VERIFIED** |
| Production schema/owner inventory & explicit operator promotion approval | Release Governance | **HOLD** |
