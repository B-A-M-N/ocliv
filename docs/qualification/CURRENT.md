# Ocliv Current Qualification Status

**Production Promotion Status:** **HOLD**

This document is the single entry point for current verification status. Dated
historical qualification records live under `docs/qualification/history/`, and
structured evidence/receipts live under `docs/qualification/receipts/`.

## Verified Gates (Source & Isolated Staging)

| Gate | Status | Notes |
|---|---|---|
| Full repository Go tests (`go test ./... -count=1 -timeout=420s`) | **PASS** | Includes `tests/integration` and all internal/packaging/staging packages |
| Race detector matrix (`internal/relay` standalone + core internal packages) | **PASS** | Zero data races across `relay`, `cli`, `agent`, `config`, `identity`, `protocol`, `store`, `lease`, `setup` |
| Static checks (`gofmt`, `go vet`, `git diff --check`, `check-repo-hygiene.sh`) | **PASS** | Enforced in CI |
| Isolated ARM64 Pi staging & real machine reboot recovery (`10.9.66.170`) | **PASS** | Same lease, same visitor HMAC key, same cookie after reboot; production `ocliv-relay` untouched |
| Pi isolated loopback qualification — 2026-11-21 (commit `950440e`) | **PASS 29/0** | V19 schema, Phase E+F audit items as originally scoped; see `history/PI-ISOLATED-RESULT-2026-11-21.md` for items exercised vs. items present-but-not-exercised |
| HEAD `8cce9af` — Go test suite (all packages, race matrix) | **PASS** | Source-only; Pi/live qualification NOT YET RUN against this commit |

> **Qualification isolation note:** Results from `950440e` are NOT transferable to
> `8cce9af`. Five security-relevant commits and a schema migration (V19→V20) landed
> between them. The Phase A schema check in `qualify-pi-isolated.py` would fail
> immediately on `950440e`'s result against HEAD. A fresh qual run against `8cce9af`
> is required before production promotion.

## Outstanding Gates (Required Before Lifting HOLD)

| Gate | Status |
|---|---|
| Clean detached-worktree release build + `govulncheck` + SBOM + `release-manifest.json` | **NOT VERIFIED** |
| Exact-hash staging qualification of the clean release artifact | **NOT VERIFIED** |
| Off-LAN trusted-TLS public ingress verification | **NOT VERIFIED** |
| Official ChatGPT OAuth end-to-end acceptance | **NOT VERIFIED** |
| 24-hour soak test | **NOT VERIFIED** |
| Production schema/owner inventory & explicit promotion approval | **HOLD** |
| Phase F — pairing E2E: `ocliv pair --no-wait` → `relay approve` → `ocliv pair resume` → publisher attaches; `poll_verifier` stored, `poll_secret` absent from DB | **NOT VERIFIED** |
| Phase G — installer/artifacts: relay configured with `--release-manifest`/`--release-artifacts`; manifest served 200, all artifacts SHA256-verified, traversal refused | **NOT VERIFIED** |
| Phase H — capacity saturation: 3 publishers with `--max-publisher-sessions=2`; 3rd gets HTTP 503 before WS upgrade; slot released on disconnect | **NOT VERIFIED** |
| Phase I — role separation: relay DB not world-readable; management endpoints require auth; `relay revoke` kills publisher authority | **NOT VERIFIED** |
