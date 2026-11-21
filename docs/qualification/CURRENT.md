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
| Pi isolated loopback qualification — 2026-11-21 (commit `950440e`) | **PASS 29/0** | V19 schema, Phase E+F audit items (tenant policy, global budget, pairing flow, installer, capability advertisement, systemd hardening); see `history/PI-ISOLATED-RESULT-2026-11-21.md` |

## Outstanding Gates (Required Before Lifting HOLD)

| Gate | Status |
|---|---|
| Clean detached-worktree release build + `govulncheck` + SBOM + `release-manifest.json` | **NOT VERIFIED** |
| Exact-hash staging qualification of the clean release artifact | **NOT VERIFIED** |
| Off-LAN trusted-TLS public ingress verification | **NOT VERIFIED** |
| Official ChatGPT OAuth end-to-end acceptance | **NOT VERIFIED** |
| 24-hour soak test | **NOT VERIFIED** |
| Production schema/owner inventory & explicit promotion approval | **HOLD** |
| Phase F — pairing E2E: `pair-request` → operator approve → `pair-status` poll with `poll_id`/`poll_secret` on real relay, V20 schema confirmed | **NOT VERIFIED** |
| Phase G — clean-machine bootstrap: `ocliv install` on a fresh machine with no Go/Git/Docker, artifact signature verification pass | **NOT VERIFIED** |
| Phase H — capacity saturation: global session budget exhausted → 503 before WebSocket upgrade, session slot released on disconnect | **NOT VERIFIED** |
