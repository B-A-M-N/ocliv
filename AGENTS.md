# Ocliv Repository Rules & Engineering Guide

This file defines current repository structure, non-negotiable invariants,
validation commands, and release constraints. Chronological audit and
remediation narratives live under `docs/audits/history/`.

## Repository Layout

- `cmd/ocliv/` — CLI/relay entrypoint
- `internal/` — Go core packages (`access`, `agent`, `apperr`, `authz`, `cli`, `config`, `control`, `doctor`, `identity`, `lease`, `limits`, `mcp`, `metrics`, `protocol`, `proxy`, `relay`, `server`, `setup`, `store`, `transport`)
- `integrations/` — First-party client/UI integrations (`chatgpt-plugin/`, `skybridge/`)
- `packaging/` — Systemd, Caddy, installer, and MCP runtime packaging recipes (source only; no generated binaries or ZIPs)
- `tests/` — Integration suites, staging fixtures, and tracked public test certs (`tests/fixtures/certs/`)
- `scripts/` — Repository hygiene (`check-repo-hygiene.sh`), qualification (`qualification/`), and release (`release/`) scripts
- `docs/` — Current operator/setup docs, `specs/`, `audits/`, and `qualification/CURRENT.md` (`history/`, `receipts/`)
- Ignored local/generated roots: `dist/`, `.scratch/`, `live/`, `lab-backup/`

## Non-Negotiable Invariants

1. **Production isolation:** Never mutate, restart, deploy, or migrate production `ocliv-relay` without explicit operator approval. All Pi qualification runs isolated under `/home/bamn/ocliv-stage/`.
2. **Forward-only state recovery:** Schema upgrades are forward-only; never weaken backup checksum/format/revocation guards or add a second restore mechanism.
3. **Fail-closed authority & crypto boundaries:**
   - Enrollment requires exact canonical `key_id` match (`"key-" + localKey.ID()`).
   - Body-bearing management mutations require negotiated `mgmt_body_sig_v2`; bodyless requests remain `ocliv-mgmt-v1` for rolling compatibility.
   - Private key and env-file loads are single-FD `O_NOFOLLOW` + regular-file + `0600` + owner-checked.
   - Root setup never writes user identity/config files into `SUDO_USER`'s home; enrollment runs as an unprivileged child process via `--code-file -` on stdin.
4. **Default edge policy:** `DefaultEdgeMode()` (`tunnel`) is the single source of truth for setup execution, recommendations, help text, and docs.
5. **Release provenance:** Production artifacts must be built from a clean detached worktree at an exact SHA with `-trimpath`, explicit ldflag `BuildCommit`/`BuildTime`/`BuildDirty=false`, `SHA256SUMS`, SBOM, `govulncheck`, and `release-manifest.json` outside Git.

## Required Validation Commands

```bash
./scripts/check-repo-hygiene.sh
test -z "$(gofmt -l cmd internal packaging tests)"
go vet ./...
git diff --check
go test ./... -count=1 -timeout=420s
go test -race ./internal/cli ./internal/protocol ./internal/identity ./internal/config ./internal/agent ./internal/store ./internal/lease ./internal/setup -count=1 -timeout=300s
go test -race ./internal/relay -count=1 -timeout=420s
```

## Qualification & Release Status

See `docs/qualification/CURRENT.md`. Production promotion remains **HOLD** until clean-commit release provenance, exact-hash staging qualification, off-LAN trusted-TLS, official ChatGPT OAuth, and 24-hour soak gates are explicitly verified.
