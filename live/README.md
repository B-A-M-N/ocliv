# live/ — local run artifacts (NOT part of the build)

Everything here is machine-local state from live qualification runs.
Only the files explicitly listed as tracked belong in git; the rest is
git-ignored (see `.gitignore`) and must never be committed.

Tracked (safe to commit):

- `README.md` — this file.
- `lab-ca.crt` — PUBLIC lab CA root for the 8444 edge. Trusting it is a
  staging-only decision; the private key never leaves the relay laptop.
- `ocliv-dist/` — release ZIPs + `SHA256SUMS` built by
  `packaging/mcp/build.sh` / `build-plugin.sh`. Reproducible
  (normalized mtimes, sorted entries); verify with `sha256sum -c`.

Untracked (local only, never commit):

- `token-g2`, `mcp-smoke.resource` — bearer token and route binding.
- `*.log` — run logs (publisher, fixture, relay, funnel).
- `relay-data/`, `fakehome/` — relay SQLite state and test homes.
- `ocliv`, `fixture` — stray binaries from earlier sessions.
