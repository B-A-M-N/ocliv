# Operator pre-flight — PiInDaSky, 2026-11-15 (READ-ONLY, completed)

Scope: strictly read-only. No backup, no binary replacement, no schema
migration, no service restart, no file on the Pi was modified. Hard-stop
boundary respected throughout.

## Results

| Check | Result | Evidence |
|---|---|---|
| Host | `PiInDaSky` (aarch64) | `hostname`, `uname -m` |
| Service | `ocliv-relay` **active** since 2026-11-11 16:51:27 CST | `systemctl is-active/show` |
| Health live | **ok** | `GET /health/live` (loopback) |
| Health ready | **ok** | `GET /health/ready` (loopback) |
| Installed binary | `0d47481f…e07a00d0b1` (the 2026-11-11 production build, source `6472ff8`) | `sha256sum /usr/local/bin/ocliv` |
| Qualified candidate on Pi | `1ceaaff4…bc85912d7` (source `19d46d8`) — matches the runbook §1 digest exactly | `sha256sum ~/ocliv-stage/ocliv-arm64` |
| Live DB schema version | **NOT READ** — DB is root-only and sudo requires a password; read-only open as `bamn` was refused | `sqlite3.connect("file:/var/lib/ocliv/ocliv.db?mode=ro")` → `unable to open database file` |
| Managed-client inventory | **NOT READ** — same root-only constraint; the query is ready in the runbook Step 0 | same |
| Public edge (bamnlabs.dynv6.net) | **TLS + ACME healthy**; `GET /` → 421 (by design: non-tunnel hostnames are refused); route-shaped `/r/<id>/mcp` → **404** (fail-closed dispatch, not a listener fault); PRM discovery shape → **404** | curl from the Pi and from the build host (LAN vantage) |
| Edge↔relay path | Caddy `bamnlabs.dynv6.net` → `127.0.0.1:8080`, loopback-only relay confirmed | `/etc/caddy/Caddyfile`, launch script |

## Interpretation

- The public edge is **functionally healthy today**: TLS is valid, ACME is
  working, and route-shaped requests dispatch to the relay rather than being
  misdirected. The 421 on the apex is the intended design (visitor traffic
  requires a tunnel hostname), not an outage.
- **This is a LAN-vantage baseline, not the required off-LAN baseline.** The
  reviewer's instruction stands: capture an off-LAN baseline before and after
  promotion so a pre-existing edge failure is not misattributed to the new
  binary.
- The schema-version read and managed-client inventory remain **explicit
  operator actions** (root). The runbook Step 0 queries are correct and
  ready; they just need a root shell.
- Candidate digest `1ceaaff4…` is verified on the Pi and matches the runbook.
  The next mutation (backup) is gated on the operator, not on any further
  agent work.

## Remaining operator gates (unchanged, in order)

1. Root-read the live schema version + managed-client inventory (Step 0).
2. Take and validate the production backup (Step 1).
3. Explicit operator approval for the forward-only migration (Steps 2–3).
4. Off-LAN baseline **before** promotion, then promote and verify
   authorized public `tools/call` after.
5. Re-register any legacy unbound managed clients (Step 4 note).
6. Accept the recovery-point limitation (post-backup state can be lost on
   restore; §5 of the runbook records this explicitly).
