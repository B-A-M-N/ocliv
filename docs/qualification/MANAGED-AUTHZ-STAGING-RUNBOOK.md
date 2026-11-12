# Managed Authorization — Isolated Staging Qualification Runbook

Status: **NOT EXECUTED** — operator-gated. This runbook qualifies the
2026-11-12 managed-auth remediation (P0-1 per-transaction authorization,
P0-2 same-key-only named-lease reclaim, consent/form/PKCE lifecycle,
bounded authorization state) on REAL public HTTPS before anything
approaches the production relay.

Companion: `MANAGED-AUTHZ-QUALIFICATION.md` (the protocol-level
procedure this runbook stages). This document adds the three things
that runbook assumes: an isolated staging instance, build provenance
for uncommitted code, and the production-isolation contract.

## 0. Isolation contract (read before touching anything)

| # | Rule | Why |
|---|------|-----|
| I1 | The production relay (`PiInDaSky .170`, `/var/lib/ocliv/ocliv.db`, unit `ocliv-relay`) is READ-ONLY for this qualification: no restart, no binary swap, no schemaV11 migration, no config edit. | schemaV11 is forward-only; a staging run must never reach the production DB. The pre-V11 binary refuses a V11 database, and a V11 DB is refused by pre-V11 binaries — mixing artifacts both ways leaves a relay DOWN. |
| I2 | The staging relay uses its OWN `--data` directory (fresh SQLite, own enrollment codes, own issuer key). | The issuer key makes a managed-auth DB a secret; staging and production must never share one. |
| I3 | Staging ports are distinct from production (relay listen, health listen, MCP port) and all bound to loopback. | The public listener is the TLS edge, never the relay. |
| I4 | The upstream is a HARMLESS local MCP server (the `pong` fixture; no private data, no real tools). | Qualification proves the tunnel, not the payload. |
| I5 | Production keeps serving throughout; any production-visible change is an abort condition, not a step. | Local green is not public qualification; production health is not a staging signal. |

If any rule cannot be satisfied, the run is **BLOCKED**, not partially
passed.

## 1. Prerequisites (operator-gated)

| # | Prerequisite | Why it blocks |
|---|--------------|----------------|
| P1 | Build provenance: the staging binary is built FROM THE UNCOMMITTED WORKING TREE and its sha256 + `git rev-parse HEAD` + `git diff HEAD --stat` are recorded before the run. | The remediation is uncommitted at `abbbe34`; an unrecorded build is unqualifiable. |
| P2 | A staging host reachable over public HTTPS for `--mcp-host` (a staging subdomain on the existing edge, or a temporary `tailscale funnel` host). | The token audience is the route URL; the flow must complete over the real public path. |
| P3 | Shell access to the staging relay's host for `ocliv authz ...` | Approval is a local operator action on the staging store. |
| P4 | A staging publisher machine (or the same host, separate process) that can reach the staging relay over WSS. | The route must bind to a live lease. |
| P5 | curl on a client machine (any machine that can reach the public HTTPS host). | DCR + PKCE must be driven by something other than the relay's own tests. |

## 2. Build provenance (do this first, on any machine)

```sh
cd /home/bamn/ocliv
git rev-parse HEAD                      # expect abbbe34 (remediation is uncommitted)
git diff HEAD --stat                    # record: the 23 modified files + boundary_test.go
sha256sum <(go build -o /tmp/ocliv-staging-bin ./cmd/ocliv && cat /tmp/ocliv-staging-bin)
```

Record all three outputs in the evidence pack. A staging run against a
binary whose provenance cannot be reproduced from the tree is a failed
run.

## 3. Staging relay (loopback only; production untouched)

```sh
# On the staging host. Fresh data dir — NEVER /var/lib/ocliv.
mkdir -p /var/lib/ocliv-staging && chmod 700 /var/lib/ocliv-staging
ocliv relay serve --listen 127.0.0.1:18081 --data /var/lib/ocliv-staging \
  --domain <staging-domain> --mcp-host <staging-fqdn> --mcp-port 18443 \
  --relay-host <staging-relay-fqdn> --health-listen 127.0.0.1:18082
ocliv relay issue-enroll --data /var/lib/ocliv-staging --tenant staging
```

**Oracle:** `/health/live` → "ok" and `/health/ready` → 200 on
`127.0.0.1:18082`. **Fail-closed:** ready non-200 means the staging store
or admission capacity is broken; stop. Note the schema version —
a fresh DB lands on schemaV11 (pairing lifecycle columns present).

## 4. Publish (one command, managed default)

```sh
# Publisher host: enroll once, then the bare alias.
ocliv login --relay https://<staging-relay-fqdn> --code-file -
ocliv mcp 8765            # bare alias: --auth ocliv-managed by default
```

**Oracle:** the publish prints the route URL and the approval commands.
**Also verify (P2):** `ocliv mcp publish --local http://127.0.0.1:8765/mcp
--auth upstream-oauth --name other` still parses as upstream-oauth
(explicit passthrough didn't regress), while the bare alias is managed.

## 5. The full OAuth flow over public HTTPS

Run every step of `MANAGED-AUTHZ-QUALIFICATION.md` §3.2–3.5 against the
staging route, with these 2026-11-12 semantics as the oracle:

1. Discovery is route-scoped (PRM/AS shapes exact).
2. Authorize with a registered-but-unapproved client → **200 consent
   page**, no `Location`, no credential in the URL.
3. `ocliv authz approve` (staging data dir) → prints ONE single-use
   pairing credential.
4. Complete consent by POSTing the form fields to the form's OWN action
   URL (parse it from the page; it must be
   `https://<staging-fqdn>/r/<route-id>/oauth/consent`) → 302 with
   `code` (and `iss`).
5. Token exchange with the required `resource` and a conforming
   (43–128 char) verifier → access token.
6. `tools/list` and `tools/call` with the bearer → 200 and exactly one
   upstream execution each (check the harmless upstream's counter).

**P0-1 oracle (the headline gate):** after step 4 completes, run a
SECOND authorize with standard parameters only — it must return the
consent page (200, no code). A code here is the defect the remediation
closed. Then approve a fresh credential and confirm the second
transaction completes.

## 6. Negative paths (staging route, fresh token per case)

N1 missing bearer → 401. N2 tampered bearer → 401. N3 wrong audience
(token for another route) → 401. N4 replayed code → 400. N5 wrong PKCE
→ 400. N6 empty `pairing_secret` → 403. N7 wrong credential → 403.
**N8** approved client, standard params only, no consent → 200 consent
page, ZERO upstream executions. **N9** replay a consumed credential →
403 (single-use). **N10** credential past its one-hour expiry → 403.
**N11** token exchange with a sub-43-character verifier → 400.

Every denial must show both the status AND the upstream's zero-execution
counter.

## 7. Reclaim boundary and persistence (P0-2)

1. Stop the publisher, republish the same name with the SAME key and a
   fresh data dir (so it cannot resume): the route id is byte-identical
   and a previously issued token still works (durable publication).
2. Enroll a SECOND key in the same staging tenant and attempt the same
   name with it: the reclaim must be REFUSED (no attach; the original
   lease keeps serving; one `lease_reclaim/denied` audit row). A
   successful second-key attach is the defect the remediation closed.

## 8. Teardown

```sh
ocliv mcp unpublish --lease <lease-id>
# staging relay: stop it; LEAVE /var/lib/ocliv-staging for post-mortem
ocliv authz list --data /var/lib/ocliv-staging
tailscale funnel reset      # only if the funnel edge was used
```

**Oracle:** the route stops serving (404/503); the production relay's
health stays 200/200 throughout; production `mcp list` unchanged.

## 9. Verdict table (fill during the run)

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | Build provenance recorded (HEAD + diff + sha256) | | |
| 2 | Production untouched (health/units/publication unchanged at every step) | | |
| 3 | Route-scoped discovery exact | | |
| 4 | Unapproved authorize → consent page, no code | | |
| 5 | Approve → one single-use credential | | |
| 6 | Consent via the form's own action → code → token → tools/call over public HTTPS | | |
| 7 | P0-1: second authorize on the ACTIVE grant → NO code | | |
| 8 | N1–N11 with zero-execution proofs | | |
| 9 | Republish preserves route id + token validity | | |
| 10 | Cross-key reclaim refused + audited | | |
| 11 | Teardown stops serving; funnel reset (if used) | | |

Overall PASS requires every row PASS with pasted evidence. Any FAIL is
a defect. A run that cannot be executed end-to-end is BLOCKED, never
PASS.

## 10. Known limits

- This run proves the managed-auth path through real public HTTPS; it
  does NOT qualify ChatGPT registration, a production IdP, refresh-token
  behavior (none exists — see the companion runbook §6), or scale.
- It qualifies the STAGING instance only. Promotion to production is a
  separate operator decision with its own gates (binary swap + schema
  migration plan + rollback pair, per the 2026-11-11 register entry's
  rollback dependency, now V11 on top of V7).
