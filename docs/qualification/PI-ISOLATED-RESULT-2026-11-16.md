# Pi isolated loopback result — 2026-11-16

## Candidate and artifact

- Source commit: `efe3a8e` (`test: enumerate staged routes from SQLite`).
- Target: Linux ARM64, PiInDaSky (`aarch64`).
- Build: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`, `-trimpath`, stripped.
- SHA-256: `aef41e6acb06273f56e812d8785f148c29bcedb095e9e2b38aadba167246d08c`.
- Pi artifact: `/home/bamn/ocliv-stage/stage-efe3a8e-20261116/ocliv-arm64`.

The digest was checked on the build host and again after transfer to the Pi.
The stage directory is mode `0700`; its enrollment code, publisher key, and
SQLite DB are each mode `0600`.

## Result

`python3 qualify-pi-isolated.py` completed **29 PASS / 0 FAIL** in the fresh
stage directory. The run bound only to loopback ports 28080, 28085, and 28099
(port 59999 was checked and remained unused). It created a fresh V11 DB and a
staging-only publisher identity.

The 29 checks covered:

- Two distinct, verified managed-OAuth routes and relay health.
- Route persistence across candidate relay restart.
- DCR, consent, PKCE exchange, operator approval, `tools/list`, and harmless
  `tools/call`.
- Relay-minted identity injection and bearer stripping before the upstream.
- Refresh-token rotation and replay rejection.
- Missing, forged, and tampered bearer denial with zero upstream executions.
- Cross-route client, code, and revocation isolation.
- Malformed DCR JSON and consent replay rejection.
- Backup creation, refusal to restore revoked grant state, and
  reset-authority invalidation.

After the run, no candidate relay/upstream process remained and all four test
ports were free. `ocliv-relay` remained `active`; no production DB, key, unit,
DNS, Caddy config, or published route was read or changed by the qualification.

## Scope limits

This is isolated loopback qualification only. It does not prove clean-host
installation, external/off-LAN reachability, ChatGPT registration, or a
24-hour soak. Those remain separate qualification gates.
