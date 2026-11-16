# Pi isolated loopback result — 2026-11-16 (current candidate)

## Candidate and artifact

- Source commit: `7674c4b4881b2824f6dc204206f51a46d4ff6ec4`
  (`test(cli): avoid stdout race during active publishers`).
- Target: Linux ARM64, PiInDaSky (`aarch64`).
- Build: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`, `-trimpath`, stripped.
- SHA-256: `e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5`.
- Size: 13,697,186 bytes.
- Build artifact: `/home/bamn/ocliv-stage/candidates/7674c4b-20261116/ocliv-arm64`.
- Pi artifact: `/home/bamn/ocliv-stage/stage-7674c4b-20261116-recorded/ocliv-arm64`.

The digest was checked on the build host and again after transfer to the Pi.
The stage directory is mode `0700`; its publisher key, SQLite DB, and saved
qualification log are owner-only.

## Result

`python3 qualify-pi-isolated.py` completed **29 PASS / 0 FAIL** in the fresh
stage directory. The run bound only to loopback ports 28080, 28085, and 28099
(port 59999 was checked and remained unused). It created a fresh V11 DB and a
staging-only publisher identity. No candidate relay listener or process
remained after cleanup; the production relay and public edge were not touched.

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
ports had no listener. The retained `ocliv-relay` service, production DB,
keys, units, DNS, Caddy config, and published routes were not changed by the
qualification.

## Source gates for this candidate

- `go test ./... -count=1`: PASS, including the 266.7 second integration suite;
  output retained at `/home/bamn/ocliv-stage/candidates/7674c4b-20261116/go-test-all.log`.
- `go test -race ./internal/... -count=1`: PASS (19 packages); output retained
  at `/home/bamn/ocliv-stage/candidates/7674c4b-20261116/race-internal.log`.
- `go vet ./...`: PASS.
- Skybridge `npm test`: **86/86 PASS**, including the real Go adapter protocol
  interoperability test.
- ARM64 artifact rebuilt from the exact clean commit and digest-checked on the
  build host and Pi.

## Scope limits

This is isolated loopback qualification only. It does not prove clean-host
installation, external/off-LAN reachability, ChatGPT registration, or a
24-hour soak. Those remain separate qualification gates.
