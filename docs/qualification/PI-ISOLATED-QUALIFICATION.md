# Isolated Pi loopback qualification

This procedure qualifies an exact ARM64 candidate on PiInDaSky without
stopping, restarting, or connecting to the production relay. The driver starts
its own relay on loopback, uses a fresh database, and creates its own staging
publisher identity. It refuses occupied ports and an existing database path.

## Build the exact candidate

Use a clean detached checkout of the commit being qualified. Store durable
build output under `/home/bamn/ocliv-stage`, never `/tmp`.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath \
  -ldflags='-s -w' -o /home/bamn/ocliv-stage/builds/<commit>/ocliv-arm64 ./cmd/ocliv
sha256sum /home/bamn/ocliv-stage/builds/<commit>/ocliv-arm64
```

Record the full source commit and artifact digest before copying the artifact.

## Run on PiInDaSky

Choose a new, commit-specific stage path. Do not reuse a previous qualification
directory. The path and its contents are owned by `bamn`; no `sudo` is used.

```sh
STAGE=/home/bamn/ocliv-stage/stage-<commit>-<date>
install -d -m 0700 "$STAGE"
install -m 0755 ocliv-arm64 "$STAGE/ocliv-arm64"
install -m 0600 qualify-pi-upstream.py "$STAGE/mcp_upstream.py"
install -m 0600 qualify-pi-isolated.py "$STAGE/qualify-pi-isolated.py"
sha256sum "$STAGE/ocliv-arm64"
python3 "$STAGE/qualify-pi-isolated.py"
```

Run the command as the normal Pi account. Do not set or export `HOME` for the
SSH session. The driver sets `HOME` only for its own candidate CLI subprocesses,
under `$STAGE/qual-home`. Its enrollment code, keys, database, logs, and guarded
backup remain under the owner-only stage directory.

The driver checks loopback ports 28080, 28085, 28099, and 59999 before starting.
It binds the candidate relay only to `127.0.0.1`, uses `$STAGE/relay-data-fresh`,
and refuses to reuse that DB directory. The production relay on 127.0.0.1:8080,
its database, systemd units, Caddy, and public DNS are outside the test path.

Every process termination checks `/proc` for the exact executable, current
owner, and stage-specific command arguments. Only child processes started by
the driver are stopped. A PID mismatch fails closed; the driver never sends a
signal based only on a PID file. The process cleanup runs on normal exit and
Python exceptions. Check the result is `PASS 29`, `FAIL 0`, and verify the
qualification ports are no longer listening before recording a pass.

Do not use historical `qualify.py` files that signal an unverified PID from a
file. They predate this process-identity guard.
