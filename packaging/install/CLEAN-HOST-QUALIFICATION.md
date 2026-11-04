# Clean-host qualification procedure (operator-run)

Goal: prove on a CLEAN machine (no prior ocliv data, no Caddy config)
that Ocliv installs, validates, enables, and serves. Never run this on
the lab relay (`/tmp/ocliv-*`, funnel host) — it provisions real
system paths.

## Prerequisites

- Fresh Linux host (systemd, Go toolchain, Caddy installed from
  https://caddyserver.com/docs/install), root.
- A real public domain (placeholders are refused). DNS A/AAAA for the
  relay host already resolves to the host's public IP.
- Source checkout at `/opt/ocliv` (or set `SRC_DIR`).

## Steps

```sh
# 0. Hermetic checks (no root needed, run anywhere with the tree):
go test ./packaging/install/ -count=1
#    ^ happy path, idempotency, Caddy/systemd/build failure rollback,
#      clean-host rollback. These are required, not optional.

# 1. Stage the sources on the relay host.
sudo mkdir -p /opt && sudo cp -r /home/<you>/ocliv /opt/ocliv

# 2. Install (transactional: stages + validates before activation;
#    any failure restores the previous state).
cd /opt/ocliv/packaging/install
sudo DOMAIN=<real-domain> MCP_HOST=<real-domain> ./install.sh
#    Expect: "installed ...; env ... (0600)" and the next-step line.
#    Any failure exits nonzero and leaves the previous install intact —
#    verify `ls -la /usr/local/bin/ocliv* /etc/ocliv/relay.env` is UNCHANGED.

# 3. Rollback drill (optional but recommended on first clean host):
#    break the Caddyfile, re-run the installer, confirm nonzero exit
#    AND the previous binary/env/unit restored byte-identical.

# 4. Edit /etc/caddy/Caddyfile from the generated template, validate:
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl reload caddy   # or: systemctl restart caddy

# 5. Enable the relay and enroll:
systemctl enable --now ocliv-relay
systemctl is-active ocliv-relay
sudo -u ocliv /usr/local/bin/ocliv relay issue-enroll --data /var/lib/ocliv --tenant home
#    (then `ocliv login` with the printed code on the client machine)

# 6. External proof (from ANOTHER network, no -k):
curl -v https://<real-domain>/v1/agent/challenge
#    Expect: relay 4xx (not a TLS error) => DNS + cert + edge live.
ocliv doctor   # client-side: relay reachability + TLS identity verified
```

## Pass/fail

- PASS requires step 6's external 4xx AND `ocliv doctor` TLS verified.
- Any `421 misdirected`, TLS error, or connection refused = FAIL:
  check `journalctl -u ocliv-relay`, `caddy validate`, DNS (`dig`).
- Record the date, host, domain, commit hash, and the curl output.
  Local green (`go test ./...`) is NEVER production proof.

## Container qualification record (2026-11-04, disposable docker/systemd host)

Method: ubuntu:24.04 + systemd as PID 1 (--privileged), prebuilt ocliv
binary behind a `go` shim (source build is proven by host gates; the
container tested install/activation/systemd/enrollment/TLS).

PASS:
- Fresh install exit 0; relay active as user ocliv, loopback-only
  (8080 relay, 18080 health); health live+ready ok.
- Enrollment + tunnel through real Caddy TLS edge (tls internal CA,
  port 8443): unauthorized 302 zero app contact, redeem 200,
  authorized 200 "hello-tls-edge" with --cacert verification (no -k);
  status ACTIVE live; doctor enrollment/reachability/TLS/local all ✓.
- Upgrade (installer re-run) exit 0, .prev preserved.
- Rollback drill: broken Caddyfile -> exit 1 pre-activation, previous
  install byte-identical, relay stayed active.
- Reboot: relay auto-started, data dir intact, tunnel re-attached
  (after re-adding /etc/hosts entries, which docker regenerates).
- 32-worker TLS load: 320 requests ok=320 fail=0, lat min 19ms /
  p50 143ms / p99 353ms / max 445ms; relay RSS 14.5->20.7MB (bounded),
  post-load ACTIVE live.
- 60s soak (host suite): ok=12652 fail=0 avg 37.7ms, goroutines +9.

Defects found + fixed during this run (both in install.sh):
1. Clean-host fresh install false-failed: pre-activation
   systemd-analyze verify stats ExecStart, which does not exist yet.
   Fix: gate staged verify on the launcher being present; the
   post-activation verify (with full rollback) is authoritative.
2. Upgrade false-failed: systemd-analyze verify rejects suffixed unit
   filenames. Fix: staged unit now validated as
   .ocliv-stage.$$/ocliv-relay.service (proper name).

Container and image torn down after the run. None of this proves
public reachability — steps 6+ (ACME, DNS, off-network client) remain
operator-gated.
