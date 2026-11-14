# Clean-host qualification procedure (operator-run)

Goal: prove on a CLEAN machine (no prior ocliv data, no Caddy config)
that Ocliv installs, validates, enables, and serves. Never run this on
the lab relay (`/tmp/ocliv-*`, funnel host) — it provisions real
system paths.

Two installers exist and both must qualify a clean host:

- **`ocliv setup --auto --hostname NAME --acme-email E --token-file T
  [--edge single-host]`** — the automated path. As root it now
  provisions the COMPLETE artifact set (see below), activates the
  edge, enrolls, and persists `relay_url`. This is the product's
  easy-deployment path.
- **`install.sh`** (this directory) — the source-build path for
  operators who want the transactional installer over a checkout at
  `/opt/ocliv`.

The complete artifact set a clean host needs, and who installs it:

| Artifact | Path | Mode/owner | `setup --auto` | `install.sh` |
|---|---|---|---|---|
| service account | `ocliv` (system) | nologin, home = data dir | yes | yes |
| relay binary | `/usr/local/bin/ocliv` | 0755 root | yes (running binary) | yes (builds from source) |
| launcher | `/usr/local/bin/ocliv-relay-launch.sh` | 0755 root | yes (embedded copy) | yes (from checkout) |
| relay environment | `/etc/ocliv/relay.env` | 0600 root, dir 0700 | yes | yes |
| data directory | `/var/lib/ocliv` | 0700 `ocliv:ocliv` | yes | yes |
| edge Caddyfile | `/etc/caddy/Caddyfile` | managed marker | yes | operator-edited |
| systemd unit | `/etc/systemd/system/ocliv-relay.service` | managed marker | yes | yes |
| Caddy activation | `systemctl enable --now caddy` + reload | — | yes | no (operator reloads) |
| relay start | `systemctl enable --now ocliv-relay` | — | yes | no (operator enables) |
| enrollment | one-time code exchange | — | yes | no (operator enrolls) |

Every managed destination rolls back on a later step's failure
(backup restore for files, first-candidate restore for the binary,
sentinel-guarded removal for newly created dirs/files); the service
account is never removed. An unmanaged destination is REFUSED, not
overwritten.

## Prerequisites

- Fresh Linux host (systemd, Go toolchain, Caddy installed from
  https://caddyserver.com/docs/install), root.
- A real public domain (placeholders are refused). DNS A/AAAA for the
  relay host already resolves to the host's public IP.
- Source checkout at `/opt/ocliv` (or set `SRC_DIR`) for `install.sh`.

## Steps

```sh
# 0. Hermetic checks (no root needed, run anywhere with the tree):
go test ./packaging/install/ ./internal/setup/ -count=1
#    ^ install.sh: happy path, idempotency, Caddy/systemd/build failure
#      rollback, clean-host rollback. internal/setup: the complete
#      `setup --auto` artifact set, ordering, permissions (0600 env,
#      0755 launcher with the shebang on line 1), data-dir
#      create/never-remove-existing, binary first-candidate rollback,
#      unmanaged refusals. These are required, not optional.

# 1a. Automated path (setup --auto; the easy-deployment flow). On the
#     clean host, with Caddy already installed and DNS resolving here:
sudo ocliv setup --auto --hostname <real-domain> \
  --acme-email you@addr --token-file ~/.dynv6-token --edge single-host
#    Expect: every step "auto: ... done" ending with "provisioning
#    complete; relay_url now https://<real-domain>", then the external
#    curl hint. A non-root run prints all ten manual commands instead.
#    Verify the artifact set on disk:
ls -la /usr/local/bin/ocliv /usr/local/bin/ocliv-relay-launch.sh \
       /etc/ocliv/relay.env /var/lib/ocliv /etc/caddy/Caddyfile \
       /etc/systemd/system/ocliv-relay.service
id ocliv && systemctl is-active caddy ocliv-relay

# 1b. Source path (install.sh) for operators who build from a checkout:
sudo mkdir -p /opt && sudo cp -r /home/<you>/ocliv /opt/ocliv
cd /opt/ocliv/packaging/install
sudo DOMAIN=<real-domain> MCP_HOST=<real-domain> ./install.sh
#    Expect: "installed ...; env ... (0600)" and the next-step line.
#    Any failure exits nonzero and leaves the previous install intact —
#    verify `ls -la /usr/local/bin/ocliv* /etc/ocliv/relay.env` is UNCHANGED.

# 2. Rollback drill (recommended on first clean host): break the
#    Caddyfile (or the env file), re-run the same installer, confirm
#    nonzero exit AND the previous artifacts restored byte-identical
#    (and for setup --auto: binary restored, data dir removed only if
#    this run created it, ocliv account kept, Caddy reloaded).

# 3. Enable + enroll for the install.sh path (setup --auto already did):
systemctl enable --now ocliv-relay
systemctl is-active ocliv-relay
sudo -u ocliv /usr/local/bin/ocliv relay issue-enroll --data /var/lib/ocliv --tenant home
#    (then `ocliv login` with the printed code on the client machine)

# 4. External proof (from ANOTHER network, no -k):
curl -v https://<real-domain>/v1/agent/challenge
#    Expect: relay 4xx (not a TLS error) => DNS + cert + edge live.
ocliv doctor   # client-side: relay reachability + TLS identity verified
```

## Pass/fail

- PASS requires step 4's external 4xx AND `ocliv doctor` TLS verified.
- Any `421 misdirected`, TLS error, or connection refused = FAIL:
  check `journalctl -u ocliv-relay`, `caddy validate`, DNS (`dig`).
- Record the date, host, domain, commit hash, and the curl output.
  Local green (`go test ./...`) is NEVER production proof.

## 2026-11-13 hermetic record for the automated path (working tree)

Covered by `go test ./internal/setup/ -count=1` and
`go test ./packaging/install/ -count=1` on this tree: the ten-step
plan for a viable path in prerequisite order (service account →
binary → launcher → data dir → env → Caddyfile → Caddy activation →
unit → relay start → enrollment), the same set as manual commands
for non-root, the 0600 env install with marker and unmanaged
refusal, the launcher install (shebang line 1, marker line 2, 0755),
data-dir create/keep/rollback (existing state never removed), the
binary first-candidate rollback, the mode-preserving managed-file
rollback, and the template pin for the pinned-issuer Caddyfile.

NOT covered here (needs a real host): live root execution of every
executor, real ACME issuance, public reachability. A live clean-host
run of `setup --auto` on a public domain remains operator-gated and
is recorded separately when performed.

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
