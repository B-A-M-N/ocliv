# Ocliv Current Qualification Status

**Production Promotion Status:** **HOLD**

This document is the single entry point for current verification status. Dated
historical qualification records live under `docs/qualification/history/`, and
structured evidence/receipts live under `docs/qualification/receipts/`.

Evidence is tracked strictly by exact commit SHA and separated into three
independent tiers: **Source/Unit-Tested**, **Isolated Artifact E2E**, and
**Public/Off-LAN/Live**. Results from earlier commits are NEVER transferred
across schema migrations or security-boundary changes.

## Verified Evidence by Exact Commit SHA

| Commit SHA | Schema | Source / Unit & Race Matrix | Isolated Artifact E2E (Pi `10.9.66.170`) | Public / Off-LAN / Live | Notes |
|---|---|---|---|---|---|
| `950440e` | V19 | PASS | PASS (29/0 loopback) | NOT VERIFIED | Historical baseline (`history/PI-ISOLATED-RESULT-2026-11-21.md`); superseded |
| `8cce9af` | V20 | PASS | NOT VERIFIED | NOT VERIFIED | Superseded by Round 2 & Round 3 remediation |
| `2f635e470183ed464150bdaceb2c1e674313cc27` | V21 | PASS (full suite + race matrix) | **PASS 60/0/0** (0 SKIP, 0 FAIL, strict release mode) | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`3b59bfddd623b133cd6112b17b2e35186adc4ea38e0f9db35e217f608fb853d3`); Phases A–I all PASS on `10.9.66.170`; production `ocliv-relay` (PID 1577) and `caddy` (PID 1574) untouched |
| `11dead068fa06f4dc152b5950aad5f6e233fdd94` | V22 | PASS (unit + hygiene + vet) | **PASS 61/0/0** + **V19→V22 migration 10/0** + **soak harness smoke PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`3b9ba712670d2769929b93152b0fe5af46cccfe7f04b14c6cc255d5c06b0bb67`); superseded by `071d7ff` |
| `071d7ff16638a55684d21f02b3a0cf22d652bda2` | V22 | PASS (installer/store/relay/cli/setup/doctor/systemd + `dash` multi-key test + hygiene + vet) | **PASS 65/0/0** (`--smoke`) + **V19→V22 online-snapshot migration 12/0** + **20s live-workload soak PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`4e35a4016298dc7c2c0825025cdd5afc63d8b138f24d2d825bf44a927e8732a1`); superseded by `b574879` |
| `b574879605e4ec9b1bfd62b356d6b19b05c1126f` | V22 | PASS (`installer`/`relay`/`cli`/`store` + `dash` multi-key/symlink/seq tests + hygiene + vet) | **PASS 65/0/0** (`--smoke`) + **V19→V22 full `--reset-authority` contract migration 12/0** + **20s dual-lane soak PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`3b9988a69dfd99d0e0706f857887798e4dcac8424304a2a714b5100e921981f7`); superseded by `3db67e0` |
| `3db67e0bc9df1990d31a72ec9d7b65bb917ee0cf` | V22 | PASS (`installer`/`relay`/`cli`/`store` + `dash` fail-closed dirty/schema/protocol negatives + hygiene + vet) | **PASS 65/0/0** (`--smoke`) + **V19→V22 migration 12/0** + **20s dual-lane soak PASS** + **`--release-gate` guard PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`5297e7636a15126eec2c897cf8c4cee62e724c5aa9183b402b0adaf9acb04811`); superseded by `df418cf` |
| `df418cf9e6ded0497dcd2d26f464f034e9d8d503` | V22 | PASS (`installer`/`relay`/`cli`/`store` + `dash` immutable-seq-identity & fail-closed tests + `soak --self-test` + hygiene + vet) | **PASS 66/0/0** (`--smoke`) + **V19→V22 migration 12/0** + **20s dual-lane soak PASS** + **`verify-promotion-evidence.py` smoke-refusal PASS** | NOT VERIFIED | Clean detached-worktree ARM64 artifact (`4c2dc35dd881706531ad543d5e183339e0a43a389c7a3140f7a8d51c0ecf73df`, `release_sequence=266`); superseded by `e468beb` |
| `e468bebfaf2299cb88423d702fa84acc51a10778` | V24 | **PASS** (full suite + `-race` + `govulncheck=pass`) | **PASS 67/0/0** (strict production) + **V17→V24 live-DB rehearsal 12/0** + **20s soak PASS** | NOT VERIFIED (superseded by `7ff4115`) | Clean signed bundle (`release_sequence=1003`); superseded by `7ff4115` (native transaction-bound auth default) |
| `7ff4115c6306afdf9d7cf9d6cd97427447701169` | V24 | **PASS** (full suite + `-race` + `govulncheck=pass`) | **PASS 67/0/0** (strict production) + **V17→V24 live-DB rehearsal 12/0** + **24h soak running** (`PID 951888`) | NOT VERIFIED (superseded by `88a11fe`) | Clean signed bundle (`release_sequence=1004`); superseded by `88a11fe` (native consent hardening, no implicit legacy fallback, Phase D2 artifact E2E) |
| `88a11fed7ed7f5f256a06cf85d3e2812a48d3b5d` | V24 | **PASS** (full `go test ./...`, `-race` on `authz`/`cli`/`protocol`/`identity`/`config`/`agent`/`store`/`lease`/`setup`/`relay`, `govulncheck=pass`, `gofmt`, `vet`, hygiene) | **PASS 88/0/0** (strict production release mode including **21 Phase D2 native tx-authz E2E checks**) + **V19→V24 migration 12/0** (all 12 `--reset-authority` zero-counts) | NOT VERIFIED (HOLD — awaiting `88a11fe` live-DB rehearsal, 24h soak & operator approval) | Clean signed production bundle (`release_sequence=1005`, `non_production=false`, AMD64 `72fe4f41…`, ARM64 `e90dc414…`): POST-only consent completion, strict CSP/`Referrer-Policy`/`X-Frame-Options`, bounded browser polling, redacted challenge audit logs, minimal pending response, explicit `--challenge` required (zero implicit legacy fallback), extended `ocliv version --json` capabilities, updated skills; production `ocliv-relay` (PID 1577), `caddy` (PID 1574), and running `7ff4115` soak (PID 951888) untouched |

## Latest Isolated Pi Staging Receipt (`88a11fe` — strict production release candidate)

- **Date:** 2026-11-25
- **Candidate Commit SHA:** `88a11fed7ed7f5f256a06cf85d3e2812a48d3b5d` (`dirty=false`, `non_production=false`, `govulncheck=pass`, `release_sequence=1005`, `signing_key_id=release-2026-v1`, `sbom_tool=cyclonedx-gomod`, schema `V24`)
- **AMD64 Binary SHA-256:** `72fe4f41dc02e3be2278f5c0d7996e39e1152881ccffb60381246fab23aa58b0`
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `e90dc414b0fb0d891932d71d9a2b539cd1130e45d1ab7983f0d59878c6a0b31c`
- **Release Manifest SHA-256:** `179d7e82735ecd522fd178b2e586209e98ce80a87931be3840c75793ddf892e7`
- **CycloneDX SBOM SHA-256 (`sbom.cdx.json`):** `eca6240686fc7a44e32e5dc38bc0cbfb7c46aaa5fe29a71740884e30a2e51b74`
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/prod-88a11fe-2026-11-25/` (`qual-receipt.json`, `mig-v19-v24-receipt.json`, `run-mig.sh`) and bundle `/home/bamn/ocliv-stage/prod-bundle-88a11fe-2026-11-25/`.
- **Strict Isolated Qualification (`qualify-pi-isolated.py --release-dir $BUNDLE --receipt-out ./qual-receipt.json`):** **PASS 88 / SKIP 0 / FAIL 0** (`mode=strict-production`, `schema=V24`, includes 21 Phase D2 native transaction-bound operator authorization E2E checks through the compiled ARM64 binary + HTTP ingress + Ed25519 management boundary).
- **Production-Gate Live DB Online-Snapshot Migration Rehearsal (`sudo /home/bamn/ocliv-stage/prod-88a11fe-2026-11-25/run-mig.sh`):** **PASS 12 / FAIL 0** (`src_schema=V17` → `V24`, all 12 `--reset-authority` zero-counts verified on real `/var/lib/ocliv/ocliv.db` online snapshot: keys, leases, publications, clients, grants, issuer keys, access tokens, visitor sessions, unconsumed consents, unconsumed OIDC tx, trust policies, visitor policies + cleared `client_secret`; candidate relay `/health/ready == 200` on restored DB; receipt `./mig-receipt.json`).
- **24-Hour Release-Gate Soak (`soak-isolated.py --release-gate`):** Running detached on Pi (`PID 957016`, log `/tmp/ocliv-soak-24h-88a11fe.out`, receipt target `./soak-24h-receipt.json`).
- **Schema V24 Durability & Credential Survival Note:** Production `/var/lib/ocliv/ocliv.db` remains at **V17** (no durable DB was ever created by earlier V24 candidates; all prior V24 DBs were disposable qualification workdirs deleted fail-closed by `I5b`). On ordinary forward migration (V17→V24): tenant/key identities, leases, publications, OAuth clients, revocations, and active non-direct grants survive; migrated `legacy` grants with `skip_pairing=1` are quarantined (`skip_pairing=0`) until reauthorized. On `relay restore --reset-authority`: tenant/key/lease/publication/client identities and revocation tombstones survive, while all active keys, live leases, publications, OAuth clients/grants, issuer keys, access tokens, visitor sessions, pending consents, pending OIDC transactions, trust policies, and visitor policies (including encrypted `client_secret`) are intentionally invalidated.
- **Production & Soak Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574`, running `7ff4115` soak `PID 951888` untouched.

## Prior Isolated Pi Staging Receipt (`7ff4115` — preserved)

- **Date:** 2026-11-25
- **Candidate Commit SHA:** `7ff4115c6306afdf9d7cf9d6cd97427447701169` (`dirty=false`, `non_production=false`, `govulncheck=pass`, `release_sequence=1004`, `signing_key_id=release-2026-v1`, `sbom_tool=cyclonedx-gomod`, schema `V24`)
- **AMD64 Binary SHA-256:** `59724cae02c14827307fb33b9f16d2d2c40ce7b0403008921072fb44609736e3`
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `d5c6c66fff2ca40ae74963bb3522b72ebfbaf8916f611733ce59a1bc83931c11`
- **Release Manifest SHA-256:** `efcfed02bb531d7f143f752315f1d3cf41a64c2f5dfbfd884aeed45c250f26b5`
- **CycloneDX SBOM SHA-256 (`sbom.cdx.json`):** `fbedffc2346ccfd5e513a793e934f110e6682e24be99b87b0bee2093ca7b20da`
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/prod-7ff4115-2026-11-25/` (`qual-receipt.json`, `run-mig.sh`) and bundle `/home/bamn/ocliv-stage/prod-bundle-7ff4115-2026-11-25/`.
- **Strict Isolated Qualification (`qualify-pi-isolated.py --release-dir $BUNDLE --receipt-out ./qual-receipt.json`):** **PASS 67 / SKIP 0 / FAIL 0** (`mode=strict-production`, `schema=V24`, `ephemeral_state_retained=false`, `scratch_cleanup_ok=true`).
- **Production-Gate Live DB Online-Snapshot Migration Rehearsal (`sudo rehearse-prod-migration.py --production-gate --src-db /var/lib/ocliv/ocliv.db --qualification-receipt ./qual-receipt.json --receipt-out ./mig-receipt.json`):** **PASS 12 / FAIL 0** (`src_journal_mode=wal`, `src_schema=V17` → `V24`, snapshot SHA-256 `1ae6f7ac8ad45c7758c61b10658fade3d0b5b332d0c90c75802ac655ad7c1f7d`; 3 tenants, 3 agent keys, 7 leases, 5 publications, 9 clients, 12 grants, 30 revocations preserved identically; `PRAGMA integrity_check=ok`, `foreign_key_check=[]`, backup+validate+restore `--reset-authority` PASS with `preserved_diffs=[]`, candidate relay `/health/ready == 200` on restored DB).
- **24-Hour Release-Gate Soak (`soak-isolated.py --release-gate`):** Running detached on Pi (`PID 951887`, log `/tmp/ocliv-soak-24h-7ff4115.out`, receipt target `./soak-24h-receipt.json`).
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Staging Receipt (`e468beb` — preserved)

- **Date:** 2026-11-25
- **Candidate Commit SHA:** `e468bebfaf2299cb88423d702fa84acc51a10778` (`dirty=false`, `non_production=false`, `govulncheck=pass`, `release_sequence=1003`, `signing_key_id=release-2026-v1`, `sbom_tool=cyclonedx-gomod`, schema `V24`)
- **AMD64 Binary SHA-256:** `d6621fc5e8976e5c3b07d566078ffe784a6775be1d7eb45103d363ceb192be50`
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `6d3071b567ff550706717c7493cd97b0e07a8162db5b1f8183c05db1195e97e3`
- **Release Manifest SHA-256:** `6205c838934baaf43a3880687493463041e113680bb6f5c9b75af94fca8bab70`
- **CycloneDX SBOM SHA-256 (`sbom.cdx.json`):** `09239f98877c675cd94ffca72e123070b2502afc94ad4c5843528cb0686d0015`
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/prod-e468beb-2026-11-25/` (`qual-receipt.json`, `mig-v19-v24-receipt.json`, `soak-smoke-receipt.json`) and bundle `/home/bamn/ocliv-stage/prod-bundle-e468beb-2026-11-25/` — strict public allowlist verified (`I5b` fail-closed `WORK_DIR` removal PASS + `I6` zero raw logs/keys/DBs/secrets retained).
- **Strict Isolated Qualification (`qualify-pi-isolated.py --release-dir $BUNDLE --receipt-out ./qual-receipt.json`):** **PASS 67 / SKIP 0 / FAIL 0** (`mode=strict-production`, `schema=V24`, `ephemeral_state_retained=false`, `scratch_cleanup_ok=true`).
- **Production-Gate Live DB Online-Snapshot Migration Rehearsal (`sudo rehearse-prod-migration.py --production-gate --src-db /var/lib/ocliv/ocliv.db --qualification-receipt ./qual-receipt.json --receipt-out ./mig-receipt.json`):** **PASS 12 / FAIL 0** (`src_journal_mode=wal`, `src_schema=V17` → `V24`, snapshot SHA-256 `62742ee0834938d8da28a55a0a3de601b5fdf5e17bc7ab8af7a765260b8cf8cc`; 3 tenants, 3 agent keys, 7 leases, 5 publications, 9 clients, 12 grants, 30 revocations preserved with identical 64-hex semantic digests; `PRAGMA integrity_check=ok`, `foreign_key_check=[]`, backup+validate+restore `--reset-authority` PASS with `preserved_diffs=[]`, candidate relay `/health/ready == 200` on restored DB).
- **24-Hour Release-Gate Soak (`soak-isolated.py --release-gate`):** Launched detached on Pi (`PID 944743`, receipt target `./soak-24h-receipt.json`; in progress).
- **Pre-Promotion Live Backup Taken:** `/var/lib/ocliv/backup-pre-e468beb.db` (verified written by operator).
- **Dual-Lane Workload Soak Smoke (`soak-isolated.py --self-test` + `--duration 20 --warmup 5 --sample-interval 5`):** **PASS** (`SOAK_SELF_TEST=OK`, `samples=5`, `dataplane_200=5`, `route_401=5`, `reconnects=1`, `pair_ok=5`, FDs `15->15`, RSS `16176KB->16648KB`, `active_sessions=2`).
- **Current Live Deployment Inventory (Read-Only Pre-Flight):**
  - Local publisher `/home/bamn/.local/bin/ocliv`: `vcs.revision=43043a9b86a7e6085d19524e70e3f4edc7063645` (`2026-11-18T04:14:06Z`, `vcs.modified=true`) — NOT yet upgraded.
  - Production Pi relay `/usr/local/bin/ocliv` (`5cb2a4e93ddc0b04ae006b66929ea9806d8341d1094810bd97ab87b92cbe94dc`): `vcs.revision=43043a9b86a7e6085d19524e70e3f4edc7063645` (`2026-11-18T04:14:06Z`, `vcs.modified=true`) — NOT yet upgraded.
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## OCL-001..009 Remediation Evidence Matrix (`e468beb`)

| Item | Requirement | Source & Unit/Race Evidence | Exact-Build Staging (`e468beb`) | Live / Operational Status |
|---|---|---|---|---|
| **OCL-001** | Authentication diagnostics | Implemented (`internal/cli/cli_mcp_url.go`, `internal/cli/cli_mcp_probe.go`); unit + `-race` PASS | Verified in `e468beb` bundle | Pending authorized binary deployment |
| **OCL-002** | Connectivity classification | Implemented (`internal/cli/cli_doctor.go`, `internal/doctor/`); unit + `-race` PASS | Verified in `e468beb` bundle | Pending authorized binary deployment |
| **OCL-003** | Canonical HTTPS probing | Implemented (`internal/cli/cli_mcp_probe.go`); unit + `-race` PASS | Verified in `e468beb` bundle | Pending authorized binary deployment |
| **OCL-004** | Events qualification | Hardened (`internal/cli/cli_mcp_events_qual.go`, `cli_mcp_events_qual_test.go`): distinct qualification levels (`READ_ONLY_EVENTS_VERIFIED`, `SUBSCRIPTION_VERIFIED`, `CALLBACK_DELIVERY_VERIFIED`, `SUBSCRIPTION_CLEANUP_VERIFIED`), correlated callback payload check, verified `events/unsubscribe` cleanup, `UNVERIFIED` external callback handling; unit + `-race` PASS | Verified in `e468beb` bundle | Pending live MCP server + authorized deployment |
| **OCL-005** | Native transaction-bound visitor auth (no mandatory external IdP / no pairing-secret copying) | **Canonical default:** native Ocliv transaction-bound operator approval over the Ed25519-signed management channel (`ocliv service pending/approve`, `/oauth/consent/status`, `/oauth/consent/complete`, `DecideConsentTransaction`, `GrantMethodOperatorTx`, durable grant + refresh token lifecycle; zero pairing secrets copied, zero Auth0/external IdP required). **Optional:** hardened federated OIDC (`go-oidc/v3` + `oauth2`, SSRF egress guard, `azp`, AES-256-GCM secret sealing, atomic `ApproveFederatedGrantAtomic`) retained for operators who opt in. Unit + `-race` PASS (`native_operator_consent_test.go`, `relay_native_consent_test.go`, `federated_authority_test.go`). | Qualified in isolated Pi staging (schema V24, zero Auth0 dependency) | Pending authorized binary deployment + live ChatGPT OAuth check |
| **OCL-006** | Revocation & V23→V24 migration | Hardened (`internal/store/store.go`, `store_v24_migration_test.go`, `internal/relay/relay_backup.go`): V24 quarantines migrated `legacy` `skip_pairing=1` grants (`skip_pairing=0`), `exactOperatorApprovedBinding` requires `direct_operator`, `--reset-authority` wipes `client_secret`, live grant/token revocation verified; unit + `-race` PASS | V19→V24 migration rehearsal 12/0 PASS | Live `/var/lib/ocliv/ocliv.db` rehearsal requires interactive `sudo` |
| **OCL-007** | Registration exhaustion protection | Verified (`internal/authz/sqlstore.go`, `federated_oidc_test.go`): DCR flood bounded at `MaxClientsPerRoute`, pending clients evicted without disturbing active/revoked grants; unit + `-race` PASS | Verified in `e468beb` bundle | Pending authorized binary deployment |
| **OCL-008** | Publisher enrollment | Implemented (`internal/cli/cli_device.go`); non-root same-host + SSH enrollment + durable identity; unit + `-race` PASS | Strict Pi Phase F pairing E2E PASS | Pending live post-deployment publisher verification |
| **OCL-009** | External host evidence | Hardened (`internal/relay/relay_public.go`, `relay_host_observations_test.go`, `internal/authz/host_observations.go`): JSON-RPC body method inspection (never trusts `MCP-Method` header over body), separates `transport_status` from JSON-RPC `result_category`, validates Events advertisement & `subscriptionId`, filters by tenant/route/canonical URL/generation/freshness, bounded retention (`MaxHostObservationsPerRoute=200`, 30d pruning); unit + `-race` PASS | Verified in `e468beb` bundle | External ChatGPT acceptance remains `EXTERNAL_ACCEPTANCE_UNVERIFIED` |

## Prior Isolated Pi Staging Receipt (`df418cf` — non-production staging smoke)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `df418cf9e6ded0497dcd2d26f464f034e9d8d503` (`dirty=false`, `govulncheck=pass`, `release_sequence=266`, `non_production=true` pending permanent offline production signing key & `cyclonedx-gomod`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `4c2dc35dd881706531ad543d5e183339e0a43a389c7a3140f7a8d51c0ecf73df`
- **Release Manifest SHA-256:** `88511a72c12188ba04ba793e966ab01651daf027c562723e1148a5c04ea1ea0f`
- **Signing Key ID:** `stage-ephemeral-df418cf` (ephemeral external `0600` Ed25519 key, unlinked immediately after signing)
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/stage-df418cf-2026-11-21/` (`qual-receipt.json`, `mig-receipt.json`, `soak-receipt.json`) — strict public allowlist verified (`I5b` fail-closed `WORK_DIR` removal PASS + `I6` zero raw logs/keys/DBs/secrets retained).
- **Isolated Staging Qualification (`qualify-pi-isolated.py --smoke --receipt-out ./qual-receipt.json`):** **PASS 66 / SKIP 0 / FAIL 0** (`ephemeral_state_retained: false`, `scratch_cleanup_ok: true`).
- **V19→V22 Online-Snapshot Migration Rehearsal (`rehearse-prod-migration.py --receipt-out ./mig-receipt.json`):** **PASS 12 / FAIL 0** (`reset_contract_version: 1`, `scratch_cleanup_ok: true`, `scratch_retained: false`, `preserved_diffs=[]`, all 8 reset authority counts `0`, restored-DB live relay `/health/ready == 200`).
- **Dual-Lane Workload Soak (`soak-isolated.py --self-test` + `--duration 20 --warmup 5 --sample-interval 5 --receipt-out ./soak-receipt.json`):** **PASS** (`SOAK_SELF_TEST=OK`, `dataplane_ok_200=5`, `disconnect_failed_as_expected=true`, `reconnects_completed=1`, `route_expected_401=5`, `pair_ok=5`, `recovery_required_at_end=false`, `scratch_cleanup_ok=true`, `scratch_retained=false`, FDs `15->15`, RSS `16192KB->16536KB`, `active_sessions=2`).
- **Promotion Verifier (`verify-promotion-evidence.py`):** Verified to fail closed on non-production smoke receipts (`VERIFY_PROMOTION_REJECTS_SMOKE=OK`).
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Staging Receipt (`3db67e0` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `3db67e0bc9df1990d31a72ec9d7b65bb917ee0cf` (`dirty=false`, `govulncheck=pass`, `non_production=true` pending permanent offline production signing key & `cyclonedx-gomod`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `5297e7636a15126eec2c897cf8c4cee62e724c5aa9183b402b0adaf9acb04811`
- **Release Manifest SHA-256:** `feefd76aebab38bbe521e8bbbcad613b42b7cc94c6c215f83a89a116987e8cb3`
- **Signing Key ID:** `stage-ephemeral-3db67e0` (ephemeral external `0600` Ed25519 key, unlinked immediately after signing)
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/stage-3db67e0-2026-11-21/` (`qual-receipt.json`, `mig-receipt.json`, `soak-receipt.json`) — strict public allowlist verified (`I6 PASS`, zero `.key`/`.db`/`.pem`/`qc.txt` retained).
- **Isolated Staging Qualification (`qualify-pi-isolated.py --smoke --receipt-out ./qual-receipt.json`):** **PASS 65 / SKIP 0 / FAIL 0** (`ephemeral_state_retained: false`).
- **V19→V22 Online-Snapshot Migration Rehearsal (`rehearse-prod-migration.py --receipt-out ./mig-receipt.json`):** **PASS 12 / FAIL 0** (`reset_contract_version: 1`, `sqlite_master`-verified mandatory V22 tables, `preserved_diffs=[]`, all 8 reset authority counts `0`, restored-DB live relay `/health/ready == 200`).
- **Dual-Lane Workload Soak (`soak-isolated.py --duration 20 --warmup 5 --sample-interval 5 --receipt-out ./soak-receipt.json`):** **PASS** (`dataplane_ok_200=5`, `disconnect_failed_as_expected=true`, `reconnects_completed=1`, `route_expected_401=5`, `pair_ok=5`, `expired_still_pending=0`, FDs `15->15`, RSS `16044KB->16456KB`, `active_sessions=2`); `--release-gate` verified to refuse `--duration 20`.
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Staging Receipt (`b574879` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `b574879605e4ec9b1bfd62b356d6b19b05c1126f` (`dirty=false`, `govulncheck=pass`, `non_production=true` pending permanent offline production signing key & `cyclonedx-gomod`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `3b9988a69dfd99d0e0706f857887798e4dcac8424304a2a714b5100e921981f7`
- **Release Manifest SHA-256:** `9e2aef55cd59cd70404704546943a73a0c2ad7ccf60d91cf136a67942f8bf467`
- **Signing Key ID:** `stage-ephemeral-b574879` (ephemeral external `0600` Ed25519 key, unlinked immediately after signing)
- **Pi Stage Directory & Machine-Readable Receipts:** `/home/bamn/ocliv-stage/stage-b574879-2026-11-21/` (`qual-receipt.json`, `mig-receipt.json`, `soak-receipt.json`)
- **Isolated Staging Qualification (`qualify-pi-isolated.py --smoke --receipt-out ./qual-receipt.json`):** **PASS 65 / SKIP 0 / FAIL 0**
- **V19→V22 Online-Snapshot Migration Rehearsal (`rehearse-prod-migration.py --receipt-out ./mig-receipt.json`):** **PASS 12 / FAIL 0** (full 64-hex canonical semantic digests identical across migration; post-`--reset-authority` `unchanged_ok=True` across all 6 identity/revocation categories and all 8 authority categories reset to `0`; restored-DB live relay `/health/ready == 200`).
- **Dual-Lane Workload Soak (`soak-isolated.py --duration 20 --warmup 5 --sample-interval 5 --receipt-out ./soak-receipt.json`):** **PASS** (`dataplane_ok_200=5` with exact echoed `soak_nonce` and advancing upstream hits, `disconnect_failed_as_expected=true`, `reconnects_completed=1`, `route_expected_401=5`, `pair_ok=5`, `unexpected_fail=0`, FDs `15->15` max `15` slope `0.0/hr`, RSS `15964KB->16492KB` median `16364KB`, `active_sessions=2`).
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Staging Receipt (`071d7ff` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `071d7ff16638a55684d21f02b3a0cf22d652bda2` (`dirty=false`, `govulncheck=pass`, `non_production=true` pending permanent signing key & `cyclonedx-gomod`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `4e35a4016298dc7c2c0825025cdd5afc63d8b138f24d2d825bf44a927e8732a1`
- **Signing Key ID:** `stage-ephemeral-071d7ff` (ephemeral external `0600` Ed25519 staging key, unlinked immediately after signing)
- **Pi Stage Directory:** `/home/bamn/ocliv-stage/stage-071d7ff-2026-11-21`
- **Isolated Staging Qualification (`qualify-pi-isolated.py --smoke`):** **PASS 65 / SKIP 0 / FAIL 0**
  - Phase G5 (`install-client.sh` in sanitized minimal PATH): explicitly excludes `go`, `git`, `caddy`, `docker`, `jq`, `ocliv`, `xxd`, and `python3`; valid signed install PASS, tampered manifest/sig/artifact rejected, and test-trust override without `OCLIV_ALLOW_TEST_TRUST=1` refused.
  - Phase H: real `--max-publisher-sessions=2`, `--max-http-streams=2` (2 held open, 3rd rejected 503 while `/health/ready=200`, release, recovers to 0), and `--max-ws-streams=2` (2 held 101, 3rd rejected 503 while `/health/ready=200`, close 1, 4th admitted 101, recovers to 0).
  - Phase I6: zero ephemeral secret files (`*.pem`, `qc.txt`) retained in stage directory.
- **V19→V22 Online-Snapshot Migration Rehearsal (`rehearse-prod-migration.py` against transactionally consistent read-only online snapshot of `stage-950440e` WAL DB):** **PASS 12 / FAIL 0** (`src_journal_mode=wal`, `src_schema=V19`, snapshot SHA-256 `70bad61c79ee9ff247979189cbf1034030a59a8b69d0862b0ad97a190114b104`; canonical sorted semantic SHA-256 digests identical across `tenants`, `agent_keys`, `leases`, `terminal_leases`, `mcp_publications`, `authz_clients`, `authz_grants`, `authz_revocations`; restored DB integrity/FK/schema/reset-authority verified + candidate relay `/health/ready == 200` on restored DB).
- **Live-Workload Soak Smoke (`soak-isolated.py --duration 20 --sample-interval 5 --receipt-out ./soak-receipt.json`):** **PASS** (`samples=5`, `reconnects_completed=1`, `route_expected_401=5`, `pair_ok=5`, `unexpected_fail=0`, FDs `13->13`, RSS `15632KB->16156KB`, `active_sessions=1`).
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Qualification Receipt (`11dead0` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `11dead068fa06f4dc152b5950aad5f6e233fdd94` (`dirty=false`, `govulncheck=pass`, schema `V22`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `3b9ba712670d2769929b93152b0fe5af46cccfe7f04b14c6cc255d5c06b0bb67`
- **Release Manifest SHA-256:** `cfa6e7ea6613d6f2d4231352f21e9b5ed8c59a704ac4e2819385677e192acdb7`
- **Signing Key ID:** `stage-ephemeral-11dead0` (ephemeral external `0600` Ed25519 staging key)
- **Pi Stage Directory:** `/home/bamn/ocliv-stage/stage-11dead0-2026-11-21`
- **Strict Qualification (`qualify-pi-isolated.py`):** **PASS 61 / SKIP 0 / FAIL 0**
- **V19→V22 Migration Rehearsal (`rehearse-prod-migration.py` against read-only copy of `stage-950440e` DB):** **PASS 10 / FAIL 0** (`PRAGMA integrity_check=ok`, `foreign_key_check=[]`, keys/leases/publications/OAuth grants/revocations preserved, backup + validate-backup + restore `--reset-authority` PASS)
- **Soak Harness Smoke (`soak-isolated.py --duration 10`):** **PASS** (FDs `11->11`, RSS `14972KB->15348KB`, `process_ready=true`)
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Prior Isolated Pi Qualification Receipt (`2f635e4` — preserved)

- **Date:** 2026-11-21
- **Candidate Commit SHA:** `2f635e470183ed464150bdaceb2c1e674313cc27` (`dirty=false`, `govulncheck=pass`, schema `V21`)
- **ARM64 Binary SHA-256 (verified post-transfer on Pi):** `3b59bfddd623b133cd6112b17b2e35186adc4ea38e0f9db35e217f608fb853d3`
- **Release Manifest SHA-256:** `2762ee7904b3df0c767a773d4f7408e9251c519bf767292ce744a34bdfbb9e24`
- **Signing Key ID:** `stage-ephemeral-2f635e4` (ephemeral external 0600 Ed25519 staging key; real production signing key & CycloneDX SBOM tool remain outstanding for production release)
- **Pi Stage Directory:** `/home/bamn/ocliv-stage/stage-2f635e4-2026-11-21`
- **Qualification Result:** **PASS 60 / SKIP 0 / FAIL 0** (`qualify-pi-isolated.py` strict release mode)
  - Phases A, A2, B, C, D, E: managed OAuth, restart durability, security boundaries, rollback guard — **PASS**
  - Phase F: `pair --no-wait` → `relay approve` → `pair resume` → live publisher attach + V21 `poll_verifier`/`resolved_tenant_id` DB checks — **PASS**
  - Phase G: signed manifest/artifacts + sanitized minimal-PATH `dash` bootstrap (`install-client.sh`, no go/git/caddy/docker/jq/ocliv) + manifest/sig/artifact tamper rejection — **PASS**
  - Phase H: `--max-publisher-sessions=2` saturation (2 admitted, 3rd rejected before WS upgrade, disconnect + re-admit without leakage) — **PASS**
  - Phase I: role separation (zero relay DB/Caddy/DNS creds in publisher home, zero inbound listening sockets on publisher PID 287606) + live `relay revoke-key --key-id` — **PASS**
- **Production Isolation Proof:** `ocliv-relay` MainPID `1577` → `1577`, `caddy` MainPID `1574` → `1574` (untouched).

## Outstanding Promotion Gates (Required Before Lifting HOLD)

| Gate | Tier | Status |
|---|---|---|
| Production release build with permanent production Ed25519 trust-root key (`release-2026-v1`) + CycloneDX SBOM (`cyclonedx-gomod`) + `govulncheck=pass` | Release Provenance | **VERIFIED** (`88a11fe`, `release_sequence=1005`) |
| Strict isolated Pi staging qualification (`qualify-pi-isolated.py`, 88/0/0 incl. Phase D2 native tx-authz E2E) | Isolated Artifact E2E | **VERIFIED** (`88a11fe`, production PIDs untouched) |
| Live production DB copy migration rehearsal (`sudo /home/bamn/ocliv-stage/prod-88a11fe-2026-11-25/run-mig.sh`) | Operator-Gated Pre-Flight | **VERIFIED** (`88a11fe`, V17→V24, **PASS 12/0**, all 12 `--reset-authority` zero-counts, `mig-receipt.json`) |
| 24-hour release-gate soak (`soak-isolated.py --release-gate`) | Isolated Artifact E2E | **IN PROGRESS** (`88a11fe` `PID 957016`, `7ff4115` `PID 951888` running side-by-side) |
| Native Ocliv transaction-bound OAuth E2E (no external IdP / no pairing-secret copying) | Public / Off-LAN / Live | **SOURCE & ISOLATED VERIFIED; live post-deploy check pending** |
| Off-LAN trusted-TLS public ingress verification (no `-k`) & authenticated public Events workflow | Public / Off-LAN / Live | **NOT VERIFIED** |
| Official ChatGPT OAuth end-to-end acceptance | Public / Off-LAN / Live | **NOT VERIFIED** |
| Explicit operator authorization to deploy/migrate production relay (`/usr/local/bin/ocliv`) and local publisher (`/home/bamn/.local/bin/ocliv`) | Release Governance | **HOLD** |
