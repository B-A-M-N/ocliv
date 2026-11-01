# Full invariant matrix (89 invariants)

Scope rule: PASS (local) = exercised by a real test on loopback/same-host
boundary with a negative arm where noted. NOT PROVEN (external) = needs
staging (DNS/TLS/edge/soak/clean-host) and is not claimed. CARRIED = prior
report's disposition, not re-proven here.

## A. Product, configuration, UX

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| A01 | CLI enrollment flow; no agent listener (`agent.go` outbound only) | enrol/attach integration tests | PASS (local) |
| A02 | Agent dials out only; no `Listen` in agent pkg | `grep`-level: no listener; attach tests | PASS (local) |
| A03 | `config.ValidatePort` | `TestValidatePort` | PASS |
| A04 | Protected default; `--public` explicit (`cmdTunnel`, lease `access_mode`) | `TestPublicModeExceptionScope`, reclaim mode-change test | PASS (local) |
| A05 | `renderStatus` UNKNOWN vs relay state; doctor probes | `TestRenderStatusDistinguishesAuthoritative/Route` | PASS (local) |
| A06 | `cli.go` precedence flags>env>config>default | CLI config tests | PASS (local) |
| A07 | attach `--json` omits share URL (opt-in) | `TestAttachJSONOmitsShareURL`-class tests | PASS (local) |
| A08 | typed `apperr` codes for unsupported targets | `TestExitForMapping`, validate tests | PASS (local) |
| A09 | `ExitFor` mapping; reconnect stays running | `TestExitForMapping`, reconnect tests | PASS |

## B. Encryption, identity, enrollment

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| B01 | Public HTTPS terminates at Caddy edge | Caddyfile template (unverified live) | NOT PROVEN (external) |
| B02 | `transport.checkedTLS` (verify required) | `TestCheckedTLSRefusesUnverifiedWSS`, `TestIsWSS` | PASS |
| B03 | WSS agent↔relay; plaintext only loopback edge | `TestCheckedTLSPlaintextLoopbackOnly` | PASS (local) |
| B04 | `lookupKey` status + handshake sig verify | handshake tests, `TestRevokeBlocksResume` | PASS (local) |
| B05 | single-use enrollment codes (`IssueEnrollmentCode`) | enroll/redeem tests | PASS (local) |
| B06 | Ed25519 challenge/nonce/version/intent binding | `TestHandshakeVersionEnforced`, nonce tests | PASS (local) |
| B07 | one-time nonces: challenge + mgmt (`consumeMgmtNonce`) | `TestMgmtMutationReplayRejected`, `TestNonceTableBounded` | PASS (local) |
| B08 | 0600 key files; unsafe perms refused | `TestSaveLoadRoundTrip` + unsafe-perm arm | PASS |
| B09 | revoked keys denied (connect + resume) | `TestRevokeBlocksResume`, takedown tests | PASS (local) |
| B10 | version match enforced (`handleConnect`) | `TestHandshakeVersionEnforced` | PASS (local) |
| B11 | cert lifecycle monitoring | none in-tree | NOT PROVEN (external) |

## C. Visitor authorization, browser security

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| C01 | `checkVisitorToken`/`checkCookieSession` before stream | header/cookie integration tests | PASS (local) |
| C02 | hostname randomness ≠ auth (`RandomHostname` + auth still required) | protected tests without credential → deny | PASS (local) |
| C03 | separate domains (tunnel vs app creds) | `TestRelayCredentialNeverForwarded` | PASS (local) |
| C04 | `ExtractHeader` relay credential path | `TestHeaderTokenAuth` | PASS (local) |
| C05 | host-only Secure/HttpOnly cookie redeem | cookie integration tests | PASS (local) |
| C06 | CSPRNG tokens, hashed verifiers, expiry, revoke | `access_test.go` round-trip/tamper tests | PASS |
| C07 | atomic consume UPDATE | `TestSingleUseTokenNoDoubleSpend`, `TestRevokeDuringUseDeniesAfterCommit` | PASS (local) |
| C08 | `CheckCSRF` exact-origin/proof | `TestCheckCSRF` incl. suffix-reject | PASS |
| C09 | auth-before-101 + origin check (`relay_ws.go`) | subprotocol match/mismatch tests | PASS (local) |
| C10 | `revokeLease` + `evictLease`, no grace | takedown + revoke integration tests | PASS (local) |
| C11 | `/_tunnel/` reserved, never forwarded | proxy reserved-path tests | PASS (local) |
| C12 | share link = bearer, revocable | share/redeem/revoke tests | PASS (local) |

## D. Hostname, tenant, destination isolation

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| D01 | exact-Host route to one lease+generation | `TestConcurrentIsolation`, routing tests | PASS (local) |
| D02 | Host/SNI/namespace validation (`route`, `SplitHost`); agent control requires exact relay authority, no loopback bypass (`relay_authority.go`) | `TestSplitHost`, malformed-host tests, `TestAgentPathsRequireRelayAuthorityEvenFromLoopback`, `TestAgentPathsRejectTunnelAuthorityThroughEdge` | PASS (local) |
| D03 | no default tenant; 4xx on unmatched | unmatched-host tests | PASS (local) |
| D04 | owner-checked reclaim + atomic replace | `TestNamedReclaimCutsOverTraffic`, `TestNamedReclaimRetiresOldSession` | PASS (local) |
| D05 | CSPRNG hostnames, no cross-owner reuse | `TestMintFormats`, reclaim tests | PASS (local) |
| D06 | fixed loopback dial (`localClient`, `LoopbackTarget`) | `TestLoopbackTarget` | PASS |
| D07 | public requests can't reroute (`RequestHead` fixed) | mode-change allocates fresh (positive) | PASS (local) |
| D08 | edge strips/appends; `clientIP` rightmost-from-loopback | `TestClientIPHonorsEdgeForwarding`, `TestPreAuthSpoofedHeaderIgnoredDirect` | PASS (local) |
| D09 | `X-Forwarded-Host` set explicitly; opt-in override | proxy header tests | PASS (local) |
| D10 | no redirect-following (`ProbeLocal`, transport no-redirect) | redirect unit tests | PASS |
| D11 | no CONNECT/open-proxy; WS only via validated path | `TestRelayServeRefusesPublicListen`, WS tests | PASS (local) |

## E. HTTP correctness, streaming, multiplexing

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| E01 | proxy request/response syntax checks | `FuzzCheckRequestSyntax` 2m PASS + unit tests | PASS |
| E02 | yamux stream per request, lease-bound | stream/concurrency tests | PASS (local) |
| E03 | length-bounded versioned frames (`protocol.go`, `WriteFull`) | protocol unit + short-write tests | PASS |
| E04 | no cross-wiring across streams | `TestConcurrentIsolation`, high-throughput echo | PASS (local) |
| E05 | bounded buffers + backpressure streaming | large-body/stream tests, `TestSlowUploadBeatsHeadTimeout` (slow valid upload never falsely completed/failed) | PASS (local) |
| E06 | bidirectional cancel propagation | `TestWebSocketAbruptCloseNoPoison`, cancel tests | PASS (local) |
| E07 | hop-by-hop strip, app headers preserved (incl. `Authorization`, `MCP-Protocol-Version`, `Mcp-Session-Id`, `Origin` for app policy) | proxy header tests, `TestMCPHeaderPreservation` | PASS (local) |
| E08 | relay creds stripped before localhost | `TestRelayCredentialNeverForwarded`, `TestMCPHeaderPreservation` (spoofed relay header absent upstream), `TestExplicitInvalidCredentialNoCookieFallback` | PASS (local) |
| E09 | no silent method/body rewrite | echo fidelity tests | PASS (local) |
| E10 | 101 only after auth+route+upstream accept | WS match/mismatch + immediate tests | PASS (local) |
| E11 | SSE flush + backpressure/cancel | SSE integration tests | PASS (local) |
| E12 | unknown semantics explicit, never approximated | `TestHandshakeVersionEnforced`, 502 paths | PASS (local) |
| E13 | committed response not replaceable | single-writer stream ownership tests | PASS (local) |
| E14 | no auto-replay on uncertain delivery | no retry-on-unknown in agent/relay | PASS (local, by construction + suite) |
| E15 | per-stream memory bounds; congestion isolated | throughput + limits tests | PASS (local) |

## F. Lifecycle and readiness

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| F01 | `lease.go` transition table | `TestTransition*`, fuzz `FuzzLeaseTransition` 45s PASS | PASS |
| F02 | one live generation; `registerSession` rejects stale; `markReconnecting` CAS on (id, generation, ACTIVE) | `TestRegisterStaleGenerationRejected`, `TestDetachStaleKeepsActive`, `TestStaleDisconnectCannotDowngradeNewGeneration`, `TestMarkReconnectingPropagatesDBErrors` | PASS (local) |
| F03 | atomic fence UPDATE; `Fence()` monotonic | `FuzzLeaseFenceMonotonic`, resume-fence tests | PASS |
| F04 | reclaim within grace keeps hostname | reclaim tests | PASS (local) |
| F05 | resume re-checks owner/expiry/revoke atomically | `TestClosedResumeIsTerminal`, `TestRevokeBlocksResume` | PASS (local) |
| F06 | `!Ready` denies all creation; live probe before print | bypass/TTL tests + `ProbeLocal` honest-report tests | PASS (local) |
| F07 | non-ACTIVE routes deny; TTL bounds in-flight (upload reads, stream frames, head-wait fire) | `TestLeaseStatusReflectsRouteLiveness`, TTL tests, `TestSlowUploadBeatsHeadTimeout`, silence-prompt-504 test | PASS (local) |
| F08 | typed timeouts, no silent hangs; upload-idle (not absolute) policy pre-completion, response deadline post-completion | timeout/terminal-error tests, `TestSlowUploadBeatsHeadTimeout`, `TestUpstreamSilenceAfterUploadTimesOut` | PASS (local) |
| F09 | bounded backoff+jitter reconnect | reconnect tests | PASS (local) |
| F10 | SIGTERM drain + close via live attachment | `shutdownLeaseID` tests; close-on-shutdown path | PASS (local) |
| F11 | restart refuses traffic until reconcile; terminal stays | `TestBootReconciliation`, restart tests | PASS (local) |
| F12 | FK pragma+verify; save errors fail attach | `TestForeignKeysEnforced`, `TestSaveLeaseErrorSurfaced` | PASS |
| F13 | late frames can't take over released names | detach/stale-generation tests | PASS (local) |

## G. Resource governance

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| G01 | header/meta/frame/stream bounds (`limits`) | limits unit tests | PASS |
| G02 | pre-auth throttle before stream creation | `TestPreAuthFloodFailsClosed` | PASS (local) |
| G03 | per-tenant/lease independent quotas | `TestPreAuthQuotasIndependentBehindEdge` | PASS (local) |
| G04 | idle-progress + max-lifetime on WS/SSE | `TestWSMaxLifetimeEnforced` | PASS (local) |
| G05 | deterministic 429/close, no deadlock | flood + throughput tests | PASS (local) |
| G06 | slow-read/write, flood, fragmentation, malicious upgrade | WS + limits adversarial tests | PASS (local) |
| G07 | enrollment + takedown precede open relay | enrollment + takedown tests | PASS (local) |
| G08 | bounded metrics cardinality | `TestSnapshotBounded` | PASS |

## H. Operations, packaging, qualification

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| H01 | loopback-only relay + health listener (`--health-listen`, loopback-validated, default 127.0.0.1:18080); TLS at Caddy | `TestRelayListenEnforcesLoopback`, `TestHealthListenEnforcesLoopback`, Caddyfile (template) | PASS (local); edge NOT PROVEN (external) |
| H02 | unit hardening (NoNewPrivileges, ProtectSystem…) | unit file (static; `systemd-analyze` clean exc. missing binary) | NOT PROVEN (clean-host run needed) |
| H03 | no secrets in logs/metrics/doctor | attach-JSON + credential tests | PASS (local) |
| H04 | audit rows per category | audit assertions in takedown/revoke tests | PASS (local) |
| H05 | attach vs route-live vs external-unknown | route status tests; external explicitly unclaimed | PASS (local) |
| H06 | restore is offline + fail-closed: active service refused, integrity + schema checked, every live revocation (leases REVOKED, keys/tokens/sessions revoked_at) must survive in the candidate | `TestRestoreRefusesRevocationRollback`, `TestRestoreAcceptsRevocationPreservingBackup` | PASS (local); clean-host run needed |
| H07 | idempotent schema (`CREATE TABLE IF NOT EXISTS`) + rollback-aware notes | `TestOpenAppliesSchema`, migration tests | PASS (local) |
| H08 | release provenance (git baseline + digest) | none — no commits exist | OPEN (needs authorized initial commit) |
| H09 | no SLA claimed without evidence | docs label targets as targets | PASS (by inspection) |
| H10 | external/adversarial/soak qualification | Gate A complete; B/D/E open | OPEN (staging needed) |

## M. MCP hosting security (V1 thin extension; mirrors normative spec §M)

Normative definitions live in `ocliv_invariants_and_exceptions_v1.md` §M
(preserved IDs, no silent changes). V1 scope: an existing HTTP MCP server
uses the ordinary secure forwarding path — no JSON-RPC parsing/rewriting
in the tunnel, no Ocliv-side OAuth validation (the app enforces
audience/issuer/expiry/scope on the exact token Ocliv forwards opaquely).
V1.1 adds the opt-in stdio adapter (`internal/mcp`, `ocliv mcp expose`)
and local management MCP (`ocliv mcp manage`); their rows below record
local evidence. OS-level confinement (dedicated user, systemd
restrictions) remains a deployment obligation, NOT PROVEN.

| ID | Enforcement | Key test(s) | Disposition |
|---|---|---|---|
| M01 | protected default; no silent public switch (`lease AccessMode`, mode-change allocates fresh) | unauthenticated JSON-RPC deny + zero app hits (`TestMCPOverOrdinaryForwardingPath`), mode-change tests | PASS (local) |
| M02 | resume with changed access mode allocates a new lease, never inherits exposure | mode-change tests (`revoke_test.go`) | PASS (local) |
| M03 | Ocliv credentials never reach the app (`SanitizeVisitorHeaders` strips `X-Ocliv-Authorization`) | adversarial spoof test, `TestMCPHeaderPreservation` | PASS (local) |
| M04 | app `Authorization` forwarded opaquely; Ocliv never validates/mints/strips it | `TestMCPHeaderPreservation` (`app_auth` byte-identical) | PASS (local); wrong-audience rejection is app-enforced — live provider interop NOT PROVEN (external) |
| M05 | stateless 2026-07-28 works without session id; legacy `Mcp-Session-Id` passes through | `TestMCPHeaderPreservation`, JSON-RPC roundtrip, SSE/WS suites | PASS (local) |
| M06 | cookie-auth same-origin enforced (`CheckCSRF`/`CheckUpgradeOrigin`); header-auth non-browser clients exempt, Origin preserved for app policy | `TestCSRFEnforcement`, `TestMCPHeaderPreservation` (foreign Origin passes with header auth) | PASS (local) |
| M07 | stdio adapter: command pinned once via local `LookPath` (no shell); HTTP traffic cannot select processes (single `Spawned`, shell-metachar injection echoed literally) | `TestNoShellInterpretation`, `TestCommandWithSpacesRejected`, `TestStdioAdapterThroughTunnel` | PASS (local); remote-process prohibition now enforced by construction, not absence |
| M08 | restricted OS authority for hosted stdio processes: loopback-only listener, scrubbed env (PATH + explicit only), pinned workdir, child killed+reaped on Close | `TestLoopbackOnly`, `TestEnvScrubbed` (positive + negative controls), `TestWorkingDirPinned`, `TestCloseTerminatesChild` | PASS (local); dedicated-OS-user/systemd confinement is deployment scope, NOT PROVEN |
| M09 | per-lease/per-tenant isolation (verifiers, generations, budgets) | tenant-isolation + concurrency suites | PASS (local) |
| M10 | revocation terminates new + in-flight access incl. streams | takedown/revoke suites, `TestRevokeTerminatesWebSocket` | PASS (local) |
| M11 | authorize-before-stream; denied MCP call never opens a stream | `TestMCPOverOrdinaryForwardingPath` (zero app hits on deny), C01 suites | PASS (local) |
| M12 | management MCP is local stdio only (`ocliv mcp manage`, closed 3-tool set, no shell/exec tool); visitor credential on `/v1/agent/lease/*` rejected 421 before lease lookup | `TestManageToolSurfaceClosed`, `TestManageUnknownToolRejected`, `TestRemoteManagementDeniedViaTunnel` + `TestMgmtMutationReplayRejected`, authority 421 suites | PASS (local) |
| M13 | result sizes/concurrency/lifetimes bounded (body caps, stream budgets, upload-idle policy, WS lifetimes; adapter: per-message cap, MaxConcurrent 503, round-trip timeout retires adapter, oversize/unterminated child output 502) | limits tests, `TestSlowUploadBeatsHeadTimeout`, `TestUpstreamSilenceAfterUploadTimesOut`, `TestPerLeaseStreamQuotaExhaustion` (65th concurrent stream 503 + release recovery), WS lifetime tests, `TestOversizeRequestRejected`, `TestOversizeChildOutputRejected`, `TestUnterminatedChildOutputRejected`, `TestConcurrencyExhaustion`, `TestTimeoutRetiresAdapter` | PASS (local); cross-machine load/soak NOT PROVEN (external) |
| M14 | explicit-invalid credential → hard 401, no cookie fallback, no app contact | `TestExplicitInvalidCredentialNoCookieFallback` | PASS (local) |
| M15 | per-client live evidence; no implied public/provider interop | this ledger + `docs/qualification/`; public custom-connection interop | Local PASS recorded; provider interop NOT PROVEN (external) |
| M16 | doctor speaks modern stateless MCP first (`MCP-Protocol-Version: 2026-07-28` tools/list, id-echoed), legacy handshake fallback; version mismatch never verifies | `TestProbeVerifiesModernStatelessServer`, `TestProbeMCPProtocolRequiresInitialize` (negative) | PASS (local) |
| M17 | OAuth discovery routed per published resource (`/.well-known/oauth-protected-resource/r/<id>/mcp` → upstream server-root form, bound to route ID+generation+host); publish validates advertised `resource` equals the route URL, mismatch fails closed with route deletion | `TestMCPRouteMetadataPathParsing`, `TestMCPRouteMetadataAdmitted`, `TestMCPRouteDiscoveryURL`, `TestValidateMCPResourceMetadata` | PASS (local); live provider flow NOT PROVEN (external) |
| M18 | anonymous fixtures cannot be published (serve/doctor local-only); publishing requires upstream-oauth; local endpoint must speak MCP before route registration (challenge suffices for oauth) | `TestParseMCPPublishFixtureAnonymousRefused`, `TestMCPPublishRejectsNonMCPServer`, `TestMCPPublishFullCycle*` | PASS (local) |
| M19 | doctor probes the recorded loopback family (`lease IPv6` flag), never the other family on the same port | `TestDoctorLoopbackTargetHonorsFamily` | PASS (local) |
