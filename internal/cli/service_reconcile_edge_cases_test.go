package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestP0HTTPNeverClaimsServingWithoutAuthoritativeLiveLease(t *testing.T) {
	kp, _ := identity.Generate()
	activeOps := func(mgmt func(string, *identity.KeyPair, string, string, string) (int, []byte, error)) serviceOps {
		return serviceOps{
			probeLoc: func(string, time.Duration) error { return nil },
			systemctl: func(args ...string) (string, error) {
				if len(args) > 0 && args[0] == "show" {
					return "loaded", nil
				}
				if len(args) > 0 && args[0] == "is-enabled" {
					return "enabled", nil
				}
				return "active", nil
			},
			mgmtCall: mgmt,
		}
	}

	// 1. Publisher active, backend ready, NO LeaseID -> must NOT be SERVING or Lease=valid.
	recNoLease := config.ServiceRecord{
		Name: "http-nolease", Type: "http", LocalURL: "http://127.0.0.1:3000",
		Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@http-nolease.service",
	}
	rep := inspectServiceStatus(recNoLease, kp, "k1", activeOps(nil))
	if rep.State == ServiceStateServing || rep.Layers.Lease == "valid" {
		t.Fatalf("P0 REPRODUCED: HTTP service with no LeaseID claimed state=%s lease=%s", rep.State, rep.Layers.Lease)
	}

	// 2. Publisher active, backend ready, relay UNREACHABLE -> must NOT be SERVING.
	recWithLease := recNoLease
	recWithLease.LeaseID = "lse-1"
	repUnreach := inspectServiceStatus(recWithLease, kp, "k1", activeOps(func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
		return 0, nil, errors.New("dial tcp: connection refused")
	}))
	if repUnreach.State == ServiceStateServing || repUnreach.Layers.Lease == "valid" || repUnreach.Layers.Agent == "connected" {
		t.Fatalf("P0 REPRODUCED: HTTP service with unreachable relay claimed state=%s lease=%s agent=%s", repUnreach.State, repUnreach.Layers.Lease, repUnreach.Layers.Agent)
	}

	// 3. Valid lease exists on relay, but route_live=false (disconnected session) -> must NOT be SERVING.
	repOffline := inspectServiceStatus(recWithLease, kp, "k1", activeOps(func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
		return http.StatusOK, []byte(`{"lease_id":"lse-1","status":"ACTIVE","route_live":false,"route_available":false,"generation":1,"url":"https://app.t.relay.example"}`), nil
	}))
	if repOffline.State == ServiceStateServing || repOffline.Layers.Agent == "connected" {
		t.Fatalf("P0 REPRODUCED: HTTP service with route_live=false claimed state=%s agent=%s", repOffline.State, repOffline.Layers.Agent)
	}

	// 4. Lease EXPIRED -> must NOT be SERVING.
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	repExpired := inspectServiceStatus(recWithLease, kp, "k1", activeOps(func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
		return http.StatusOK, []byte(`{"lease_id":"lse-1","status":"EXPIRED","route_live":false,"route_available":false,"generation":1,"lease_expires_at":"` + past + `"}`), nil
	}))
	if repExpired.State == ServiceStateServing {
		t.Fatalf("P0 REPRODUCED: expired HTTP lease claimed SERVING: %+v", repExpired)
	}

	// 5. Stale generation (relay generation < recorded StateGeneration) -> must NOT be SERVING.
	recStale := recWithLease
	recStale.StateGeneration = 5
	repStale := inspectServiceStatus(recStale, kp, "k1", activeOps(func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
		return http.StatusOK, []byte(`{"lease_id":"lse-1","status":"ACTIVE","route_live":true,"route_available":true,"generation":3,"url":"https://app.t.relay.example"}`), nil
	}))
	if repStale.State == ServiceStateServing {
		t.Fatalf("P0 REPRODUCED: stale HTTP lease generation claimed SERVING: %+v", repStale)
	}

	// 6. Authoritative ACTIVE + route_live + route_available + unexpired -> SERVING.
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	repOK := inspectServiceStatus(recWithLease, kp, "k1", activeOps(func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
		return http.StatusOK, []byte(`{"lease_id":"lse-1","status":"ACTIVE","route_live":true,"route_available":true,"generation":2,"lease_expires_at":"` + future + `","url":"https://app.t.relay.example"}`), nil
	}))
	if repOK.State != ServiceStateServing || repOK.Health != HealthReady || repOK.Layers.Lease != "valid" || repOK.Layers.Agent != "connected" {
		t.Fatalf("expected SERVING/READY/valid/connected for healthy HTTP lease, got %+v", repOK)
	}
}

func TestHelperProcessHostJSON(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_HOST_JSON") != "1" {
		return
	}
	scenario := os.Getenv("HOST_JSON_SCENARIO")
	home := os.Getenv("HOME")
	cfgDir := filepath.Join(home, ".config", "ocliv")
	_ = os.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	_ = os.Setenv("OCLIV_PROFILE", "")
	_ = os.Setenv("USER", "testuser")

	switch scenario {
	case "success":
		seedEnrolledProfileForTest(t, "https://relay.example")
		ops := serviceOps{
			provision: func(config.ServiceRecord, serviceOps) error { return nil },
			probeLoc:  func(string, time.Duration) error { return nil },
			probePub:  func(string, time.Duration) (int, error) { return http.StatusUnauthorized, nil },
			loginctl: func(args ...string) (string, error) {
				return "yes", nil
			},
			mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
				if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
					return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-sub-1","pub_name":"sub-tools","profile":"managed-oauth","url":"https://relay.example/r/pub-sub-1/mcp","publication_state":"VERIFIED","desired_enabled":true,"state_generation":1,"session_live":true,"admission":"READY","admission_reason":"READY"}]}`), nil
				}
				return http.StatusOK, []byte(`{}`), nil
			},
			systemctl: func(args ...string) (string, error) {
				if len(args) > 0 && args[0] == "show" {
					return "loaded", nil
				}
				if len(args) > 0 && args[0] == "is-enabled" {
					return "enabled", nil
				}
				if len(args) > 0 && args[0] == "is-active" {
					return "active", nil
				}
				return "", nil
			},
		}
		os.Exit(cmdHostWithOps([]string{"mcp", "8765", "--name", "sub-tools", "--json"}, ops))
	case "failure-backend":
		seedEnrolledProfileForTest(t, "https://relay.example")
		ops := serviceOps{
			provision: func(config.ServiceRecord, serviceOps) error { return nil },
			probeLoc:  func(string, time.Duration) error { return errors.New("connection refused") },
			loginctl:  func(args ...string) (string, error) { return "yes", nil },
			mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
				return http.StatusOK, []byte(`{"publications":[]}`), nil
			},
			systemctl: func(args ...string) (string, error) {
				if len(args) > 0 && args[0] == "show" {
					return "loaded", nil
				}
				return "inactive", nil
			},
		}
		os.Exit(cmdHostWithOps([]string{"mcp", "8765", "--name", "sub-fail", "--json"}, ops))
	case "failure-unenrolled":
		os.Exit(cmdHostWithOps([]string{"mcp", "8765", "--name", "sub-unauth", "--json"}, serviceOps{}))
	default:
		os.Exit(99)
	}
}

func TestP1HostJSONSubprocessStandaloneOutput(t *testing.T) {
	runSub := func(scenario string) ([]byte, []byte, int) {
		t.Helper()
		home := t.TempDir()
		cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessHostJSON")
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_HOST_JSON=1",
			"HOST_JSON_SCENARIO="+scenario,
			"HOME="+home,
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				t.Fatalf("subprocess failed unexpectedly: %v", err)
			}
		}
		return stdout.Bytes(), stderr.Bytes(), code
	}

	// 1. Success path: stdout MUST be strictly one valid JSON document, zero stray text.
	outOK, errOK, codeOK := runSub("success")
	if codeOK != apperr.ExitOK {
		t.Fatalf("success scenario exit=%d stderr=%s stdout=%s", codeOK, errOK, outOK)
	}
	var resOK HostTransactionResult
	if err := json.Unmarshal(outOK, &resOK); err != nil {
		t.Fatalf("invalid standalone JSON on stdout (success): %v\nstdout:\n%s", err, outOK)
	}
	if !resOK.Configured || !resOK.RunningNow || !resOK.PersistenceConfigured || resOK.RebootRecoveryProven || !resOK.PubliclyServing {
		t.Fatalf("unexpected success HostTransactionResult: %+v", resOK)
	}

	// 2. Backend failure path: non-zero exit AND valid standalone JSON on stdout.
	outFail, _, codeFail := runSub("failure-backend")
	if codeFail == apperr.ExitOK {
		t.Fatalf("expected non-zero exit on backend failure, got 0")
	}
	var resFail HostTransactionResult
	if err := json.Unmarshal(outFail, &resFail); err != nil {
		t.Fatalf("invalid standalone JSON on stdout (failure-backend): %v\nstdout:\n%s", err, outFail)
	}
	if resFail.Error == "" || resFail.PubliclyServing {
		t.Fatalf("expected error and PubliclyServing=false, got %+v", resFail)
	}

	// 3. Unenrolled failure path: ExitAuth AND valid standalone JSON on stdout.
	outUnauth, _, codeUnauth := runSub("failure-unenrolled")
	if codeUnauth != apperr.ExitAuth {
		t.Fatalf("expected ExitAuth (%d), got %d", apperr.ExitAuth, codeUnauth)
	}
	var resUnauth HostTransactionResult
	if err := json.Unmarshal(outUnauth, &resUnauth); err != nil {
		t.Fatalf("invalid standalone JSON on stdout (failure-unenrolled): %v\nstdout:\n%s", err, outUnauth)
	}
	if resUnauth.Error == "" {
		t.Fatalf("expected error field on unenrolled JSON, got %+v", resUnauth)
	}
}

func TestP1HTTPDisableMissingLeaseIDResolution(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")
	seedEnrolledProfileForTest(t, "https://relay.example")

	st, _ := openServicesForProfile("default")
	kp, keyID, _ := loadKeyForProfile("default")

	// 1. Lost local LeaseID, active remote lease exists -> resolves via /v1/agent/leases and revokes it!
	_ = st.Put(config.ServiceRecord{
		Name: "http-lost-id", Type: "http", LocalURL: "http://127.0.0.1:3000",
		Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@http-lost-id.service",
	})
	revokedID := ""
	opsResolve := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/leases" {
				return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-remote-99","label":"http-lost-id","status":"ACTIVE","route_live":true,"url":"https://http-lost-id.t.relay.example"}]}`), nil
			}
			if method == http.MethodPost && path == "/v1/agent/lease/lse-remote-99/revoke" {
				revokedID = "lse-remote-99"
				return http.StatusOK, []byte(`{"status":"revoked"}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		probePub: func(string, time.Duration) (int, error) { return http.StatusServiceUnavailable, nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "inactive", nil
		},
	}
	rec1, _, _ := st.Get("http-lost-id")
	res1 := stopServiceAuthoritatively(st, rec1, kp, keyID, opsResolve)
	if revokedID != "lse-remote-99" || !res1.RemoteDisabled || res1.RemoteDisableStatus != "CONFIRMED" {
		t.Fatalf("expected remote lease lse-remote-99 to be resolved and revoked, got revokedID=%q res=%+v", revokedID, res1)
	}

	// 2. Lost local LeaseID, relay unreachable -> REMOTE_DISABLE_UNCONFIRMED, cmdServiceDisable MUST fail!
	_ = st.Put(config.ServiceRecord{
		Name: "http-unreach", Type: "http", LocalURL: "http://127.0.0.1:3001",
		Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@http-unreach.service",
	})
	opsUnreach := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 0, nil, errors.New("relay offline")
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "inactive", nil
		},
	}
	if code := cmdServiceDisable([]string{"http-unreach"}, opsUnreach); code != apperr.ExitRelayTLS {
		t.Fatalf("expected ExitRelayTLS (%d) when HTTP remote disable is unconfirmed, got %d", apperr.ExitRelayTLS, code)
	}

	// 3. Truly never-published HTTP service (DesiredConfigured, no LeaseID, no PublicURL) -> NEVER_PUBLISHED.
	_ = st.Put(config.ServiceRecord{
		Name: "http-never", Type: "http", LocalURL: "http://127.0.0.1:3002",
		Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredConfigured, SystemdUnit: "ocliv-publisher@http-never.service",
	})
	recNever, _, _ := st.Get("http-never")
	resNever := stopServiceAuthoritatively(st, recNever, kp, keyID, opsUnreach)
	if resNever.RemoteDisableStatus != "NEVER_PUBLISHED" || !resNever.Stopped {
		t.Fatalf("expected NEVER_PUBLISHED and Stopped=true for never-published HTTP service, got %+v", resNever)
	}
}

func TestP1LegacyServiceIdentityMigration(t *testing.T) {
	dir := t.TempDir()
	st := config.OpenServiceStore(dir)
	kp, _ := identity.Generate()
	keyID := string(kp.ID())

	// Write a pre-remediation legacy service record (no Identity field).
	legacy := config.ServiceRecord{
		Name:          "legacy-mcp",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       "default",
		RelayURL:      "https://relay.example",
		DesiredState:  config.DesiredEnabled,
		PublicationID: "pub-legacy-1",
		PublicURL:     "https://relay.example/r/pub-legacy-1/mcp",
		SystemdUnit:   "ocliv-publisher@legacy-mcp.service",
	}
	if err := st.Put(legacy); err != nil {
		t.Fatal(err)
	}

	// 1. Read-only inspectServiceStatus MUST NOT mutate the legacy record on disk.
	beforeBytes, _ := os.ReadFile(filepath.Join(dir, "services.json"))
	_ = inspectServiceStatus(legacy, kp, keyID, serviceOps{
		probeLoc:  func(string, time.Duration) error { return nil },
		probePub:  func(string, time.Duration) (int, error) { return http.StatusUnauthorized, nil },
		systemctl: func(args ...string) (string, error) { return "active", nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-legacy-1","pub_name":"legacy-mcp","profile":"managed-oauth","url":"https://relay.example/r/pub-legacy-1/mcp","publication_state":"VERIFIED","desired_enabled":true,"state_generation":1,"session_live":true,"admission":"READY"}]}`), nil
		},
	})
	afterBytes, _ := os.ReadFile(filepath.Join(dir, "services.json"))
	if !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatal("read-only inspectServiceStatus mutated legacy services.json")
	}

	// 2. Wrong owner key (publication absent from calling key's inventory) -> migration MUST fail closed!
	rec, _, _ := st.Get("legacy-mcp")
	if _, err := migrateLegacyServiceIdentity(st, rec, kp, "wrong-key", "https://relay.example", serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return http.StatusOK, []byte(`{"publications":[]}`), nil
		},
	}); err == nil {
		t.Fatal("expected legacy identity migration to reject unowned publication")
	}

	// 3. Authenticated owner key matches publication -> preserves route ID and URL, persists SchemaVersion=1.
	migrated, err := migrateLegacyServiceIdentity(st, rec, kp, keyID, "https://relay.example", serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-legacy-1","pub_name":"legacy-mcp","profile":"managed-oauth","url":"https://relay.example/r/pub-legacy-1/mcp"}]}`), nil
		},
	})
	if err != nil {
		t.Fatalf("migrateLegacyServiceIdentity failed: %v", err)
	}
	if migrated.Identity == nil || migrated.Identity.SchemaVersion != config.CurrentIdentitySchemaVersion ||
		migrated.Identity.OwnerKeyID != keyID || migrated.Identity.PublicationID != "pub-legacy-1" ||
		migrated.PublicURL != "https://relay.example/r/pub-legacy-1/mcp" {
		t.Fatalf("unexpected migrated identity: %+v", migrated)
	}
}

func TestP1EvidenceBasedHealthLayersAndReconcileEdgeOutage(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	kp, _ := identity.Generate()

	_ = st.Put(config.ServiceRecord{
		Name: "edge-outage-svc", Type: "mcp", LocalURL: "http://127.0.0.1:8765/mcp",
		Profile: "default", RelayURL: "https://relay.example", PublicationID: "pub-edge-1",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@edge.service",
	})
	restarted := false
	ops := serviceOps{
		probeLoc: func(string, time.Duration) error { return nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && (args[0] == "start" || args[0] == "restart") {
				restarted = true
			}
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "active", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 0, nil, errors.New("dial tcp: network unreachable")
		},
	}

	rep, err := reconcileServiceOnce(st, "edge-outage-svc", kp, "k1", ops, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Layers.Process != "active" || rep.Layers.Agent == "connected" || rep.Layers.Edge != "unreachable" {
		t.Fatalf("expected Process=active, Agent!=connected, Edge=unreachable; got %+v", rep.Layers)
	}
	if restarted {
		t.Fatal("reconciler must not restart an active publisher during a relay/edge outage")
	}
	rec, _, _ := st.Get("edge-outage-svc")
	if rec.Reconcile == nil || rec.Reconcile.FailureLayer != "edge" {
		t.Fatalf("expected FailureLayer=edge, got %+v", rec.Reconcile)
	}
}

func TestP2RealSystemdAnalyzeVerifyGeneratedUnits(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze not installed")
	}
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "ocliv-publisher@.service")
	bePath := filepath.Join(dir, "ocliv-backend@.service")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic0600(pubPath, renderPublisherUnitTemplate(exe)); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic0600(bePath, renderBackendUnitTemplate(exe)); err != nil {
		t.Fatal(err)
	}
	// Verify both generated unit templates with real systemd-analyze (non-recursive).
	out, err := exec.Command("systemd-analyze", "verify", "--recursive-errors=no", pubPath, bePath).CombinedOutput()
	if err != nil {
		// Older systemd versions may not support --recursive-errors=no; fall back to standard verify and check for syntax errors.
		out2, err2 := exec.Command("systemd-analyze", "verify", pubPath, bePath).CombinedOutput()
		if err2 != nil && (strings.Contains(string(out2), "Failed to parse") || strings.Contains(string(out2), "Invalid") || strings.Contains(string(out2), "Unknown")) {
			t.Fatalf("systemd-analyze verify reported unit syntax errors:\n%s", out2)
		}
		_ = out
	}
}
