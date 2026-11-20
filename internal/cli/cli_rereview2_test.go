package cli

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
)

func TestP0FirstStartHTTPLeaseDiscoveryAndNegativeCases(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")
	t.Setenv("USER", "testuser")

	seedEnrolledProfileForTest(t, "https://relay.example")

	// Mixed-case service name "MyApp" -> relay stores lowercased label "myapp".
	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		probeLoc:  func(string, time.Duration) error { return nil },
		probeEdge: func(string, time.Duration) (int, error) { return http.StatusOK, nil },
		loginctl:  func(args ...string) (string, error) { return "yes", nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/leases" {
				return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-first-1","label":"myapp","port":3000,"access_mode":"protected","status":"ACTIVE","generation":1,"persistent":true,"url":"https://myapp.t.relay.example","route_live":true,"route_available":true}]}`), nil
			}
			if method == http.MethodGet && path == "/v1/agent/lease/lse-first-1/status" {
				return http.StatusOK, []byte(`{"lease_id":"lse-first-1","port":3000,"access_mode":"protected","status":"ACTIVE","generation":1,"url":"https://myapp.t.relay.example","route_live":true,"route_available":true}`), nil
			}
			return http.StatusNotFound, nil, nil
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

	// Plain `ocliv host 3000 --name MyApp --json` defaults to protected HTTP,
	// starts with LeaseID == "", discovers lse-first-1 via GET /v1/agent/leases,
	// verifies edge probe, reaches SERVING, and persists LeaseID!
	if code := cmdHostWithOps([]string{"3000", "--name", "MyApp", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("first-start HTTP host failed: code=%d", code)
	}
	st, _ := openServicesForProfile("default")
	rec, ok, _ := st.Get("MyApp")
	if !ok || rec.Type != "http" || rec.Auth != "protected" || rec.LeaseID != "lse-first-1" || rec.PublicURL != "https://myapp.t.relay.example" {
		t.Fatalf("expected discovered LeaseID persisted on ServiceRecord, got %+v", rec)
	}

	// Negative cases for resolveHostedHTTPLease:
	kp, keyID, _ := loadKeyForProfile("default")
	blankRec := rec
	blankRec.LeaseID = ""

	// 1. Wrong port must not match.
	repWrongPort := inspectServiceStatus(blankRec, kp, keyID, serviceOps{
		probeLoc:  func(string, time.Duration) error { return nil },
		systemctl: ops.systemctl,
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-wrong-port","label":"myapp","port":9999,"access_mode":"protected","status":"ACTIVE","route_live":true,"route_available":true}]}`), nil
		},
	})
	if repWrongPort.State == ServiceStateServing {
		t.Fatalf("wrong port lease must not reach SERVING: %+v", repWrongPort)
	}

	// 2. Wrong access_mode must not match.
	repWrongMode := inspectServiceStatus(blankRec, kp, keyID, serviceOps{
		probeLoc:  func(string, time.Duration) error { return nil },
		systemctl: ops.systemctl,
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-wrong-mode","label":"myapp","port":3000,"access_mode":"public","status":"ACTIVE","route_live":true,"route_available":true}]}`), nil
		},
	})
	if repWrongMode.State == ServiceStateServing {
		t.Fatalf("wrong access_mode lease must not reach SERVING: %+v", repWrongMode)
	}

	// 3. Ambiguous leases (>1 eligible) must fail closed.
	repAmbig := inspectServiceStatus(blankRec, kp, keyID, serviceOps{
		probeLoc:  func(string, time.Duration) error { return nil },
		systemctl: ops.systemctl,
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-a","label":"myapp","port":3000,"access_mode":"protected","status":"ACTIVE","route_live":true,"route_available":true},{"lease_id":"lse-b","label":"myapp","port":3000,"access_mode":"protected","status":"ACTIVE","route_live":true,"route_available":true}]}`), nil
		},
	})
	if repAmbig.State == ServiceStateServing || !strings.Contains(repAmbig.IngressDetail, "ambiguous") {
		t.Fatalf("ambiguous leases must fail closed: %+v", repAmbig)
	}
}

func TestP0MutableTargetUpdateRebindsRunningPublisher(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")
	t.Setenv("USER", "testuser")

	seedEnrolledProfileForTest(t, "https://relay.example")

	currentRelayPort := 3000
	unitActive := false
	restartedUnit := false
	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		probeLoc:  func(string, time.Duration) error { return nil },
		probeEdge: func(string, time.Duration) (int, error) { return http.StatusOK, nil },
		loginctl:  func(args ...string) (string, error) { return "yes", nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/leases" {
				return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-rebind-1","label":"web","port":3000,"access_mode":"protected","status":"ACTIVE","generation":1,"url":"https://web.t.relay.example","route_live":true,"route_available":true}]}`), nil
			}
			if method == http.MethodGet && path == "/v1/agent/lease/lse-rebind-1/status" {
				if currentRelayPort == 4000 {
					return http.StatusOK, []byte(`{"lease_id":"lse-rebind-1","port":4000,"access_mode":"protected","status":"ACTIVE","generation":2,"url":"https://web.t.relay.example","route_live":true,"route_available":true}`), nil
				}
				return http.StatusOK, []byte(`{"lease_id":"lse-rebind-1","port":3000,"access_mode":"protected","status":"ACTIVE","generation":1,"url":"https://web.t.relay.example","route_live":true,"route_available":true}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "start" && strings.HasPrefix(args[1], "ocliv-publisher@") {
				unitActive = true
				return "", nil
			}
			if len(args) >= 2 && args[0] == "restart" && strings.HasPrefix(args[1], "ocliv-publisher@") {
				restartedUnit = true
				unitActive = true
				currentRelayPort = 4000
				return "", nil
			}
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			if len(args) > 0 && args[0] == "is-enabled" {
				return "enabled", nil
			}
			if len(args) > 0 && args[0] == "is-active" {
				if unitActive {
					return "active", nil
				}
				return "inactive", nil
			}
			return "", nil
		},
	}

	// 1. Initial host on port 3000.
	if code := cmdHostWithOps([]string{"3000", "--name", "web", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("initial host failed: code=%d", code)
	}
	st, _ := openServicesForProfile("default")
	before, _, _ := st.Get("web")
	if before.ConfigGeneration != 1 || before.AppliedConfigGeneration != 1 {
		t.Fatalf("expected ConfigGen=1 Applied=1, got %+v", before)
	}

	// 2. Re-host same name on new port 4000 -> MUST bump ConfigGeneration, restart publisher,
	//    rebind relay to port 4000, and preserve ServiceID & PublicURL!
	if code := cmdHostWithOps([]string{"4000", "--name", "web", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("port-update host failed: code=%d", code)
	}
	if !restartedUnit {
		t.Fatal("expected controlled systemctl restart when target port changed on an active unit")
	}
	after, _, _ := st.Get("web")
	if after.ConfigGeneration != 2 || after.AppliedConfigGeneration != 2 {
		t.Fatalf("expected ConfigGen=2 Applied=2 after rebind, got %+v", after)
	}
	if after.Identity.ServiceID != before.Identity.ServiceID || after.PublicURL != before.PublicURL || after.LeaseID != before.LeaseID {
		t.Fatalf("identity changed on target port update: before=%+v after=%+v", before, after)
	}
}

func TestP1NonDestructiveServiceRestart(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	seedEnrolledProfileForTest(t, "https://relay.example")
	st, _ := openServicesForProfile("default")
	_, keyID, _ := loadKeyForProfile("default")
	svcID, _ := config.NewServiceID()
	_ = st.Put(config.ServiceRecord{
		Name: "app-restart", Type: "http", LocalURL: "http://127.0.0.1:3000",
		Auth: "protected", Profile: "default", RelayURL: "https://relay.example",
		LeaseID: "lse-keep-1", PublicURL: "https://app-restart.t.relay.example",
		DesiredState: config.DesiredEnabled, ConfigGeneration: 1, AppliedConfigGeneration: 1,
		SystemdUnit: "ocliv-publisher@app-restart.service",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     svcID,
			Name:          "app-restart",
			OwnerKeyID:    keyID,
			RelayID:       "https://relay.example",
		},
	})

	revokedOrDisabled := false
	restarted := false
	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		probeLoc:  func(string, time.Duration) error { return nil },
		probeEdge: func(string, time.Duration) (int, error) { return http.StatusOK, nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if strings.HasSuffix(path, "/revoke") || strings.HasSuffix(path, "/disable") {
				revokedOrDisabled = true
			}
			if method == http.MethodGet && path == "/v1/agent/lease/lse-keep-1/status" {
				return http.StatusOK, []byte(`{"lease_id":"lse-keep-1","port":3000,"access_mode":"protected","status":"ACTIVE","generation":2,"url":"https://app-restart.t.relay.example","route_live":true,"route_available":true}`), nil
			}
			return http.StatusOK, []byte(`{}`), nil
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "restart" {
				restarted = true
			}
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "active", nil
		},
	}

	if code := cmdServiceRestart([]string{"app-restart"}, ops); code != apperr.ExitOK {
		t.Fatalf("cmdServiceRestart failed: code=%d", code)
	}
	if revokedOrDisabled {
		t.Fatal("non-destructive restart must NEVER call revoke or disable")
	}
	if !restarted {
		t.Fatal("expected systemctl restart to be called")
	}
	after, _, _ := st.Get("app-restart")
	if after.DesiredState != config.DesiredEnabled || after.LeaseID != "lse-keep-1" {
		t.Fatalf("restart mutated desired state or lease: %+v", after)
	}
}

func TestP1HTTPRemoveMissingLeaseIDAndWrongKeyProtection(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	kpB, _ := identity.Generate()
	keyB := string(kpB.ID())
	svcID, _ := config.NewServiceID()

	// 1. Service owned by key-A, local state lost LeaseID, profile now holds key-B
	//    whose relay inventory is legitimately empty -> MUST NOT report remote disable confirmed!
	recOwnedByA := config.ServiceRecord{
		Name: "owned-by-a", Type: "http", LocalURL: "http://127.0.0.1:3000",
		Auth: "protected", Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@owned-by-a.service",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     svcID,
			Name:          "owned-by-a",
			OwnerKeyID:    "key-A",
			RelayID:       "https://relay.example",
		},
	}
	_ = st.Put(recOwnedByA)
	emptyInvOps := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/leases" {
				return http.StatusOK, []byte(`{"leases":[]}`), nil
			}
			return http.StatusOK, []byte(`{}`), nil
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "is-enabled" {
				return "disabled", nil
			}
			return "inactive", nil
		},
	}
	rec1, _, _ := st.Get("owned-by-a")
	stopRes := stopServiceAuthoritatively(st, rec1, kpB, keyB, emptyInvOps)
	if stopRes.RemoteDisabled || stopRes.RemoteDisableStatus == "CONFIRMED" {
		t.Fatalf("wrong key with empty inventory must NEVER report remote disable confirmed: %+v", stopRes)
	}
	rec1, _, _ = st.Get("owned-by-a")
	if _, err := removeServiceAuthoritatively(st, rec1, kpB, keyB, emptyInvOps); err == nil {
		t.Fatal("wrong key must not be allowed to remove service owned by key-A")
	}

	// 2. Same owner key B, missing local LeaseID, active remote lease exists -> remove resolves & revokes!
	svcID2, _ := config.NewServiceID()
	recOwnedByB := config.ServiceRecord{
		Name: "owned-by-b", Type: "http", LocalURL: "http://127.0.0.1:3001",
		Auth: "protected", Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@owned-by-b.service",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     svcID2,
			Name:          "owned-by-b",
			OwnerKeyID:    keyB,
			RelayID:       "https://relay.example",
		},
	}
	_ = st.Put(recOwnedByB)
	revoked := ""
	opsB := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/leases" {
				return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-b-77","label":"owned-by-b","port":3001,"access_mode":"protected","status":"ACTIVE","route_live":true}]}`), nil
			}
			if method == http.MethodPost && path == "/v1/agent/lease/lse-b-77/revoke" {
				revoked = "lse-b-77"
				return http.StatusOK, []byte(`{"status":"revoked"}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		systemctl: emptyInvOps.systemctl,
	}
	rec2, _, _ := st.Get("owned-by-b")
	if _, err := removeServiceAuthoritatively(st, rec2, kpB, keyB, opsB); err != nil {
		t.Fatalf("expected authoritative HTTP remove to resolve and revoke lse-b-77, got err=%v", err)
	}
	if revoked != "lse-b-77" {
		t.Fatalf("expected lse-b-77 to be revoked before local deletion, got %q", revoked)
	}
	if _, ok, _ := st.Get("owned-by-b"); ok {
		t.Fatal("expected local service record deleted after confirmed remote revocation")
	}
}

func TestP1IdentityBindingInvariantsAndCentralizedValidation(t *testing.T) {
	// 128-bit ServiceID: "svc-" + 32 hex chars = 36 chars.
	id, err := config.NewServiceID()
	if err != nil || len(id) != 36 || !strings.HasPrefix(id, "svc-") {
		t.Fatalf("expected 128-bit svc-<32hex>, got %q err=%v", id, err)
	}

	// Incomplete current-schema identity (OwnerKeyID == "") must be detected by identityNeedsBinding.
	recIncomplete := config.ServiceRecord{
		Name: "inc",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     id,
			Name:          "inc",
			OwnerKeyID:    "",
			RelayID:       "https://relay.example",
		},
	}
	if !identityNeedsBinding(recIncomplete) {
		t.Fatal("expected identityNeedsBinding=true when OwnerKeyID is empty")
	}

	// Future schema version must be rejected explicitly.
	recFuture := config.ServiceRecord{
		Name: "fut",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion + 1,
			ServiceID:     id,
			Name:          "fut",
			OwnerKeyID:    "k1",
			RelayID:       "https://relay.example",
		},
	}
	if err := validateIdentitySchemaVersion(recFuture); err == nil {
		t.Fatal("expected future identity schema version to be rejected")
	}

	// Centralized validation must reject invalid `ocliv host` combinations leaving zero ServiceRecord.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))
	t.Setenv("OCLIV_PROFILE", "")
	seedEnrolledProfileForTest(t, "https://relay.example")

	badCases := [][]string{
		{"8765", "--type", "http", "--auth", "ocliv-managed", "--name", "bad1"},
		{"--stdio", "--type", "http", "--name", "bad2", "--", "echo", "hi"},
		{"--stdio", "--auth", "upstream-oauth", "--name", "bad3", "--", "echo", "hi"},
	}
	for _, argv := range badCases {
		if code := cmdHostWithOps(argv, serviceOps{}); code != apperr.ExitCLIValidation {
			t.Fatalf("expected ExitCLIValidation for %v, got %d", argv, code)
		}
	}
	st, _ := openServicesForProfile("default")
	list, _ := st.List()
	if len(list) != 0 {
		t.Fatalf("invalid host requests must leave zero service records, got %d", len(list))
	}
}

func TestP2HTTPEdgeProbeAndManagedExecutableAndSetupState(t *testing.T) {
	kp, _ := identity.Generate()
	rec := config.ServiceRecord{
		Name: "edge-http", Type: "http", LocalURL: "http://127.0.0.1:3000",
		Auth: "protected", Profile: "default", RelayURL: "https://relay.example",
		LeaseID: "lse-e1", PublicURL: "https://edge-http.t.relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@edge-http.service",
	}
	baseOps := serviceOps{
		probeLoc: func(string, time.Duration) error { return nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "active", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return http.StatusOK, []byte(`{"lease_id":"lse-e1","port":3000,"access_mode":"protected","status":"ACTIVE","generation":1,"url":"https://edge-http.t.relay.example","route_live":true,"route_available":true}`), nil
		},
	}

	// 1. Without probeEdge -> RELAY_READY, Layers.Edge remains "unknown" and PublicTransport=false.
	repRelayOnly := inspectServiceStatus(rec, kp, "k1", baseOps)
	if repRelayOnly.VerificationLevel != "RELAY_READY" || repRelayOnly.Layers.Edge != "unknown" || repRelayOnly.PublicTransport {
		t.Fatalf("relay-only HTTP check must not claim edge reachable: %+v", repRelayOnly)
	}

	// 2. With probeEdge TLS error -> Layers.Edge="tls_error", State=OFFLINE.
	tlsOps := baseOps
	tlsOps.probeEdge = func(string, time.Duration) (int, error) {
		return 0, errors.New("x509: certificate signed by unknown authority")
	}
	repTLS := inspectServiceStatus(rec, kp, "k1", tlsOps)
	if repTLS.Layers.Edge != "tls_error" || repTLS.State != ServiceStateOffline {
		t.Fatalf("expected tls_error/OFFLINE, got %+v", repTLS)
	}

	// 3. With probeEdge 200 -> EDGE_READY, Layers.Edge="reachable", PublicTransport=true.
	edgeOK := baseOps
	edgeOK.probeEdge = func(string, time.Duration) (int, error) { return http.StatusOK, nil }
	repEdge := inspectServiceStatus(rec, kp, "k1", edgeOK)
	if repEdge.VerificationLevel != "EDGE_READY" || repEdge.Layers.Edge != "reachable" || !repEdge.PublicTransport {
		t.Fatalf("expected EDGE_READY/reachable/PublicTransport=true, got %+v", repEdge)
	}

	// 4. Managed executable copy survives transient source binary removal & extractExecStartBinary matches it.
	tmpDir := t.TempDir()
	srcBin := filepath.Join(tmpDir, "transient-ocliv")
	dstBin := filepath.Join(tmpDir, "managed", "ocliv")
	if err := os.WriteFile(srcBin, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installManagedExecutable(srcBin, dstBin); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(srcBin)
	unitFile := filepath.Join(tmpDir, "ocliv-publisher@.service")
	if err := writeAtomic0600(unitFile, renderPublisherUnitTemplate(dstBin)); err != nil {
		t.Fatal(err)
	}
	gotBin := extractExecStartBinary(unitFile)
	if gotBin != dstBin {
		t.Fatalf("extractExecStartBinary=%q want %q", gotBin, dstBin)
	}
	if st, err := os.Stat(gotBin); err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("managed executable not runnable after transient source removed: %v", err)
	}

	// 5. Durable non-secret setup state round-trip.
	t.Setenv("HOME", tmpDir)
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(tmpDir, ".config", "ocliv"))
	wantSetup := setupState{
		DetectedPath:   "nat-ipv4-needs-forward",
		Hostname:       "lab.dynv6.net",
		EdgeMode:       "single-host",
		ACMEEmail:      "ops@example.com",
		CompletedStage: "detected",
		Blocker:        "port_443_forward",
	}
	if err := saveSetupState(wantSetup); err != nil {
		t.Fatal(err)
	}
	gotSetup, ok := loadSetupState()
	if !ok || gotSetup.Hostname != wantSetup.Hostname || gotSetup.EdgeMode != wantSetup.EdgeMode || gotSetup.CompletedStage != wantSetup.CompletedStage {
		t.Fatalf("setupState round-trip mismatch: %+v", gotSetup)
	}
}
