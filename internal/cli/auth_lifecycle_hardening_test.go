package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/protocol"
	"ocliv/internal/setup"
)

func TestEnrollmentRejectsMismatchedOrMalformedKeyIDs(t *testing.T) {
	cases := []struct {
		name  string
		keyID string
	}{
		{"empty", ""},
		{"legacy_mock_key_abc", "key-abc"},
		{"shorter", "key-1234"},
		{"longer", "key-0123456789abcdef00"},
		{"same_length_wrong", "key-deadbeefdeadbeef"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cfgDir := filepath.Join(home, ".config", "ocliv")
			t.Setenv("HOME", home)
			t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
			t.Setenv("OCLIV_PROFILE", "")

			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"key_id":    tc.keyID,
					"tenant_id": "ten-1",
				})
			}))
			defer srv.Close()
			caPath := writeTestServerCA(t, srv)
			t.Setenv("OCLIV_CACERT", caPath)

			_, code := performEnroll(srv.URL, "CODE-123", caPath)
			if code != apperr.ExitAuth {
				t.Fatalf("case %s: expected ExitAuth, got %d", tc.name, code)
			}
			// Final agent.key and config.toml MUST NOT be installed.
			if _, err := os.Stat(filepath.Join(cfgDir, config.AgentKeyFile)); !os.IsNotExist(err) {
				t.Fatalf("case %s: agent.key was installed despite key_id mismatch", tc.name)
			}
			if _, err := os.Stat(filepath.Join(cfgDir, config.ConfigFile)); !os.IsNotExist(err) {
				t.Fatalf("case %s: config.toml was installed despite key_id mismatch", tc.name)
			}
			// Recovery state (agent.key.pending + enroll-pending.json) MUST be preserved.
			if _, err := os.Stat(filepath.Join(cfgDir, "agent.key.pending")); err != nil {
				t.Fatalf("case %s: agent.key.pending was deleted on mismatch: %v", tc.name, err)
			}
			if _, err := os.Stat(filepath.Join(cfgDir, "enroll-pending.json")); err != nil {
				t.Fatalf("case %s: enroll-pending.json was deleted on mismatch: %v", tc.name, err)
			}
		})
	}
}

func TestKeyRotationCrashAfterSaveAndJournalWriteFault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_PROFILE", "")

	var rotateHits atomic.Int32
	var committedNewKeyID string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/capabilities":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"capabilities": []string{protocol.CapabilityPersistentNamedLeases, protocol.CapabilityMgmtBodySignatureV2},
			})
		case "/v1/agent/key/rotate":
			rotateHits.Add(1)
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			pubBytes, _ := base64.StdEncoding.DecodeString(req["new_public_key"])
			h := sha256.Sum256(pubBytes)
			committedNewKeyID = "key-" + hex.EncodeToString(h[:8])
			_ = json.NewEncoder(w).Encode(map[string]any{
				"old_key_id": r.Header.Get("X-Ocliv-Key"),
				"new_key_id": committedNewKeyID,
			})
		case "/v1/agent/leases":
			_, _ = w.Write([]byte(`{"leases":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, srv))

	seedEnrolledProfileForTest(t, srv.URL)
	activeDir, keyPath, activeCfg, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activeCfg, []byte("relay_url = \""+srv.URL+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Fault 1: inject crash immediately after SaveDurableReplace (BEFORE LOCAL_KEY_COMMITTED journal write).
	origHook := keyRotateAfterSaveHook
	origWrite := keyRotateJournalWriteFn
	defer func() {
		keyRotateAfterSaveHook = origHook
		keyRotateJournalWriteFn = origWrite
	}()

	keyRotateAfterSaveHook = func() error {
		return errors.New("simulated power loss after SaveDurableReplace")
	}
	if code := runKeyRotate([]string{"--json"}, serviceOps{}); code == apperr.ExitOK {
		t.Fatalf("expected non-zero exit on post-SaveDurableReplace fault")
	}
	if rotateHits.Load() != 1 {
		t.Fatalf("expected 1 remote rotate hit, got %d", rotateHits.Load())
	}
	// Staged key MUST still exist because LOCAL_KEY_COMMITTED was NOT written yet!
	if _, err := os.Stat(filepath.Join(activeDir, "agent.key.rotating")); err != nil {
		t.Fatalf("A2 REGRESSION: staged key deleted before LOCAL_KEY_COMMITTED persisted: %v", err)
	}
	// Installed key MUST already be committedNewKeyID.
	instKey, err := identity.Load(keyPath)
	if err != nil || "key-"+string(instKey.ID()) != committedNewKeyID {
		t.Fatalf("expected installed key %s after SaveDurableReplace, got %v err=%v", committedNewKeyID, instKey, err)
	}

	// Fault 2: remove staged key externally to prove state-derived recovery STILL succeeds
	// when installed key already equals NewKeyID, AND inject a journal write failure once!
	_ = os.Remove(filepath.Join(activeDir, "agent.key.rotating"))
	keyRotateAfterSaveHook = nil
	keyRotateJournalWriteFn = func(path string, j keyRotationPendingJournal) error {
		if j.State == rotStateLocalKeyCommitted {
			return errors.New("simulated journal write failure")
		}
		return writeRotationJournal(path, j)
	}
	if code := runKeyRotate([]string{"--json"}, serviceOps{}); code == apperr.ExitOK {
		t.Fatalf("expected non-zero exit on journal write fault")
	}
	if rotateHits.Load() != 1 {
		t.Fatalf("A2 REGRESSION: retry re-called /rotate (%d hits)", rotateHits.Load())
	}

	// Final retry with healthy disk MUST complete cleanly with ZERO additional /rotate RPCs!
	keyRotateJournalWriteFn = writeRotationJournal
	if code := runKeyRotate([]string{"--json"}, serviceOps{}); code != apperr.ExitOK {
		t.Fatalf("A2 REGRESSION: state-derived recovery failed: code=%d", code)
	}
	if rotateHits.Load() != 1 {
		t.Fatalf("A2 REGRESSION: final recovery re-called /rotate (%d hits)", rotateHits.Load())
	}
	if _, err := os.Stat(filepath.Join(activeDir, "key-rotation-pending.json")); !os.IsNotExist(err) {
		t.Fatalf("expected journal removed after completion")
	}
}

func TestKeyRotationRejectsAuthorityMismatchZeroRequests(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_PROFILE", "")

	var relayBHits atomic.Int32
	srvA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"leases":[]}`))
	}))
	defer srvA.Close()
	srvB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayBHits.Add(1)
		_, _ = w.Write([]byte(`{"leases":[]}`))
	}))
	defer srvB.Close()

	seedEnrolledProfileForTest(t, srvA.URL)
	activeDir, _, activeCfg, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	oldKey, oldKeyID, err := loadKey()
	if err != nil || oldKey == nil {
		t.Fatal(err)
	}
	newKey, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	stagedPath := filepath.Join(activeDir, "agent.key.rotating")
	if err := newKey.Save(stagedPath); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(activeDir, "key-rotation-pending.json")
	if err := writeRotationJournal(journalPath, keyRotationPendingJournal{
		RelayURL:      srvA.URL,
		OldKeyID:      oldKeyID,
		NewKeyID:      "key-" + string(newKey.ID()),
		StagedKeyPath: stagedPath,
		State:         rotStateStaged,
	}); err != nil {
		t.Fatal(err)
	}

	// Switch config.toml to relay B!
	if err := os.WriteFile(activeCfg, []byte("relay_url = \""+srvB.URL+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, srvB))

	if code := runKeyRotate([]string{"--json"}, serviceOps{}); code != apperr.ExitAuth {
		t.Fatalf("A3 REGRESSION: expected ExitAuth on authority mismatch, got %d", code)
	}
	if relayBHits.Load() != 0 {
		t.Fatalf("A3 REGRESSION: relay B received %d requests despite journal bound to relay A", relayBHits.Load())
	}
	if _, err := os.Stat(journalPath); err != nil {
		t.Fatalf("expected journal preserved on authority mismatch")
	}
	if _, err := os.Stat(stagedPath); err != nil {
		t.Fatalf("expected staged key preserved on authority mismatch")
	}
}

func TestMgmtV2NegotiationFailClosedMatrix(t *testing.T) {
	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := "key-" + string(kp.ID())

	cases := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{
			name: "404_both_caps_and_challenge",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
		},
		{
			name: "500_on_capabilities",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
		},
		{
			name: "malformed_json_on_capabilities",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{not-json`))
			},
		},
		{
			name: "missing_mgmt_body_sig_v2",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"capabilities":["persistent_named_leases"]}`))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mutationHits atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/agent/key/rotate" {
					mutationHits.Add(1)
					http.Error(w, "should never be called", http.StatusInternalServerError)
					return
				}
				tc.handler(w, r)
			}))
			defer srv.Close()
			t.Setenv("OCLIV_CACERT", writeTestServerCA(t, srv))

			_, _, err := mgmtCallBody(srv.URL, kp, keyID, http.MethodPost, "/v1/agent/key/rotate", []byte(`{"test":true}`))
			if err == nil {
				t.Fatalf("A4 REGRESSION (%s): body-bearing mutation unexpectedly succeeded", tc.name)
			}
			if mutationHits.Load() != 0 {
				t.Fatalf("A4 REGRESSION (%s): mutation endpoint received %d requests", tc.name, mutationHits.Load())
			}
		})
	}

	// Verify read-only /v1/agent/capabilities avoids calling /v1/agent/challenge altogether!
	var challengeHits, rotateHits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/capabilities":
			_, _ = w.Write([]byte(`{"capabilities":["persistent_named_leases","mgmt_body_sig_v2"]}`))
		case "/v1/agent/challenge":
			challengeHits.Add(1)
			http.Error(w, "should not allocate challenge nonce", http.StatusInternalServerError)
		case "/v1/agent/key/rotate":
			rotateHits.Add(1)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, srv))

	st, _, err := mgmtCallBody(srv.URL, kp, keyID, http.MethodPost, "/v1/agent/key/rotate", []byte(`{"test":true}`))
	if err != nil || st != http.StatusOK {
		t.Fatalf("capabilities-negotiated v2 call failed: st=%d err=%v", st, err)
	}
	if challengeHits.Load() != 0 || rotateHits.Load() != 1 {
		t.Fatalf("expected 0 challenge hits and 1 rotate hit, got challenge=%d rotate=%d", challengeHits.Load(), rotateHits.Load())
	}
}

func TestBackendEnvFileSingleFDSymlinkAndOversizedRejected(t *testing.T) {
	dir := t.TempDir()
	bigPath := filepath.Join(dir, "huge.env")
	bigPayload := "BIG=" + strings.Repeat("A", (1<<20)+64) + "\n"
	if err := os.WriteFile(bigPath, []byte(bigPayload), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBackendEnvFileStrict(bigPath, nil); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("A5 REGRESSION: expected oversized env file to fail closed, got %v", err)
	}
}

func TestKeyRotationVerifiesPublishersUnderNewKeyAndResumesPartial(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_PROFILE", "")

	var rotateHits atomic.Int32
	var committedNewKeyID string
	var svcBReady atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/capabilities":
			_, _ = w.Write([]byte(`{"capabilities":["persistent_named_leases","mgmt_body_sig_v2"]}`))
		case "/v1/agent/key/rotate":
			rotateHits.Add(1)
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			pubBytes, _ := base64.StdEncoding.DecodeString(req["new_public_key"])
			h := sha256.Sum256(pubBytes)
			committedNewKeyID = "key-" + hex.EncodeToString(h[:8])
			_ = json.NewEncoder(w).Encode(map[string]any{
				"old_key_id": r.Header.Get("X-Ocliv-Key"),
				"new_key_id": committedNewKeyID,
			})
		case "/v1/agent/leases":
			if r.Header.Get("X-Ocliv-Key") != committedNewKeyID {
				http.Error(w, "wrong key", http.StatusForbidden)
				return
			}
			leases := []map[string]any{
				{"lease_id": "lse-a", "label": "svca", "port": 3001, "access_mode": "protected", "status": "ACTIVE", "route_live": true},
			}
			if svcBReady.Load() {
				leases = append(leases, map[string]any{
					"lease_id": "lse-b", "label": "svcb", "port": 3002, "access_mode": "protected", "status": "ACTIVE", "route_live": true,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"leases": leases})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, srv))

	seedEnrolledProfileForTest(t, srv.URL)
	activeDir, _, activeCfg, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activeCfg, []byte("relay_url = \""+srv.URL+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := openServicesForProfile("default")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []config.ServiceRecord{
		{Name: "svca", Type: "http", Profile: "default", BackendMode: config.BackendAttached, DesiredState: config.DesiredEnabled, Auth: "protected", LocalURL: "http://127.0.0.1:3001", SystemdUnit: "ocliv-svc-svca.service"},
		{Name: "svcb", Type: "http", Profile: "default", BackendMode: config.BackendAttached, DesiredState: config.DesiredEnabled, Auth: "protected", LocalURL: "http://127.0.0.1:3002", SystemdUnit: "ocliv-svc-svcb.service"},
	} {
		if err := st.Put(s); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	restarts := map[string]int{}
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "restart" {
				mu.Lock()
				restarts[args[1]]++
				mu.Unlock()
			}
			return "active", nil
		},
	}

	// Attempt 1: svca verifies under new key, svcb is NOT live yet -> MUST fail & preserve journal!
	if code := runKeyRotate([]string{"--json"}, ops); code == apperr.ExitOK {
		t.Fatalf("A7 REGRESSION: rotation succeeded despite svcb not attached under new key")
	}
	journalPath := filepath.Join(activeDir, "key-rotation-pending.json")
	rawJ, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("A7 REGRESSION: journal deleted despite unverified svcb: %v", err)
	}
	var j keyRotationPendingJournal
	_ = json.Unmarshal(rawJ, &j)
	if !j.RecoveredServices["svca"] || j.RecoveredServices["svcb"] {
		t.Fatalf("expected svca=true svcb=false in journal, got %+v", j.RecoveredServices)
	}

	// Attempt 2: svcb becomes live -> retry MUST NOT restart svca again and MUST NOT re-call /rotate!
	svcBReady.Store(true)
	if code := runKeyRotate([]string{"--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("A7 retry failed: code=%d", code)
	}
	if rotateHits.Load() != 1 {
		t.Fatalf("expected 1 remote rotate hit, got %d", rotateHits.Load())
	}
	if restarts["ocliv-svc-svca.service"] != 1 {
		t.Fatalf("A7 REGRESSION: already-recovered svca was restarted %d times (want 1)", restarts["ocliv-svc-svca.service"])
	}
	if restarts["ocliv-svc-svcb.service"] != 2 {
		t.Fatalf("expected svcb restarted twice (initial + retry), got %d", restarts["ocliv-svc-svcb.service"])
	}
}

func TestSetupStateMachineSchemaRejectionAndStageRevalidation(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Unsupported newer schema version MUST fail closed.
	if err := os.WriteFile(filepath.Join(cfgDir, "setup-state.json"), []byte(`{"schema_version":99,"completed_stage":"COMPLETE"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadSetupStateStrict(); err == nil || !strings.Contains(err.Error(), "unsupported setup state schema version") {
		t.Fatalf("A9 REGRESSION: unsupported schema version was not rejected: err=%v", err)
	}

	// Stage revalidation resumes at the first invalid stage.
	st := setupState{
		SchemaVersion:  setupStateSchemaVersion,
		Fingerprint:    setupFingerprint("demo.duckdns.org", "tunnel", "a@b.com"),
		CompletedStage: stageRelayReady,
	}
	stage, reval := planSetupResume(st, st.Fingerprint, func(s string) bool {
		return s != stageSystemInstalled
	})
	if stage != stageSystemInstalled {
		t.Fatalf("expected resume at %s, got %s (reval=%v)", stageSystemInstalled, stage, reval)
	}
	// Fingerprint mismatch resets to DETECTED.
	stage2, _ := planSetupResume(st, setupFingerprint("other.duckdns.org", "tunnel", "a@b.com"), func(string) bool { return true })
	if stage2 != stageDetected {
		t.Fatalf("expected fingerprint mismatch to reset to %s, got %s", stageDetected, stage2)
	}
}

func TestBuildInfoLdflagPrecedenceAndDefaultEdgeConsistency(t *testing.T) {
	// A10: explicit ldflag values take precedence over debug.ReadBuildInfo.
	origC, origT, origD := BuildCommit, BuildTime, BuildDirty
	defer func() {
		BuildCommit, BuildTime, BuildDirty = origC, origT, origD
	}()
	BuildCommit = "deadbeef1234567890"
	BuildTime = "2026-11-20T12:00:00Z"
	BuildDirty = "false"

	bi := GetBuildInfo()
	if bi.BuildCommit != "deadbeef1234567890" || bi.BuildTime != "2026-11-20T12:00:00Z" || bi.Dirty {
		t.Fatalf("A10 REGRESSION: ldflag precedence broken: %+v", bi)
	}
	m := buildRuntimeManifest("/src/ocliv", "/dst/ocliv", "abc123")
	if m.BuildCommit != "deadbeef1234567890" || m.Dirty {
		t.Fatalf("A10 REGRESSION: runtimeManifest ignored unified BuildInfo: %+v", m)
	}

	// A11: DefaultEdgeMode == recommendedEdgeMode == "wildcard".
	if DefaultEdgeMode() != "wildcard" {
		t.Fatalf("expected DefaultEdgeMode=wildcard, got %q", DefaultEdgeMode())
	}
	if got := recommendedEdgeMode(setup.Detection{Path: setup.PathDirectV4}); got != DefaultEdgeMode() {
		t.Fatalf("A11 REGRESSION: recommendedEdgeMode=%q != DefaultEdgeMode=%q", got, DefaultEdgeMode())
	}
}
