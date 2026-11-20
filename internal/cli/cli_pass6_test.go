package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/protocol"
)

func writeTestServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	_ = x509.Certificate{}
	return caPath
}

func TestPass6P0_1RollingUpgradeMgmtSignatureMatrix(t *testing.T) {
	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := "key-" + string(kp.ID())

	// 1) Old relay: challenge omits mgmt_body_sig_v2; rejects v2 header.
	var oldMutationHits atomic.Int32
	oldSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"nonce":        "n1",
				"capabilities": []string{},
			})
		case "/v1/agent/leases":
			if r.Header.Get("X-Ocliv-Sig-Version") != "" {
				http.Error(w, "old relay does not understand v2", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"leases":[]}`))
		case "/v1/agent/key/rotate":
			oldMutationHits.Add(1)
			http.Error(w, "should not be reached", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer oldSrv.Close()
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, oldSrv))

	// Bodyless call against old relay MUST succeed using v1.
	st, _, err := mgmtCall(oldSrv.URL, kp, keyID, http.MethodGet, "/v1/agent/leases")
	if err != nil || st != http.StatusOK {
		t.Fatalf("P0-1 REGRESSION: bodyless call to old relay failed: status=%d err=%v", st, err)
	}
	// Body-bearing mutation against old relay MUST fail closed locally BEFORE sending request.
	_, _, err = mgmtCallBody(oldSrv.URL, kp, keyID, http.MethodPost, "/v1/agent/key/rotate", []byte(`{"new_key_id":"key-x"}`))
	if err == nil {
		t.Fatalf("P0-1 REGRESSION: body-bearing mutation against old relay unexpectedly succeeded")
	}
	if oldMutationHits.Load() != 0 {
		t.Fatalf("P0-1 REGRESSION: body-bearing mutation was sent to old relay (%d hits) instead of failing closed locally", oldMutationHits.Load())
	}

	// 2) New relay: challenge advertises mgmt_body_sig_v2; requires v2 on body-bearing mutation.
	var sawV2OnBody atomic.Bool
	var sawV1OnBodyless atomic.Bool
	newSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"nonce":        "n2",
				"capabilities": []string{protocol.CapabilityPersistentNamedLeases, protocol.CapabilityMgmtBodySignatureV2},
			})
		case "/v1/agent/leases":
			if r.Header.Get("X-Ocliv-Sig-Version") == "" {
				sawV1OnBodyless.Store(true)
			}
			_, _ = w.Write([]byte(`{"leases":[]}`))
		case "/v1/agent/key/rotate":
			if r.Header.Get("X-Ocliv-Sig-Version") != "2" || r.Header.Get("X-Ocliv-Body-SHA256") == "" {
				http.Error(w, "missing v2 body sig", http.StatusUnauthorized)
				return
			}
			sawV2OnBody.Store(true)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer newSrv.Close()
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, newSrv))

	if st, _, err := mgmtCall(newSrv.URL, kp, keyID, http.MethodGet, "/v1/agent/leases"); err != nil || st != http.StatusOK {
		t.Fatalf("bodyless call to new relay failed: status=%d err=%v", st, err)
	}
	if st, _, err := mgmtCallBody(newSrv.URL, kp, keyID, http.MethodPost, "/v1/agent/key/rotate", []byte(`{"new_key_id":"key-y"}`)); err != nil || st != http.StatusOK {
		t.Fatalf("body-bearing v2 call to new relay failed: status=%d err=%v", st, err)
	}
	if !sawV1OnBodyless.Load() || !sawV2OnBody.Load() {
		t.Fatalf("expected v1 on bodyless (%v) and v2 on body (%v)", sawV1OnBodyless.Load(), sawV2OnBody.Load())
	}
}

func TestPass6P0_2IdentityNoFollowAndExclusiveSave(t *testing.T) {
	dir := t.TempDir()
	realKey := filepath.Join(dir, "real.key")
	kp1, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := kp1.Save(realKey); err != nil {
		t.Fatalf("Save new key: %v", err)
	}
	// Second Save to existing path MUST fail via O_EXCL.
	if err := kp1.Save(realKey); err == nil {
		t.Fatalf("P0-2 REGRESSION: identity.Save overwrote existing key instead of failing O_EXCL")
	}
	// Symlink to valid 0600 key MUST be rejected by identity.Load (O_NOFOLLOW).
	linkKey := filepath.Join(dir, "link.key")
	if err := os.Symlink(realKey, linkKey); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Load(linkKey); err == nil {
		t.Fatalf("P0-2 REGRESSION: identity.Load followed symlink %s", linkKey)
	}
	// SaveDurableReplace atomically replaces existing key with 0600 permissions.
	kp2, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := kp2.SaveDurableReplace(realKey); err != nil {
		t.Fatalf("SaveDurableReplace: %v", err)
	}
	loaded, err := identity.Load(realKey)
	if err != nil {
		t.Fatalf("Load after SaveDurableReplace: %v", err)
	}
	if loaded.ID() != kp2.ID() {
		t.Fatalf("expected replaced key %s, got %s", kp2.ID(), loaded.ID())
	}
}

func TestPass6P0_3EnrollmentPostRenameCrashRecovery(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := "key-" + string(kp.ID())
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(cfgDir, config.AgentKeyFile)
	if err := kp.Save(keyPath); err != nil {
		t.Fatal(err)
	}

	// Fake relay admits the already-renamed key on /v1/agent/leases.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agent/leases" && r.Header.Get("X-Ocliv-Key") == keyID {
			_, _ = w.Write([]byte(`{"leases":[]}`))
			return
		}
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusUnauthorized)
	}))
	defer srv.Close()
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, srv))

	// Write enroll-pending.json simulating crash AFTER agent.key rename, BEFORE config.toml write.
	journalPath := filepath.Join(cfgDir, "enroll-pending.json")
	jBytes, _ := json.Marshal(enrollPendingJournal{
		RelayURL: srv.URL,
		KeyID:    keyID,
	})
	if err := os.WriteFile(journalPath, jBytes, 0600); err != nil {
		t.Fatal(err)
	}

	gotID, code := performEnroll(srv.URL, "unused-code", "")
	if code != apperr.ExitOK || gotID != keyID {
		t.Fatalf("P0-3 REGRESSION: post-rename crash recovery failed: code=%d gotID=%q want=%q", code, gotID, keyID)
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("expected enroll-pending.json removed after recovery")
	}
	cfgMap, err := config.LoadAgentFile(filepath.Join(cfgDir, config.ConfigFile))
	if err != nil || cfgMap["relay_url"] != srv.URL {
		t.Fatalf("expected config.toml repaired with relay_url=%q, got %+v err=%v", srv.URL, cfgMap, err)
	}
}

func TestPass6P0_4KeyRotationResumesFromMetadataReboundWithoutReCallingRotate(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	var rotateHits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"nonce":        "n-rot",
				"capabilities": []string{protocol.CapabilityPersistentNamedLeases, protocol.CapabilityMgmtBodySignatureV2},
			})
		case "/v1/agent/key/rotate":
			rotateHits.Add(1)
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			pubBytes, _ := base64.StdEncoding.DecodeString(req["new_public_key"])
			h := sha256.Sum256(pubBytes)
			newKeyID := "key-" + hex.EncodeToString(h[:8])
			_ = json.NewEncoder(w).Encode(map[string]any{
				"old_key_id":           r.Header.Get("X-Ocliv-Key"),
				"new_key_id":           newKeyID,
				"leases_transferred":   1,
				"sessions_evicted":     1,
				"publications_updated": 0,
			})
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
	if err := st.Put(config.ServiceRecord{
		Name:         "rotapp",
		Type:         "http",
		Profile:      "default",
		BackendMode:  config.BackendAttached,
		DesiredState: config.DesiredEnabled,
		Auth:         "protected",
		LocalURL:     "http://127.0.0.1:3000",
		SystemdUnit:  "ocliv-svc-rotapp.service",
	}); err != nil {
		t.Fatal(err)
	}

	// Attempt 1: remote rotate succeeds, local key + service metadata succeed, systemctl restart FAILS.
	failOps := serviceOps{
		systemctl: func(args ...string) (string, error) {
			return "", errors.New("simulated systemd restart failure")
		},
	}
	if code := runKeyRotate([]string{"--json"}, failOps); code == apperr.ExitOK {
		t.Fatalf("P0-4 REGRESSION: runKeyRotate returned ExitOK despite publisher restart failure")
	}
	if rotateHits.Load() != 1 {
		t.Fatalf("expected 1 remote rotate call, got %d", rotateHits.Load())
	}
	journalPath := filepath.Join(activeDir, "key-rotation-pending.json")
	rawJ, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("P0-4 REGRESSION: rotation journal missing after partial failure: %v", err)
	}
	var j keyRotationPendingJournal
	if err := json.Unmarshal(rawJ, &j); err != nil {
		t.Fatal(err)
	}
	if j.State != rotStateServiceMetadataRebound {
		t.Fatalf("expected journal state=%q, got %q", rotStateServiceMetadataRebound, j.State)
	}

	// Attempt 2: systemctl restart now succeeds -> MUST resume locally and NOT call /rotate again!
	var restarted atomic.Bool
	okOps := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "restart" {
				restarted.Store(true)
			}
			return "active", nil
		},
	}
	if code := runKeyRotate([]string{"--json"}, okOps); code != apperr.ExitOK {
		t.Fatalf("rotation resume failed: code=%d", code)
	}
	if rotateHits.Load() != 1 {
		t.Fatalf("P0-4 REGRESSION: rotation resume re-called remote /rotate (%d hits)", rotateHits.Load())
	}
	if !restarted.Load() {
		t.Fatalf("expected rotation resume to restart DesiredEnabled publisher")
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("expected rotation journal removed after successful completion")
	}
}

func TestPass6P1_1LogoutReportsIncompleteLocalCleanup(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agent/key/revoke" {
			_, _ = w.Write([]byte(`{"revoked":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("OCLIV_CACERT", writeTestServerCA(t, srv))

	seedEnrolledProfileForTest(t, srv.URL)
	_, _, activeCfg, err := agentFiles()
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
	if err := st.Put(config.ServiceRecord{
		Name:         "logoutapp",
		Type:         "http",
		Profile:      "default",
		BackendMode:  config.BackendAttached,
		DesiredState: config.DesiredEnabled,
		Auth:         "protected",
		LocalURL:     "http://127.0.0.1:3000",
		SystemdUnit:  "ocliv-svc-logoutapp.service",
	}); err != nil {
		t.Fatal(err)
	}

	failOps := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "is-active" {
				return "active", nil
			}
			if len(args) > 0 && args[0] == "is-enabled" {
				return "enabled", nil
			}
			return "", errors.New("simulated systemctl stop/disable failure")
		},
	}
	code := runLogout([]string{}, failOps)
	if code != apperr.ExitInternal {
		t.Fatalf("P1-1 REGRESSION: expected ExitInternal (%d) when local unit cleanup fails, got %d", apperr.ExitInternal, code)
	}
}

func TestPass6P1_4AndP1_5DoctorMissingKeyNoPanicAndExplicitProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", "")
	t.Setenv("OCLIV_PROFILE", "")

	if code := cmdProfile([]string{"create", "altprof"}); code != apperr.ExitOK {
		t.Fatalf("cmdProfile create altprof failed: code=%d", code)
	}
	altDir, err := config.DataDirForProfile("altprof")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(altDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(altDir, config.ConfigFile), []byte("relay_url = \"https://relay.example\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Deliberately do NOT create agent.key in altprof!
	st, err := openServicesForProfile("altprof")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(config.ServiceRecord{
		Name:         "nokeyapp",
		Type:         "http",
		Profile:      "altprof",
		BackendMode:  config.BackendAttached,
		DesiredState: config.DesiredEnabled,
		Auth:         "protected",
		LocalURL:     "http://127.0.0.1:3000",
	}); err != nil {
		t.Fatal(err)
	}

	ops := serviceOps{
		loginctl: func(args ...string) (string, error) { return "yes", nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "inactive", nil
		},
	}
	// Must NOT panic and must return non-zero (unhealthy due to missing key).
	code := runDoctor([]string{"--profile", "altprof", "--all", "--json"}, ops)
	if code == apperr.ExitOK {
		t.Fatalf("expected non-zero doctor exit code for service with missing agent key")
	}
}

func TestPass6P1_9AndP1_11ManagedRuntimeValidationAndStrictEnvFile(t *testing.T) {
	// P1-9: ensureManagedRuntime must reject a pinned binary with missing/corrupt manifest.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", "")
	rtDir := filepath.Join(home, ".local", "share", "ocliv", "bin")
	if err := os.MkdirAll(rtDir, 0700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(rtDir, "ocliv")
	if err := os.WriteFile(dst, []byte("#!/bin/sh\necho bogus\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureManagedRuntime(); err == nil || !strings.Contains(err.Error(), "MANAGED_RUNTIME_INVALID") {
		t.Fatalf("P1-9 REGRESSION: expected MANAGED_RUNTIME_INVALID for unmanifested runtime, got err=%v", err)
	}

	// P1-11: loadBackendEnvFileStrict fails closed on missing, 0644, symlink, bad syntax; overrides deterministically.
	envDir := t.TempDir()
	if _, err := loadBackendEnvFileStrict(filepath.Join(envDir, "missing.env"), nil); err == nil {
		t.Fatalf("expected missing env file to fail closed")
	}
	wideEnv := filepath.Join(envDir, "wide.env")
	if err := os.WriteFile(wideEnv, []byte("FOO=bar\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wideEnv, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBackendEnvFileStrict(wideEnv, nil); err == nil {
		t.Fatalf("expected 0644 env file to fail closed")
	}
	goodEnv := filepath.Join(envDir, "good.env")
	if err := os.WriteFile(goodEnv, []byte("# comment\nFOO=from_file\nNEWKEY=123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	symEnv := filepath.Join(envDir, "sym.env")
	if err := os.Symlink(goodEnv, symEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBackendEnvFileStrict(symEnv, nil); err == nil {
		t.Fatalf("expected symlinked env file to fail closed")
	}
	badEnv := filepath.Join(envDir, "bad.env")
	if err := os.WriteFile(badEnv, []byte("NOT_A_PAIR\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBackendEnvFileStrict(badEnv, nil); err == nil {
		t.Fatalf("expected malformed env file to fail closed")
	}

	merged, err := loadBackendEnvFileStrict(goodEnv, []string{"FOO=from_parent", "KEEP=yes"})
	if err != nil {
		t.Fatalf("loadBackendEnvFileStrict valid failed: %v", err)
	}
	var fooCount int
	var gotFoo, gotNew, gotKeep string
	for _, kv := range merged {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "FOO":
			fooCount++
			gotFoo = v
		case "NEWKEY":
			gotNew = v
		case "KEEP":
			gotKeep = v
		}
	}
	if fooCount != 1 || gotFoo != "from_file" || gotNew != "123" || gotKeep != "yes" {
		t.Fatalf("unexpected merged env: %v", merged)
	}
}
