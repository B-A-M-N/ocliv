package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/setup"
)

func TestP0HTTPDisableRejects401AndSweepsStaleLeaseID(t *testing.T) {
	dir := t.TempDir()
	st := config.OpenServiceStore(dir)
	kp, _ := identity.Generate()
	keyID := string(kp.ID())
	svcID, _ := config.NewServiceID()

	rec := config.ServiceRecord{
		Name: "stale-http", Type: "http", LocalURL: "http://127.0.0.1:3000",
		Auth: "protected", Profile: "default", RelayURL: "https://relay.example",
		LeaseID: "lse-stale-old", PublicURL: "https://stale-http.t.relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@stale-http.service",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     svcID,
			Name:          "stale-http",
			WireLabel:     "stale-http",
			OwnerKeyID:    keyID,
			RelayID:       "https://relay.example",
		},
	}
	_ = st.Put(rec)

	// 1. Live protected route returning 401 MUST FAIL disable confirmation!
	rec1, _, _ := st.Get("stale-http")
	res401 := stopServiceAuthoritatively(st, rec1, kp, keyID, serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodPost && strings.HasSuffix(path, "/revoke") {
				return http.StatusOK, []byte(`{"status":"revoked"}`), nil
			}
			return http.StatusOK, []byte(`{"leases":[]}`), nil
		},
		probeEdge: func(string, time.Duration) (int, error) { return http.StatusUnauthorized, nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "inactive", nil
		},
	})
	if res401.RemoteDisabled || res401.RemoteDisableStatus == "CONFIRMED" {
		t.Fatalf("P0 REGRESSION: HTTP 401 must NEVER confirm route offline: %+v", res401)
	}

	// 2. Stale LeaseID returning 404 MUST sweep /v1/agent/leases and revoke the live rebound lease!
	_, _ = st.UpdateCAS("stale-http", 0, func(r *config.ServiceRecord) error {
		r.DesiredState = config.DesiredEnabled
		r.LeaseID = "lse-stale-old"
		return nil
	})
	rec2, _, _ := st.Get("stale-http")
	revokedLive := false
	resSweep := stopServiceAuthoritatively(st, rec2, kp, keyID, serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodPost && path == "/v1/agent/lease/lse-stale-old/revoke" {
				return http.StatusNotFound, []byte("unknown lease"), nil
			}
			if method == http.MethodGet && path == "/v1/agent/leases" {
				return http.StatusOK, []byte(`{"leases":[{"lease_id":"lse-live-new","label":"stale-http","port":3000,"access_mode":"protected","status":"ACTIVE","route_live":true,"url":"https://stale-http.t.relay.example"}]}`), nil
			}
			if method == http.MethodPost && path == "/v1/agent/lease/lse-live-new/revoke" {
				revokedLive = true
				return http.StatusOK, []byte(`{"status":"revoked"}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		probeEdge: func(string, time.Duration) (int, error) { return http.StatusNotFound, nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			return "inactive", nil
		},
	})
	if !revokedLive || !resSweep.RemoteDisabled || resSweep.RemoteDisableStatus != "CONFIRMED" {
		t.Fatalf("expected stale 404 to sweep and revoke lse-live-new, got revokedLive=%v res=%+v", revokedLive, resSweep)
	}
	// P1-9: After confirmed HTTP stop, ServiceRecord.LeaseID must be cleared while PublicURL is retained.
	afterStop, _, _ := st.Get("stale-http")
	if afterStop.LeaseID != "" || afterStop.PublicURL != "https://stale-http.t.relay.example" {
		t.Fatalf("expected LeaseID cleared and PublicURL retained after stop, got %+v", afterStop)
	}
}

func TestP0WireLabelCollisionAndUnderscoreRejected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))
	t.Setenv("OCLIV_PROFILE", "")
	seedEnrolledProfileForTest(t, "https://relay.example")

	// Underscore is invalid as a DNS wire label for HTTP services.
	if _, _, code, err := registerHostedService(serviceAddRequest{
		Name: "my_app", Type: "http", LocalURL: "http://127.0.0.1:3000",
	}, serviceOps{}); err == nil || code != apperr.ExitCLIValidation {
		t.Fatalf("expected underscore HTTP name to be rejected, got code=%d err=%v", code, err)
	}

	// Register "Foo" -> WireLabel="foo".
	if _, _, code, err := registerHostedService(serviceAddRequest{
		Name: "Foo", Type: "http", LocalURL: "http://127.0.0.1:3000",
	}, serviceOps{}); err != nil || code != apperr.ExitOK {
		t.Fatalf("register Foo failed: code=%d err=%v", code, err)
	}

	// Registering "foo" MUST fail as a canonical wire-label collision!
	if _, _, code, err := registerHostedService(serviceAddRequest{
		Name: "foo", Type: "http", LocalURL: "http://127.0.0.1:3001",
	}, serviceOps{}); err == nil || code != apperr.ExitCLIValidation {
		t.Fatalf("expected Foo/foo wire-label collision to be rejected, got code=%d err=%v", code, err)
	}
}

func TestP0PrivilegedSecretFileSymlinkRejectedAndDuckDNSSupported(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.token")
	if err := os.WriteFile(realFile, []byte("secret-tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symFile := filepath.Join(dir, "sym.token")
	if err := os.Symlink(realFile, symFile); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFileStrict(symFile); err == nil {
		t.Fatal("expected symlink token file to be rejected by O_NOFOLLOW")
	}
	if got, err := readSecretFileStrict(realFile); err != nil || got != "secret-tok" {
		t.Fatalf("expected regular 0600 token file to succeed, got %q err=%v", got, err)
	}

	// Ambient OCLIV_DYNV6_ENDPOINT MUST NOT override production dynv6Endpoint().
	t.Setenv("OCLIV_DYNV6_ENDPOINT", "https://evil.example/steal")
	if ep := dynv6Endpoint(); ep != setup.Dynv6UpdateEndpoint {
		t.Fatalf("P0 REGRESSION: OCLIV_DYNV6_ENDPOINT overrode endpoint to %q", ep)
	}

	// DuckDNS update works cleanly and refuses redirects.
	var gotDomains, gotIP string
	duckSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDomains = r.URL.Query().Get("domains")
		gotIP = r.URL.Query().Get("ip")
		_, _ = w.Write([]byte("OK"))
	}))
	defer duckSrv.Close()
	if err := setup.UpdateDuckDNS(context.Background(), duckSrv.URL, "mylab.duckdns.org", "duck-tok-123", "203.0.113.5", ""); err != nil {
		t.Fatalf("UpdateDuckDNS failed: %v", err)
	}
	if gotDomains != "mylab" || gotIP != "203.0.113.5" {
		t.Fatalf("unexpected DuckDNS query: domains=%q ip=%q", gotDomains, gotIP)
	}
}

func TestP1AccessExplicitTargetAndIncompatibleSingleHostEdge(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")
	seedEnrolledProfileForTest(t, "https://relay.example")

	// Multiple leases -> resolveAccessTarget without NAME/--lease MUST fail!
	ls, err := config.OpenLeaseStore(cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = ls.Save(config.LeaseRecord{LeaseID: "lse-1", Name: "app1"})
	_ = ls.Save(config.LeaseRecord{LeaseID: "lse-2", Name: "app2"})
	if _, _, err := resolveAccessTarget("", "", cfgDir); err == nil {
		t.Fatal("expected resolveAccessTarget to reject ambiguous implicit selection with 2 leases")
	}
	if id, _, err := resolveAccessTarget("app2", "", cfgDir); err != nil || id != "lse-2" {
		t.Fatalf("expected explicit name app2 -> lse-2, got id=%q err=%v", id, err)
	}

	// Incompatible single-host setup edge -> `ocliv host 3000` (HTTP) MUST fail fast before writing service state!
	if err := saveSetupState(setupState{EdgeMode: "single-host", Hostname: "mylab.duckdns.org"}); err != nil {
		t.Fatal(err)
	}
	if code := cmdHostWithOps([]string{"3000", "--name", "webapp", "--json"}, serviceOps{}); code != apperr.ExitCLIValidation {
		t.Fatalf("expected ExitCLIValidation when hosting HTTP on single-host edge, got %d", code)
	}
}

func TestP1RestartFencedAgainstConcurrentDisable(t *testing.T) {
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
		Name: "race-restart", Type: "mcp", BackendMode: config.BackendManaged,
		BackendExec: "/bin/true", BackendUnit: "ocliv-backend@race.service",
		LocalURL: "http://127.0.0.1:8765/mcp", Auth: "ocliv-managed",
		Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@race.service",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     svcID,
			Name:          "race-restart",
			WireLabel:     "race-restart",
			OwnerKeyID:    keyID,
			RelayID:       "https://relay.example",
		},
	})

	stoppedBackend := false
	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "restart" && args[1] == "ocliv-backend@race.service" {
				// Simulate concurrent stop/disable committing right as backend restarts.
				_, _ = st.UpdateCAS("race-restart", 0, func(r *config.ServiceRecord) error {
					r.DesiredState = config.DesiredDisabled
					return nil
				})
				return "", nil
			}
			if len(args) >= 2 && args[0] == "stop" && args[1] == "ocliv-backend@race.service" {
				stoppedBackend = true
			}
			return "", nil
		},
	}
	if _, code, err := restartHostedService("race-restart", ops); code != apperr.ExitAuth || err == nil {
		t.Fatalf("expected ExitAuth on concurrent disable during restart, got code=%d err=%v", code, err)
	}
	if !stoppedBackend {
		t.Fatal("expected managed backend to be stopped when concurrent disable committed during restart")
	}
}

func TestP0HTTPPublisherArgsParseCleanlyInCmdTunnel(t *testing.T) {
	t.Setenv("OCLIV_CONFIG_DIR", t.TempDir())
	args, err := buildHTTPPublisherArgs(config.ServiceRecord{
		Name:     "webpass4",
		Type:     "http",
		LocalURL: "http://127.0.0.1:28191",
		RelayURL: "https://relay.example.test",
		Auth:     "protected",
	})
	if err != nil {
		t.Fatalf("buildHTTPPublisherArgs: %v", err)
	}
	opts, rc := parseTunnelOptions(args)
	if rc != apperr.ExitOK {
		t.Fatalf("parseTunnelOptions(%v) failed with rc=%d", args, rc)
	}
	if opts.port != 28191 || !opts.cfg.Persistent || opts.cfg.Name != "webpass4" || opts.cfg.RelayURL != "https://relay.example.test" {
		t.Fatalf("unexpected parsed tunnel options: %+v", opts)
	}
}

func TestP1PendingEnrollJournalAndRemoteFirstLogout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))
	dir, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}

	// 1. Ambiguous post-send failure (connection dropped after request received)
	//    preserves pending key + journal so the operator never loses an enrolled key.
	dropSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, herr := hj.Hijack(); herr == nil {
				_ = conn.Close()
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer dropSrv.Close()
	_, rc := performEnroll(dropSrv.URL, "ambiguous-code", "")
	if rc == apperr.ExitOK {
		t.Fatal("expected enroll against dropped response to fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "enroll-pending.json")); err != nil {
		t.Fatalf("expected enroll-pending.json to be preserved on ambiguous failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.key.pending")); err != nil {
		t.Fatalf("expected agent.key.pending to be preserved on ambiguous failure: %v", err)
	}

	// 2. Remote-first logout fails closed when relay is unreachable without --force-local.
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := mergeRelayURL(cfgPath, "http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if rc := cmdLogout(nil); rc != apperr.ExitRelayTLS {
		t.Fatalf("expected logout without --force-local to fail closed (ExitRelayTLS), got %d", rc)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatal("local key must NOT be deleted when remote revocation failed without --force-local")
	}

	// 3. With --force-local, local files are removed.
	if rc := cmdLogout([]string{"--force-local"}); rc != apperr.ExitOK {
		t.Fatalf("expected logout --force-local to succeed, got %d", rc)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("expected agent.key to be removed after --force-local")
	}

	// 4. With reachable relay returning 200 on /v1/agent/key/revoke, normal logout succeeds.
	revokedCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/key/revoke" {
			revokedCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"revoked":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if err := k.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := mergeRelayURL(cfgPath, srv.URL); err != nil {
		t.Fatal(err)
	}
	if rc := cmdLogout(nil); rc != apperr.ExitOK {
		t.Fatalf("expected remote-first logout to succeed, got %d", rc)
	}
	if !revokedCalled {
		t.Fatal("expected logout to call POST /v1/agent/key/revoke")
	}
}

func TestP1RuntimeManifestAndUpgrade(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	src := filepath.Join(t.TempDir(), "ocliv-src")
	if err := os.WriteFile(src, []byte("fake-ocliv-binary-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(home, ".local", "share", "ocliv", "bin", "ocliv")
	if err := installManagedExecutable(src, dst); err != nil {
		t.Fatalf("installManagedExecutable: %v", err)
	}
	m, ok := loadRuntimeManifest(dst)
	if !ok {
		t.Fatal("expected runtime.json manifest to be written")
	}
	wantSum, err := fileSHA256(src)
	if err != nil {
		t.Fatal(err)
	}
	if m.SHA256 != wantSum || m.BinaryPath != dst {
		t.Fatalf("unexpected runtime manifest: %+v (want sha=%s)", m, wantSum)
	}
	if rc := cmdRuntime([]string{"status", "--json"}); rc != apperr.ExitOK {
		t.Fatalf("cmdRuntime status --json failed: rc=%d", rc)
	}
}

func TestP2SetupJSONRunsFullTransaction(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OCLIV_CONFIG_DIR", dir)
	t.Setenv("DUCKDNS_TOKEN", "secret-duck-token")
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.42"))
	}))
	defer echo.Close()
	rc, out := runSuppressedStdout(func() int {
		return cmdSetup([]string{
			"--auto", "--hostname", "demo.duckdns.org", "--dry-run", "--json",
			"--echo-v4", echo.URL, "--echo-v6", echo.URL,
		})
	})
	if rc != apperr.ExitOK {
		t.Fatalf("setup --auto --dry-run --json failed: rc=%d out=%s", rc, out)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("setup --json stdout is NOT pure valid JSON: %v\nstdout:\n%s", err, out)
	}
	if parsed["action"] != "setup_dns" || parsed["completed_stage"] != "dry_run_ok" || parsed["edge_mode"] != "tunnel" {
		t.Fatalf("unexpected setup JSON payload: %+v", parsed)
	}
}

func TestP0AccessJSONRequiresOutBeforeMutation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))
	if rc := cmdAccess([]string{"share", "web", "--json"}); rc != apperr.ExitCLIValidation {
		t.Fatalf("P0-7: share --json without --out must fail validation, got %d", rc)
	}
	if rc := cmdAccess([]string{"rotate", "web", "--json"}); rc != apperr.ExitCLIValidation {
		t.Fatalf("P0-7: rotate --json without --out must fail validation, got %d", rc)
	}
}

func TestP0KeyRotateCrashRecoveryJournal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))
	dir, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKeyID := "key-" + string(oldKey.ID())
	if err := oldKey.Save(keyPath); err != nil {
		t.Fatal(err)
	}

	// Simulate relay that commits rotation on first call, then drops connection
	// before sending response (worst-case crash window, P0-2).
	var committedNewKeyID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agent/key/rotate":
			var req struct {
				NewPublicKey string `json:"new_public_key"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			// Record that the new key is now admitted, then drop TCP connection.
			if rawJ, err := os.ReadFile(filepath.Join(dir, "key-rotation-pending.json")); err == nil {
				var pj keyRotationPendingJournal
				if json.Unmarshal(rawJ, &pj) == nil {
					committedNewKeyID = pj.NewKeyID
				}
			}
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, herr := hj.Hijack(); herr == nil {
					_ = conn.Close()
					return
				}
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agent/leases":
			if committedNewKeyID != "" && r.Header.Get("X-Ocliv-Key") == committedNewKeyID {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"leases":[]}`))
				return
			}
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	if err := mergeRelayURL(cfgPath, srv.URL); err != nil {
		t.Fatal(err)
	}

	// First attempt drops mid-flight: staged key & journal MUST be preserved.
	if rc := cmdKeyRotate(nil); rc != apperr.ExitRelayTLS {
		t.Fatalf("expected ExitRelayTLS on dropped response, got %d", rc)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.key.rotating")); err != nil {
		t.Fatalf("P0-2: staged rotating key was deleted after ambiguous drop: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key-rotation-pending.json")); err != nil {
		t.Fatalf("P0-2: rotation journal missing after ambiguous drop: %v", err)
	}

	// Second attempt probes new key, sees it admitted, finalizes local swap!
	if rc := cmdKeyRotate([]string{"--json"}); rc != apperr.ExitOK {
		t.Fatalf("P0-2: recovery retry of cmdKeyRotate failed with rc=%d", rc)
	}
	_, curKeyID, err := loadKey()
	if err != nil {
		t.Fatalf("loadKey after recovery: %v", err)
	}
	if curKeyID != committedNewKeyID || curKeyID == oldKeyID {
		t.Fatalf("P0-2: expected recovered key %s, got %s", committedNewKeyID, curKeyID)
	}
	if _, err := os.Stat(filepath.Join(dir, "key-rotation-pending.json")); !os.IsNotExist(err) {
		t.Fatal("expected rotation journal to be removed after recovery")
	}
}

func TestP1LogoutIgnoresAmbientRelayOverrideAndPreservesConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))
	t.Setenv("OCLIV_RELAY_URL", "http://127.0.0.1:1") // ambient poison MUST be ignored
	_, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	revoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/key/revoke" {
			revoked = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"revoked":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if err := mergeRelayURL(cfgPath, srv.URL); err != nil {
		t.Fatal(err)
	}
	if rc := cmdLogout(nil); rc != apperr.ExitOK {
		t.Fatalf("P1-3: logout failed even though bound relay was reachable: rc=%d", rc)
	}
	if !revoked {
		t.Fatal("P1-3: logout did not contact persisted bound relay")
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("P1-4: logout must preserve agent.conf preferences: %v", err)
	}
}

func TestP1ManagedRuntimeImmutableAndDowngradeFenced(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dst := filepath.Join(home, ".local", "share", "ocliv", "bin", "ocliv")
	src1 := filepath.Join(t.TempDir(), "ocliv-v1")
	if err := os.WriteFile(src1, []byte("runtime-v1-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installManagedExecutable(src1, dst); err != nil {
		t.Fatal(err)
	}
	sum1, _ := fileSHA256(dst)

	// P1-7: ensureManagedRuntime MUST NOT overwrite an existing pinned binary.
	gotPath, err := ensureManagedRuntime()
	if err != nil {
		t.Fatalf("ensureManagedRuntime: %v", err)
	}
	if gotPath != dst {
		t.Fatalf("ensureManagedRuntime returned %q, want %q", gotPath, dst)
	}
	sumAfter, _ := fileSHA256(dst)
	if sumAfter != sum1 {
		t.Fatal("P1-7: ensureManagedRuntime silently overwrote pinned managed runtime!")
	}

	// P1-9: downgrade fence blocks schema downgrade without --allow-downgrade.
	m, _ := loadRuntimeManifest(dst)
	m.StoreSchemaVersion = 999
	if err := saveRuntimeManifest(dst, m); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeManagedRuntime(src1, dst, false); err == nil {
		t.Fatal("P1-9: expected schema downgrade to be blocked without --allow-downgrade")
	}
	if _, err := upgradeManagedRuntime(src1, dst, true); err != nil {
		t.Fatalf("P1-9: expected --allow-downgrade to succeed: %v", err)
	}
}

func TestP2DuckDNSRefreshTimerAndSymlinkStateGuard(t *testing.T) {
	// Verify BootstrapPlan includes the DuckDNS refresh timer step.
	steps, blocker := setup.PlanBootstrap(setup.BootstrapEnv{
		AsRoot: true, CaddyPresent: true, Path: setup.PathDirectV4,
		Hostname: "demo.duckdns.org", DeployDir: "/tmp/deploy", DataDir: "/var/lib/ocliv",
	})
	if blocker != "" {
		t.Fatalf("unexpected blocker: %s", blocker)
	}
	foundDuckTimer := false
	for _, s := range steps {
		if strings.Contains(strings.ToLower(s.Title), "duckdns refresh timer") {
			foundDuckTimer = true
		}
	}
	if !foundDuckTimer {
		t.Fatalf("expected BootstrapPlan for demo.duckdns.org to include duckdns refresh timer step: %+v", steps)
	}

	// Symlinked ~/.config/ocliv directory must be refused by saveSetupState.
	fakeHome := t.TempDir()
	realDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fakeHome, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(fakeHome, ".config", "ocliv")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fakeHome)
	t.Setenv("OCLIV_CONFIG_DIR", "")
	if err := saveSetupState(setupState{Hostname: "demo.duckdns.org"}); err == nil {
		t.Fatal("expected saveSetupState to refuse writing through symlinked ~/.config/ocliv directory")
	}
}

func TestP2DoctorServiceNameAndAll(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OCLIV_CONFIG_DIR", dir)
	st, err := openServices()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(config.ServiceRecord{
		Name:         "webdoc",
		Type:         "http",
		DesiredState: config.DesiredDisabled,
		BackendMode:  config.BackendAttached,
		LocalURL:     "http://127.0.0.1:9999",
		Auth:         "protected",
	}); err != nil {
		t.Fatal(err)
	}
	ops := defaultServiceOps()
	ops.systemctl = func(args ...string) (string, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return "inactive", fmt.Errorf("inactive")
		}
		if len(args) > 0 && args[0] == "is-enabled" {
			return "disabled", fmt.Errorf("disabled")
		}
		return "", nil
	}
	if rc := runDoctor([]string{"webdoc", "--json"}, ops); rc != apperr.ExitOK {
		t.Fatalf("doctor webdoc --json failed: rc=%d", rc)
	}
	if rc := runDoctor([]string{"--all", "--json"}, ops); rc != apperr.ExitOK {
		t.Fatalf("doctor --all --json failed: rc=%d", rc)
	}
}
