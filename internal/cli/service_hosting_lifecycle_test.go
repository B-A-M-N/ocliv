package cli

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestP0ManagedBackendStartupOrdering(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	seedEnrolledProfileForTest(t, "https://relay.example")

	// Add a fresh managed service (DesiredState starts as DesiredConfigured).
	addCode := cmdServiceAdd([]string{
		"managed-svc",
		"--type", "mcp",
		"--manage",
		"--exec", "/bin/true",
		"--local", "http://127.0.0.1:18765/mcp",
		"--auth", "ocliv-managed",
		"--relay", "https://relay.example",
	}, serviceOps{
		probeLoc: func(string, time.Duration) error { return errors.New("not running yet") },
	})
	if addCode != apperr.ExitOK {
		t.Fatalf("cmdServiceAdd failed: code=%d", addCode)
	}

	backendRan := false
	publisherStarted := false
	ops := serviceOps{
		provision: func(rec config.ServiceRecord, ops serviceOps) error { return nil },
		probeLoc: func(string, time.Duration) error {
			if !backendRan {
				return errors.New("backend not running")
			}
			return nil
		},
		probePub: func(string, time.Duration) (int, error) {
			return http.StatusUnauthorized, nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-managed-1","pub_name":"managed-svc","profile":"managed-oauth","url":"https://relay.example/r/pub-managed-1/mcp","publication_state":"VERIFIED","desired_enabled":true,"state_generation":1,"session_live":true,"admission":"READY","admission_reason":"READY"}]}`), nil
			}
			return http.StatusOK, []byte(`{}`), nil
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) < 2 {
				return "", nil
			}
			cmd, unit := args[0], args[1]
			if cmd == "start" && strings.HasPrefix(unit, "ocliv-backend@") {
				// Simulate systemd invoking `ocliv service run-backend`.
				code := cmdServiceRunBackend([]string{"--name", "managed-svc", "--profile", "default"})
				if code != apperr.ExitOK {
					return "run-backend refused", errors.New("exit non-zero")
				}
				backendRan = true
				return "", nil
			}
			if cmd == "start" && strings.HasPrefix(unit, "ocliv-publisher@") {
				publisherStarted = true
				return "", nil
			}
			if cmd == "show" {
				return "loaded", nil
			}
			if cmd == "is-enabled" {
				return "enabled", nil
			}
			if cmd == "is-active" {
				if publisherStarted {
					return "active", nil
				}
				return "inactive", nil
			}
			return "", nil
		},
	}

	startCode := cmdServiceStart([]string{"managed-svc", "--wait-ready"}, ops)
	if startCode != apperr.ExitOK {
		t.Fatalf("P0 REPRODUCED: fresh managed backend start failed with code=%d (backendRan=%v, publisherStarted=%v)", startCode, backendRan, publisherStarted)
	}
	if !backendRan || !publisherStarted {
		t.Fatalf("expected both backendRan and publisherStarted, got backendRan=%v publisherStarted=%v", backendRan, publisherStarted)
	}
}

func TestP0BackendFailureNeverProducesPublicRoute(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	seedEnrolledProfileForTest(t, "https://relay.example")

	if code := cmdServiceAdd([]string{
		"fail-be", "--type", "mcp", "--manage", "--exec", "/bin/true",
		"--local", "http://127.0.0.1:18766/mcp", "--relay", "https://relay.example",
	}, serviceOps{probeLoc: func(string, time.Duration) error { return errors.New("down") }}); code != apperr.ExitOK {
		t.Fatalf("add failed: %d", code)
	}

	relayCalled := false
	pubStarted := false
	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		probeLoc:  func(string, time.Duration) error { return errors.New("connection refused") },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			relayCalled = true
			return http.StatusOK, []byte(`{}`), nil
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "start" && strings.HasPrefix(args[1], "ocliv-backend@") {
				return "crash", errors.New("exit 1")
			}
			if len(args) >= 2 && args[0] == "start" && strings.HasPrefix(args[1], "ocliv-publisher@") {
				pubStarted = true
			}
			return "", nil
		},
	}

	code := cmdServiceStart([]string{"fail-be", "--wait-ready"}, ops)
	if code == apperr.ExitOK {
		t.Fatal("expected non-zero exit when managed backend fails")
	}
	if relayCalled || pubStarted {
		t.Fatalf("failed backend must never publish or start publisher (relayCalled=%v pubStarted=%v)", relayCalled, pubStarted)
	}
	st, _ := openServicesForProfile("default")
	rec, ok, _ := st.Get("fail-be")
	if !ok || rec.DesiredState != config.DesiredConfigured || rec.LastFailure == "" {
		t.Fatalf("expected rolled-back DesiredConfigured with LastFailure, got %+v", rec)
	}
}

func TestP0ConcurrentDisableDuringStartupStopsBackendAndRefusesPublication(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	seedEnrolledProfileForTest(t, "https://relay.example")

	if code := cmdServiceAdd([]string{
		"race-start", "--type", "mcp", "--manage", "--exec", "/bin/true",
		"--local", "http://127.0.0.1:18767/mcp", "--relay", "https://relay.example",
	}, serviceOps{probeLoc: func(string, time.Duration) error { return errors.New("down") }}); code != apperr.ExitOK {
		t.Fatalf("add failed: %d", code)
	}
	st, _ := openServicesForProfile("default")

	backendStopped := false
	relayCalled := false
	pubStarted := false
	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		probeLoc: func(string, time.Duration) error {
			// Simulate a concurrent disable committing right after backend starts.
			_, _ = st.UpdateCAS("race-start", 0, func(r *config.ServiceRecord) error {
				r.DesiredState = config.DesiredDisabled
				return nil
			})
			return nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			relayCalled = true
			return http.StatusOK, []byte(`{}`), nil
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "stop" && strings.HasPrefix(args[1], "ocliv-backend@") {
				backendStopped = true
			}
			if len(args) >= 2 && args[0] == "start" && strings.HasPrefix(args[1], "ocliv-publisher@") {
				pubStarted = true
			}
			return "", nil
		},
	}

	code := cmdServiceStart([]string{"race-start", "--wait-ready"}, ops)
	if code != apperr.ExitAuth {
		t.Fatalf("expected ExitAuth on concurrent disable during startup, got %d", code)
	}
	if !backendStopped {
		t.Fatal("expected managed backend to be stopped on concurrent disable")
	}
	if relayCalled || pubStarted {
		t.Fatalf("concurrent disable must block publication and publisher start (relay=%v pub=%v)", relayCalled, pubStarted)
	}
}

func TestP0RepeatedServiceStartIsIdempotent(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	seedEnrolledProfileForTest(t, "https://relay.example")

	if code := cmdServiceAdd([]string{
		"idem-svc", "--type", "mcp", "--local", "http://127.0.0.1:18768/mcp", "--relay", "https://relay.example",
	}, serviceOps{probeLoc: func(string, time.Duration) error { return nil }}); code != apperr.ExitOK {
		t.Fatalf("add failed: %d", code)
	}

	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		probeLoc:  func(string, time.Duration) error { return nil },
		probePub:  func(string, time.Duration) (int, error) { return http.StatusUnauthorized, nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-idem-1","pub_name":"idem-svc","profile":"managed-oauth","url":"https://relay.example/r/pub-idem-1/mcp","publication_state":"VERIFIED","desired_enabled":true,"state_generation":1,"session_live":true,"admission":"READY","admission_reason":"READY"}]}`), nil
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

	if code := cmdServiceStart([]string{"idem-svc", "--wait-ready"}, ops); code != apperr.ExitOK {
		t.Fatalf("first start failed: %d", code)
	}
	st, _ := openServicesForProfile("default")
	rec1, _, _ := st.Get("idem-svc")

	if code := cmdServiceStart([]string{"idem-svc", "--wait-ready"}, ops); code != apperr.ExitOK {
		t.Fatalf("second start failed: %d", code)
	}
	rec2, _, _ := st.Get("idem-svc")
	list, _ := st.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 service record, got %d", len(list))
	}
	if rec1.Identity.ServiceID != rec2.Identity.ServiceID || rec1.PublicationID != rec2.PublicationID || rec1.SystemdUnit != rec2.SystemdUnit {
		t.Fatalf("repeated start mutated identity/unit: rec1=%+v rec2=%+v", rec1, rec2)
	}
}

func TestP1HostRequiresVerifiedRebootPersistenceAndTransactionalRetry(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")
	t.Setenv("USER", "testuser")

	seedEnrolledProfileForTest(t, "https://relay.example")

	lingerEnabled := false
	unitEnabled := false
	backendUp := false

	ops := serviceOps{
		provision: func(config.ServiceRecord, serviceOps) error { return nil },
		probeLoc: func(string, time.Duration) error {
			if !backendUp {
				return errors.New("backend down")
			}
			return nil
		},
		probePub: func(string, time.Duration) (int, error) { return http.StatusUnauthorized, nil },
		loginctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "show-user" {
				if lingerEnabled {
					return "yes", nil
				}
				return "no", nil
			}
			if len(args) > 0 && args[0] == "enable-linger" {
				if lingerEnabled {
					return "", nil
				}
				return "permission denied", errors.New("exit 1")
			}
			return "", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-host-1","pub_name":"personal-tools","profile":"managed-oauth","url":"https://relay.example/r/pub-host-1/mcp","publication_state":"VERIFIED","desired_enabled":true,"state_generation":1,"session_live":true,"admission":"READY","admission_reason":"READY"}]}`), nil
			}
			return http.StatusOK, []byte(`{}`), nil
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) == 0 {
				return "", nil
			}
			switch args[0] {
			case "enable":
				if !unitEnabled {
					return "enable failed", errors.New("exit 1")
				}
				return "", nil
			case "show":
				return "loaded", nil
			case "is-enabled":
				if unitEnabled {
					return "enabled", nil
				}
				return "disabled", nil
			case "is-active":
				return "active", nil
			}
			return "", nil
		},
	}

	// 1. Backend down -> host fails, leaves recoverable configured record.
	if code := cmdHostWithOps([]string{"mcp", "8765", "--name", "personal-tools", "--json"}, ops); code == apperr.ExitOK {
		t.Fatal("expected ocliv host to fail when backend is unreachable")
	}

	// 2. Backend up, but systemd enable fails -> host MUST fail (persistence mandatory).
	backendUp = true
	if code := cmdHostWithOps([]string{"mcp", "8765", "--name", "personal-tools", "--json"}, ops); code == apperr.ExitOK {
		t.Fatal("expected ocliv host to fail when systemd enable fails")
	}

	// 3. Unit enabled, but linger disabled -> host MUST fail (reboot persistence unverified).
	unitEnabled = true
	if code := cmdHostWithOps([]string{"mcp", "8765", "--name", "personal-tools", "--json"}, ops); code == apperr.ExitOK {
		t.Fatal("expected ocliv host to fail when user lingering is disabled")
	}

	// 4. Linger enabled -> safe retry with same --name succeeds without "already exists"!
	lingerEnabled = true
	if code := cmdHostWithOps([]string{"mcp", "8765", "--name", "personal-tools", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("expected ocliv host retry to succeed once persistence and backend are ready, got code=%d", code)
	}
}

func TestP1PermanentIdentityDecoupledFromLocalPortAndExec(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	t.Setenv("OCLIV_PROFILE", "")

	seedEnrolledProfileForTest(t, "https://relay.example")

	if code := cmdServiceAdd([]string{
		"stable-svc", "--type", "mcp", "--manage", "--exec", "/bin/true",
		"--local", "http://127.0.0.1:8765/mcp", "--relay", "https://relay.example",
	}, serviceOps{probeLoc: func(string, time.Duration) error { return nil }}); code != apperr.ExitOK {
		t.Fatalf("add failed: %d", code)
	}

	st, _ := openServicesForProfile("default")
	_, err := st.UpdateCAS("stable-svc", 0, func(r *config.ServiceRecord) error {
		r.PublicationID = "pub-perm-1"
		r.PublicURL = "https://relay.example/r/pub-perm-1/mcp"
		if r.Identity != nil {
			r.Identity.PublicationID = "pub-perm-1"
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := st.Get("stable-svc")

	// Local port change + backend exec change must preserve ServiceID, PublicationID, and PublicURL.
	if code := cmdServiceUpdate([]string{"stable-svc", "--local", "http://127.0.0.1:9000/mcp", "--exec", "/bin/echo"}); code != apperr.ExitOK {
		t.Fatalf("update failed: %d", code)
	}
	after, _, _ := st.Get("stable-svc")
	if after.LocalURL != "http://127.0.0.1:9000/mcp" || after.BackendExec != "/bin/echo" {
		t.Fatalf("mutable target not updated: %+v", after)
	}
	if after.Identity.ServiceID != before.Identity.ServiceID || after.PublicationID != before.PublicationID || after.PublicURL != before.PublicURL {
		t.Fatalf("permanent identity changed on port/exec update: before=%+v after=%+v", before, after)
	}

	// Auth profile change in place must be rejected.
	if code := cmdServiceUpdate([]string{"stable-svc", "--auth", "upstream-oauth"}); code == apperr.ExitOK {
		t.Fatal("expected auth profile change in place to be rejected")
	}

	// Cross-key collision must fail closed on start and reconcile.
	_, _ = st.UpdateCAS("stable-svc", 0, func(r *config.ServiceRecord) error {
		r.Identity.OwnerKeyID = "different-owner-key"
		r.DesiredState = config.DesiredEnabled
		return nil
	})
	if code := cmdServiceStart([]string{"stable-svc"}, serviceOps{}); code != apperr.ExitAuth {
		t.Fatalf("expected ExitAuth on cross-key collision, got %d", code)
	}
	kp, keyID, _ := loadKeyForProfile("default")
	if _, err := reconcileServiceOnce(st, "stable-svc", kp, keyID, serviceOps{}, time.Now()); err != nil {
		t.Fatalf("reconcileServiceOnce returned unexpected err: %v", err)
	}
	crossRec, _, _ := st.Get("stable-svc")
	if crossRec.Reconcile == nil || !crossRec.Reconcile.Terminal || crossRec.Reconcile.FailureLayer != "authorization" {
		t.Fatalf("expected terminal authorization fence on cross-key collision, got %+v", crossRec.Reconcile)
	}
}

func TestP1LayeredReconciliationNarrowBackendRecovery(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	kp, _ := identity.Generate()
	now := time.Now().UTC()

	_ = st.Put(config.ServiceRecord{
		Name: "layered-svc", Type: "mcp", BackendMode: config.BackendManaged,
		BackendExec: "/bin/true", BackendUnit: "ocliv-backend@layered.service",
		LocalURL: "http://127.0.0.1:18769/mcp", Profile: "default",
		RelayURL: "https://relay.example", PublicationID: "pub-layer-1",
		PublicURL:    "https://relay.example/r/pub-layer-1/mcp",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@layered.service",
	})

	var actions []string
	ops := serviceOps{
		probeLoc: func(string, time.Duration) error { return errors.New("backend crashed") },
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && (args[0] == "restart" || args[0] == "start") {
				actions = append(actions, args[0]+":"+args[1])
				return "", nil
			}
			if len(args) > 0 && args[0] == "show" {
				return "loaded", nil
			}
			if len(args) > 0 && args[0] == "is-active" {
				return "active", nil
			}
			return "enabled", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[{"route_id":"pub-layer-1","pub_name":"layered-svc","profile":"managed-oauth","url":"https://relay.example/r/pub-layer-1/mcp","publication_state":"VERIFIED","desired_enabled":true,"state_generation":2,"session_live":true,"admission":"READY","admission_reason":"READY"}]}`), nil
		},
	}

	if _, err := reconcileServiceOnce(st, "layered-svc", kp, "k1", ops, now); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0] != "restart:ocliv-backend@layered.service" {
		t.Fatalf("expected narrow restart of backend unit only, got actions=%v", actions)
	}
	rec, _, _ := st.Get("layered-svc")
	if rec.Reconcile == nil || rec.Reconcile.FailureLayer != "backend" || rec.Reconcile.ErrorClassification != "retryable" {
		t.Fatalf("expected FailureLayer=backend retryable, got %+v", rec.Reconcile)
	}
}

func TestP1HTTPRemoteFirstDisableAndRemove(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	kp, _ := identity.Generate()

	rec := config.ServiceRecord{
		Name: "http-svc", Type: "http", LocalURL: "http://127.0.0.1:3000",
		Auth: "protected", Profile: "default", RelayURL: "https://relay.example",
		LeaseID: "lse-http-1", PublicURL: "https://http-svc.t.relay.example",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@http-svc.service",
	}
	_ = st.Put(rec)
	rec, _, _ = st.Get("http-svc")

	var order []string
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			order = append(order, method+":"+path)
			if method == http.MethodPost && path == "/v1/agent/lease/lse-http-1/revoke" {
				return http.StatusOK, []byte(`{"status":"revoked"}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		probePub: func(string, time.Duration) (int, error) {
			order = append(order, "probe")
			return http.StatusNotFound, nil
		},
		systemctl: func(args ...string) (string, error) {
			order = append(order, "systemctl:"+args[0])
			if args[0] == "show" {
				return "loaded", nil
			}
			if args[0] == "is-enabled" {
				return "disabled", nil
			}
			return "inactive", nil
		},
	}

	res := stopServiceAuthoritatively(st, rec, kp, "k1", ops)
	if !res.Stopped || !res.RemoteDisabled || res.RemoteDisableStatus != "CONFIRMED" {
		t.Fatalf("expected confirmed remote HTTP disable, got %+v", res)
	}
	if len(order) < 3 || order[0] != "POST:/v1/agent/lease/lse-http-1/revoke" || order[1] != "probe" {
		t.Fatalf("expected remote HTTP revoke + probe before local stop, got order=%v", order)
	}

	// Remove must fail closed if relay is unreachable.
	rec, _, _ = st.Get("http-svc")
	if _, err := removeServiceAuthoritatively(st, rec, kp, "k1", serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 0, nil, errors.New("relay offline")
		},
	}); err == nil {
		t.Fatal("expected HTTP remove to fail closed when relay unreachable")
	}
	if _, ok, _ := st.Get("http-svc"); !ok {
		t.Fatal("HTTP service record deleted despite relay unreachable")
	}
}

func TestP2SupervisorNoShellExecutionAndSpacePaths(t *testing.T) {
	pub := renderPublisherUnitTemplate("/opt/my ocliv/bin/ocliv%1")
	be := renderBackendUnitTemplate("/opt/my ocliv/bin/ocliv%1")
	if strings.Contains(pub, "/bin/sh") || strings.Contains(be, "/bin/sh") {
		t.Fatalf("unit templates must not invoke /bin/sh:\npub=%s\nbe=%s", pub, be)
	}
	if !strings.Contains(pub, `ExecStart="/opt/my ocliv/bin/ocliv%%1" service run-publisher`) {
		t.Fatalf("expected systemd-quoted executable path in publisher unit, got:\n%s", pub)
	}
	if !strings.Contains(be, `ExecStart="/opt/my ocliv/bin/ocliv%%1" service run-backend`) {
		t.Fatalf("expected systemd-quoted executable path in backend unit, got:\n%s", be)
	}
}
