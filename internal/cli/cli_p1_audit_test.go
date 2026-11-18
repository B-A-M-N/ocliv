package cli

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/identity"
)

func TestServiceInstanceIsolationAndUnitTemplates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", "")

	i1, err := serviceInstanceID("default", "kontrol")
	if err != nil || !strings.HasPrefix(i1, "default--kontrol-") {
		t.Fatalf("i1=%q err=%v", i1, err)
	}
	i2, err := serviceInstanceID("staging", "kontrol")
	if err != nil || !strings.HasPrefix(i2, "staging--kontrol-") {
		t.Fatalf("i2=%q err=%v", i2, err)
	}
	if i1 == i2 {
		t.Fatal("default and staging instances collided")
	}
	c1, err := serviceInstanceID("a--b", "c")
	if err != nil {
		t.Fatalf("c1 err=%v", err)
	}
	c2, err := serviceInstanceID("a", "b--c")
	if err != nil {
		t.Fatalf("c2 err=%v", err)
	}
	if c1 == c2 {
		t.Fatalf("delimiter collision between (a--b, c) and (a, b--c): %q", c1)
	}
	if strings.Contains(userPublisherUnitTemplate, "OCLIV_LOCAL_URL") {
		t.Fatal("publisher unit template must not require OCLIV_LOCAL_URL (breaks stdio services)")
	}
	if !strings.Contains(userBackendUnitTemplate, "service run-backend") {
		t.Fatal("backend unit template must invoke `ocliv service run-backend` to preserve arg boundaries")
	}
}

func TestStopAlwaysStopsLocalOnRelayOutage(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	rec := config.ServiceRecord{
		Name:          "svc-outage",
		Type:          "mcp",
		BackendMode:   config.BackendAttached,
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       "default",
		RelayURL:      "https://relay.example",
		PublicationID: "pub-1",
		SystemdUnit:   "ocliv-publisher@default--svc-outage.service",
		DesiredState:  config.DesiredEnabled,
	}
	if err := st.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	kp, _ := identity.Generate()
	stoppedUnit := false
	unitState := "active"
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 0, nil, errors.New("relay offline")
		},
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "stop" {
				stoppedUnit = true
				unitState = "inactive"
				return "", nil
			}
			if len(args) >= 2 && args[0] == "is-active" {
				return unitState, nil
			}
			return "loaded", nil
		},
	}
	res := stopServiceAuthoritatively(st, rec, kp, "key-1", ops)
	if !stoppedUnit {
		t.Fatal("local unit was not stopped during relay outage")
	}
	if res.State != "STOP_UNCONFIRMED" {
		t.Fatalf("State=%q want STOP_UNCONFIRMED", res.State)
	}
}

func TestRemoveFailsClosedOnMissingRemoteOwnershipAndForgetLocalWorks(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	rec := config.ServiceRecord{
		Name:          "svc-stale",
		Type:          "mcp",
		BackendMode:   config.BackendAttached,
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       "default",
		RelayURL:      "https://relay.example",
		PublicationID: "pub-other-key",
		SystemdUnit:   "ocliv-publisher@default--svc-stale.service",
	}
	if err := st.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	kp, _ := identity.Generate()
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "is-enabled" {
				return "disabled", nil
			}
			return "inactive", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return 200, []byte(`{"publications":[]}`), nil
			}
			return 404, nil, nil
		},
	}
	if _, err := removeServiceAuthoritatively(st, rec, kp, "key-stale", ops); err == nil {
		t.Fatal("expected refusal when PublicationID is absent from authorized inventory")
	}
	if _, ok, _ := st.Get("svc-stale"); !ok {
		t.Fatal("local service record was deleted despite unverified ownership")
	}
	if err := forgetLocalService(st, rec, ops); err != nil {
		t.Fatalf("forgetLocalService: %v", err)
	}
	if _, ok, _ := st.Get("svc-stale"); ok {
		t.Fatal("local service record still exists after forgetLocalService")
	}
}

func TestHTTPServiceLifecycleAndStructuredUnitError(t *testing.T) {
	kp, _ := identity.Generate()
	rec := config.ServiceRecord{
		Name:         "web-ui",
		Type:         "http",
		BackendMode:  config.BackendAttached,
		LocalURL:     "http://127.0.0.1:3000",
		Profile:      "default",
		RelayURL:     "https://relay.example",
		SystemdUnit:  "ocliv-publisher@default--web-ui.service",
		DesiredState: config.DesiredEnabled,
	}
	calledMCPInventory := false
	ops2 := serviceOps{
		probeLoc: func(_ string, _ time.Duration) error { return nil },
		systemctl: func(_ ...string) (string, error) {
			return "Failed to connect to bus: No medium found", errors.New("exit 1")
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, path string) (int, []byte, error) {
			if strings.Contains(path, "mcp-routes") {
				calledMCPInventory = true
			}
			return 404, nil, nil
		},
	}
	// HTTP service status must not query MCP inventory, and D-Bus failure must not leak as raw ProcessState.
	rep := inspectServiceStatus(rec, kp, "key-1", ops2)
	if calledMCPInventory {
		t.Fatal("http service queried MCP route inventory")
	}
	if rep.ProcessState != "manager-unreachable" {
		t.Fatalf("ProcessState=%q, want manager-unreachable", rep.ProcessState)
	}
	_ = filepath.Join
}

func TestStopAndCleanupRefusesDeletionWhenStopUnconfirmed(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	rec := config.ServiceRecord{
		Name:        "sticky-svc",
		Type:        "mcp",
		LocalURL:    "http://127.0.0.1:8080/mcp",
		Profile:     "default",
		SystemdUnit: "ocliv-publisher@default--sticky-svc.service",
	}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) >= 1 && args[0] == "is-active" {
				return "active", nil
			}
			return "", nil
		},
	}
	err := stopAndCleanupLocalService(st, rec, ops)
	if err == nil || !strings.Contains(err.Error(), "STOP_UNCONFIRMED") {
		t.Fatalf("expected STOP_UNCONFIRMED error, got %v", err)
	}
	if _, ok, gerr := st.Get("sticky-svc"); gerr != nil || !ok {
		t.Fatalf("service record was deleted despite STOP_UNCONFIRMED (ok=%v err=%v)", ok, gerr)
	}
}

func TestRunPublisherRefusesDesiredConfigured(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	st := config.OpenServiceStore(cfgDir)
	if err := st.Put(config.ServiceRecord{
		Name:         "cfg-only",
		Type:         "mcp",
		LocalURL:     "http://127.0.0.1:8080/mcp",
		Profile:      "default",
		DesiredState: config.DesiredConfigured,
	}); err != nil {
		t.Fatal(err)
	}
	code := cmdServiceRunPublisher([]string{"--name", "cfg-only", "--profile", "default"})
	if code == 0 {
		t.Fatalf("expected non-zero refusal for DesiredConfigured, got %d", code)
	}
}

func TestValidEvidenceFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	base := config.VerificationEvidence{
		RouteID:         "r1",
		PublicURL:       "https://relay.example/r/r1/mcp",
		Stage:           "MCP_AUTHENTICATED",
		StateGeneration: 3,
		VerifiedAt:      now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
	}
	if !validEvidence(&base, "r1", "https://relay.example/r/r1/mcp", 3) {
		t.Fatal("expected valid evidence to pass")
	}
	noStage := base
	noStage.Stage = ""
	if validEvidence(&noStage, "r1", "https://relay.example/r/r1/mcp", 3) {
		t.Fatal("expected missing Stage to fail")
	}
	badStage := base
	badStage.Stage = "INVENTED_STAGE"
	if validEvidence(&badStage, "r1", "https://relay.example/r/r1/mcp", 3) {
		t.Fatal("expected untrusted Stage to fail")
	}
	futureVer := base
	futureVer.VerifiedAt = now.Add(2 * time.Minute).Format(time.RFC3339)
	if validEvidence(&futureVer, "r1", "https://relay.example/r/r1/mcp", 3) {
		t.Fatal("expected future-dated VerifiedAt to fail")
	}
	zeroGen := base
	zeroGen.StateGeneration = 0
	if validEvidence(&zeroGen, "r1", "https://relay.example/r/r1/mcp", 3) {
		t.Fatal("expected zero StateGeneration to fail")
	}
	noExpiry := base
	noExpiry.ExpiresAt = ""
	if validEvidence(&noExpiry, "r1", "https://relay.example/r/r1/mcp", 3) {
		t.Fatal("expected missing ExpiresAt to fail")
	}
	badVerified := base
	badVerified.VerifiedAt = "not-a-time"
	if validEvidence(&badVerified, "r1", "https://relay.example/r/r1/mcp", 3) {
		t.Fatal("expected unparsable VerifiedAt to fail")
	}
}

func TestReconcileServiceOnceRespectsTerminalFenceAndBackoff(t *testing.T) {
	st := config.OpenServiceStore(t.TempDir())
	kp, _ := identity.Generate()
	now := time.Now().UTC()

	// 1. Disabled service must never be restarted.
	_ = st.Put(config.ServiceRecord{
		Name: "svc-dis", Type: "mcp", LocalURL: "http://127.0.0.1:8080/mcp",
		Profile: "default", RelayURL: "https://relay.example",
		DesiredState: config.DesiredDisabled, SystemdUnit: "ocliv-publisher@svc-dis.service",
	})
	starts := 0
	ops := serviceOps{
		probeLoc: func(_ string, _ time.Duration) error { return nil },
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "start" {
				starts++
			}
			return "inactive", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[]}`), nil
		},
	}
	if _, err := reconcileServiceOnce(st, "svc-dis", kp, "k1", ops, now); err != nil {
		t.Fatal(err)
	}
	if starts != 0 {
		t.Fatalf("disabled service was restarted (%d starts)", starts)
	}

	// 2. Enabled but inactive service restarts once, then respects backoff.
	_ = st.Put(config.ServiceRecord{
		Name: "svc-en", Type: "mcp", LocalURL: "http://127.0.0.1:8080/mcp",
		Profile: "default", RelayURL: "https://relay.example", PublicationID: "pub-123",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@svc-en.service",
	})
	if _, err := reconcileServiceOnce(st, "svc-en", kp, "k1", ops, now); err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("expected 1 restart attempt, got %d", starts)
	}
	if _, err := reconcileServiceOnce(st, "svc-en", kp, "k1", ops, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("backoff was ignored: got %d starts", starts)
	}
}

func TestStopAndVerifyUnitRejectsUnreachableAndDisableFailure(t *testing.T) {
	// 1. Manager unreachable must return StoppedNow=false and retain record.
	st := config.OpenServiceStore(t.TempDir())
	rec := config.ServiceRecord{
		Name: "unreach-svc", Type: "mcp", LocalURL: "http://127.0.0.1:8080/mcp",
		Profile: "default", SystemdUnit: "ocliv-publisher@unreach-svc.service",
	}
	_ = st.Put(rec)
	unreachOps := serviceOps{
		systemctl: func(_ ...string) (string, error) {
			return "Failed to connect to bus: No medium found", errors.New("exit 1")
		},
	}
	if err := stopAndCleanupLocalService(st, rec, unreachOps); err == nil || !strings.Contains(err.Error(), "STOP_UNCONFIRMED") {
		t.Fatalf("expected STOP_UNCONFIRMED on unreachable manager, got %v", err)
	}
	if _, ok, _ := st.Get("unreach-svc"); !ok {
		t.Fatal("service record was deleted when systemd manager was unreachable")
	}

	// 2. Disable failure must return StoppedNow=true, DisabledForReboot=false, and retain record.
	disFailOps := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "is-active" {
				return "inactive", nil
			}
			if len(args) > 0 && args[0] == "disable" {
				return "permission denied", errors.New("exit 1")
			}
			return "loaded", nil
		},
	}
	if err := stopAndCleanupLocalService(st, rec, disFailOps); err == nil || !strings.Contains(err.Error(), "STOP_UNCONFIRMED") {
		t.Fatalf("expected STOP_UNCONFIRMED on disable failure, got %v", err)
	}
	if _, ok, _ := st.Get("unreach-svc"); !ok {
		t.Fatal("service record was deleted despite disable failure")
	}
}

func TestInspectUnitDoesNotTreatErrorsAsInactiveOrDisabled(t *testing.T) {
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "is-active" {
				return "garbage-output", errors.New("permission denied")
			}
			if len(args) > 0 && args[0] == "is-enabled" {
				return "timeout", errors.New("dbus timeout")
			}
			return "loaded", nil
		},
	}
	info := inspectUnit("ocliv-publisher@test.service", ops)
	if info.ActiveState != "unknown" {
		t.Fatalf("ActiveState=%q, want unknown on unexpected error", info.ActiveState)
	}
	if info.EnabledKnown {
		t.Fatal("expected EnabledKnown=false on is-enabled failure")
	}
	ev := stopAndVerifyUnit("ocliv-publisher@test.service", true, ops)
	if ev.StoppedNow || ev.DisabledForReboot {
		t.Fatalf("expected StoppedNow=false and DisabledForReboot=false on uncertain inspection: %+v", ev)
	}
}

func TestRunBackendRefusesDisabledAndConfigured(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	st := config.OpenServiceStore(cfgDir)
	for _, ds := range []string{config.DesiredConfigured, config.DesiredDisabled} {
		_ = st.Put(config.ServiceRecord{
			Name: "be-" + ds, Type: "mcp", BackendMode: config.BackendManaged,
			BackendExec: "/bin/true", LocalURL: "http://127.0.0.1:8080/mcp",
			Profile: "default", DesiredState: ds,
		})
		if code := cmdServiceRunBackend([]string{"--name", "be-" + ds, "--profile", "default"}); code == 0 {
			t.Fatalf("expected non-zero refusal for backend desired_state=%q", ds)
		}
	}
}

func TestEmergencyDisableSucceedsRemotelyWhenSupervisorBroken(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)
	seedEnrolledProfileForTest(t, "https://relay.example")
	st, _ := openServicesForProfile("default")
	_ = st.Put(config.ServiceRecord{
		Name: "emerg-svc", Type: "mcp", LocalURL: "http://127.0.0.1:8080/mcp",
		Profile: "default", RelayURL: "https://relay.example",
		PublicationID: "pub-emerg", PublicURL: "https://relay.example/r/pub-emerg/mcp",
		DesiredState: config.DesiredEnabled, SystemdUnit: "ocliv-publisher@emerg.service",
	})
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodPost && strings.HasSuffix(path, "/disable") {
				return 200, []byte(`{"desired_enabled":false,"state_generation":4,"session_live":false}`), nil
			}
			return 200, nil, nil
		},
		probePub: func(_ string, _ time.Duration) (int, error) { return http.StatusNotFound, nil },
		systemctl: func(_ ...string) (string, error) {
			return "Failed to connect to bus", errors.New("exit 1")
		},
	}
	if code := cmdServiceDisable([]string{"emerg-svc"}, ops); code != 0 {
		t.Fatalf("emergency disable exit=%d, want 0 when remote disable confirmed despite broken local supervisor", code)
	}
}
