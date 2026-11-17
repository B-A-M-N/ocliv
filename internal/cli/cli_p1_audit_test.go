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
	if err != nil || i1 != "default--kontrol" {
		t.Fatalf("i1=%q err=%v", i1, err)
	}
	i2, err := serviceInstanceID("staging", "kontrol")
	if err != nil || i2 != "staging--kontrol" {
		t.Fatalf("i2=%q err=%v", i2, err)
	}
	if i1 == i2 {
		t.Fatal("default and staging instances collided")
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
		systemctl: func(_ ...string) (string, error) { return "inactive", nil },
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
