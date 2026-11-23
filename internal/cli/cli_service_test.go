package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestServiceStoreAndPortUpdatePreservesIdentity(t *testing.T) {
	dir := t.TempDir()
	st := config.OpenServiceStore(dir)

	rec := config.ServiceRecord{
		Name:          "my-tools",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:3000/mcp",
		Auth:          "ocliv-managed",
		DesiredState:  config.DesiredConfigured,
		PublicationID: "route-abc",
		PublicURL:     "https://relay.test/r/route-abc/mcp",
	}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.Get("my-tools")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	if _, err := st.UpdateCAS("my-tools", got.Revision, func(r *config.ServiceRecord) error {
		r.LocalURL = "http://127.0.0.1:8765/mcp"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Stale revision must be rejected by UpdateCAS.
	if _, err := st.UpdateCAS("my-tools", got.Revision, func(r *config.ServiceRecord) error {
		r.LocalURL = "http://127.0.0.1:9999/mcp"
		return nil
	}); err == nil {
		t.Fatal("expected stale UpdateCAS to fail")
	}
	got2, ok, err := st.Get("my-tools")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if got2.PublicationID != "route-abc" || got2.PublicURL != "https://relay.test/r/route-abc/mcp" || got2.LocalURL != "http://127.0.0.1:8765/mcp" {
		t.Fatalf("unexpected updated record: %+v", got2)
	}
}

func TestStopServiceDisablesRelayBeforeStoppingProcess(t *testing.T) {
	dir := t.TempDir()
	st := config.OpenServiceStore(dir)
	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := string(kp.ID())

	rec := config.ServiceRecord{
		Name:          "svc1",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		RelayURL:      "https://relay.test",
		DesiredState:  config.DesiredEnabled,
		PublicationID: "pub-1",
		PublicURL:     "https://relay.test/r/pub-1/mcp",
		SystemdUnit:   "ocliv-publisher@svc1.service",
	}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	rec, _, _ = st.Get("svc1")

	var order []string
	opsOK := serviceOps{
		systemctl: func(args ...string) (string, error) {
			order = append(order, "systemctl:"+args[0])
			if args[0] == "show" {
				return "loaded", nil
			}
			if args[0] == "is-active" {
				return "inactive", nil
			}
			return "", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			order = append(order, "relay:"+method+":"+path)
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/pub-1/disable" {
				return http.StatusOK, []byte(`{"desired_enabled":false,"state_generation":2,"session_live":false}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		probePub: func(_ string, _ time.Duration) (int, error) {
			order = append(order, "probe")
			return http.StatusNotFound, nil
		},
	}
	res := stopServiceAuthoritatively(st, rec, kp, keyID, opsOK)
	if !res.Stopped || res.State != ServiceStateDisabled || res.RetainedURL != rec.PublicURL {
		t.Fatalf("unexpected stop result: %+v", res)
	}
	// Verify relay disable & public 404 probe ran BEFORE systemctl stop.
	if len(order) < 3 || order[0] != "relay:POST:/v1/agent/mcp-routes/pub-1/disable" || order[1] != "probe" {
		t.Fatalf("expected relay disable + probe before systemctl stop, got order=%v", order)
	}

	// Even if local systemctl stop fails/remains active, relay disable still ran first!
	relayDisabledOnStuckUnit := false
	opsStuckUnit := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if args[0] == "show" {
				return "loaded", nil
			}
			if args[0] == "is-active" {
				return "active", nil
			}
			return "stop failed", errors.New("exit 1")
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/pub-1/disable" {
				relayDisabledOnStuckUnit = true
				return http.StatusOK, []byte(`{"desired_enabled":false,"session_live":false}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		probePub: func(_ string, _ time.Duration) (int, error) {
			return http.StatusNotFound, nil
		},
	}
	rec, _, _ = st.Get("svc1")
	resStuck := stopServiceAuthoritatively(st, rec, kp, keyID, opsStuckUnit)
	if !relayDisabledOnStuckUnit {
		t.Fatal("relay disable was NOT called when local unit was stuck")
	}
	if resStuck.Stopped || resStuck.State != "STOP_UNCONFIRMED" {
		t.Fatalf("expected STOP_UNCONFIRMED when unit stuck active, got %+v", resStuck)
	}
}

func TestRemoveResolvesMissingPublicationIDAndFailsClosedWhenUnreachable(t *testing.T) {
	dir := t.TempDir()
	st := config.OpenServiceStore(dir)
	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := string(kp.ID())

	rec := config.ServiceRecord{
		Name:         "svc-fg",
		Type:         "mcp",
		LocalURL:     "http://127.0.0.1:8765/mcp",
		Auth:         "ocliv-managed",
		RelayURL:     "https://relay.test",
		DesiredState: config.DesiredEnabled,
		// PublicationID intentionally empty (e.g. foreground run)
	}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}

	// 1. Relay unreachable -> must NOT delete local record!
	opsDown := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 0, nil, errors.New("connection refused")
		},
	}
	if _, err := removeServiceAuthoritatively(st, rec, kp, keyID, opsDown); err == nil {
		t.Fatal("expected error when relay unreachable during remove")
	}
	if _, ok, _ := st.Get("svc-fg"); !ok {
		t.Fatal("local service record was deleted despite unreachable relay")
	}

	// 2. Relay returns matching publication -> must DELETE remote route before local record.
	deletedRemote := false
	opsOK := serviceOps{
		systemctl: func(_ ...string) (string, error) { return "inactive", nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				if deletedRemote {
					return 200, []byte(`{"publications":[]}`), nil
				}
				return 200, []byte(`{"publications":[{"route_id":"pub-fg-1","pub_name":"svc-fg","profile":"managed-oauth"}]}`), nil
			}
			if method == http.MethodDelete && path == "/v1/agent/mcp-routes/pub-fg-1" {
				deletedRemote = true
				return 200, []byte(`{"status":"deleted"}`), nil
			}
			return 404, nil, nil
		},
	}
	pubID, err := removeServiceAuthoritatively(st, rec, kp, keyID, opsOK)
	if err != nil {
		t.Fatalf("unexpected remove error: %v", err)
	}
	if pubID != "pub-fg-1" || !deletedRemote {
		t.Fatalf("expected pub-fg-1 to be resolved and deleted, got pubID=%q deleted=%v", pubID, deletedRemote)
	}
	if _, ok, _ := st.Get("svc-fg"); ok {
		t.Fatal("local record still exists after confirmed removal")
	}
}

func TestProvisionUserSupervisorWritesRestrictedUnitAndEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_CONFIG_DIR", "")

	rec := config.ServiceRecord{
		Name:        "agentgateway",
		Type:        "mcp",
		BackendMode: config.BackendAttached,
		LocalURL:    "http://127.0.0.1:8765/mcp",
		Auth:        "ocliv-managed",
		RelayURL:    "https://bamnlabs.dynv6.net",
		Profile:     "default",
	}
	reloaded := false
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "daemon-reload" {
				reloaded = true
			}
			return "", nil
		},
	}
	if err := provisionUserSupervisor(rec, ops); err != nil {
		t.Fatalf("provisionUserSupervisor failed: %v", err)
	}
	if !reloaded {
		t.Fatal("expected systemctl daemon-reload to run")
	}
	inst, err := serviceInstanceID("default", "agentgateway")
	if err != nil {
		t.Fatalf("serviceInstanceID: %v", err)
	}
	envPath := filepath.Join(home, ".config", "ocliv", "service-"+inst+".env")
	fi, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("missing env file: %v", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("env file permissions too permissive: %v", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(envPath)
	if !strings.Contains(string(raw), "OCLIV_RELAY_URL=https://bamnlabs.dynv6.net") {
		t.Fatalf("unexpected env file content: %s", raw)
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", "ocliv-publisher@.service")
	if _, err := os.Stat(unitPath); err != nil {
		t.Fatalf("missing user systemd unit: %v", err)
	}
}

func TestInspectServiceStatusStateMatrix(t *testing.T) {
	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := string(kp.ID())

	baseRec := config.ServiceRecord{
		Name:          "svc1",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		RelayURL:      "https://relay.test",
		DesiredState:  config.DesiredEnabled,
		PublicationID: "pub-1",
		PublicURL:     "https://relay.test/r/pub-1/mcp",
		SystemdUnit:   "ocliv-publisher@svc1.service",
	}

	invJSON := func(pubState string, desired, live bool, admission, reason string) []byte {
		b, _ := json.Marshal(map[string]any{
			"publications": []map[string]any{{
				"route_id":          "pub-1",
				"pub_name":          "svc1",
				"profile":           "managed-oauth",
				"url":               "https://relay.test/r/pub-1/mcp",
				"lease_id":          "lse-1",
				"publication_state": pubState,
				"desired_enabled":   desired,
				"session_live":      live,
				"admission":         admission,
				"admission_reason":  reason,
			}},
		})
		return b
	}

	// 1. SERVING + READY (PublicTransport=true, PublicVerified=false until externally verified)
	rep := inspectServiceStatus(baseRec, kp, keyID, serviceOps{
		systemctl: func(args ...string) (string, error) {
			if args[0] == "show" {
				return "loaded", nil
			}
			return "active", nil
		},
		probeLoc: func(_ string, _ time.Duration) error { return nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, invJSON("VERIFIED", true, true, "READY", "READY"), nil
		},
		probePub: func(_ string, _ time.Duration) (int, error) { return 401, nil },
	})
	if rep.State != ServiceStateServing || rep.Health != HealthReady || !rep.PublicTransport || rep.PublicVerified {
		t.Fatalf("expected SERVING/READY/transport=true/verified=false, got %+v", rep)
	}

	// 2. FAULTED + FAILED when unit not-found
	repFault := inspectServiceStatus(baseRec, kp, keyID, serviceOps{
		systemctl: func(args ...string) (string, error) {
			if args[0] == "show" {
				return "not-found", nil
			}
			return "inactive", nil
		},
		probeLoc: func(_ string, _ time.Duration) error { return nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, invJSON("VERIFIED", true, false, "BLOCKED", "LEASE_OFFLINE"), nil
		},
	})
	if repFault.State != ServiceStateFaulted || repFault.Health != HealthFailed || repFault.ProcessState != "not-found" {
		t.Fatalf("expected FAULTED/FAILED/not-found, got %+v", repFault)
	}
}
