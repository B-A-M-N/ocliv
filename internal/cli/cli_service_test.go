package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/identity"
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
	// Move local backend port from 3000 to 8765: name and publication identity stay identical.
	got, ok, err := st.Get("my-tools")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	got.LocalURL = "http://127.0.0.1:8765/mcp"
	if err := st.Put(got); err != nil {
		t.Fatal(err)
	}
	got2, ok, err := st.Get("my-tools")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if got2.PublicationID != "route-abc" || got2.PublicURL != "https://relay.test/r/route-abc/mcp" || got2.LocalURL != "http://127.0.0.1:8765/mcp" {
		t.Fatalf("unexpected updated record: %+v", got2)
	}
}

func TestStopServiceAuthoritativeAndFailClosed(t *testing.T) {
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

	// Case 1: Full confirmation -> STOPPED, route retained, desired_state=disabled.
	opsOK := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if args[0] == "is-active" {
				return "inactive", nil
			}
			return "", nil
		},
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/pub-1/disable" {
				return http.StatusOK, []byte(`{"desired_enabled":false,"session_live":false}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		probePub: func(_ string, _ time.Duration) (int, error) {
			return http.StatusNotFound, nil
		},
	}
	res := stopServiceAuthoritatively(st, rec, kp, keyID, opsOK)
	if !res.Stopped || res.State != ServiceStateDisabled || res.RetainedURL != rec.PublicURL {
		t.Fatalf("unexpected stop result: %+v", res)
	}
	saved, _, _ := st.Get("svc1")
	if saved.DesiredState != config.DesiredDisabled {
		t.Fatalf("desired_state=%q, want disabled", saved.DesiredState)
	}

	// Case 2: Relay unreachable -> UNKNOWN, stopped=false.
	opsUnreachable := opsOK
	opsUnreachable.mgmtCall = func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
		return 0, nil, errors.New("connection refused")
	}
	res2 := stopServiceAuthoritatively(st, rec, kp, keyID, opsUnreachable)
	if res2.Stopped || res2.State != ServiceStateUnknown {
		t.Fatalf("expected UNKNOWN/stopped=false when relay unreachable, got %+v", res2)
	}

	// Case 3: Public route still returns 401 -> STOP_UNCONFIRMED, stopped=false.
	opsLeaking := opsOK
	opsLeaking.probePub = func(_ string, _ time.Duration) (int, error) {
		return http.StatusUnauthorized, nil
	}
	res3 := stopServiceAuthoritatively(st, rec, kp, keyID, opsLeaking)
	if res3.Stopped || res3.State != "STOP_UNCONFIRMED" {
		t.Fatalf("expected STOP_UNCONFIRMED when public route still answers 401, got %+v", res3)
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

	// 1. SERVING + READY
	rep := inspectServiceStatus(baseRec, kp, keyID, serviceOps{
		systemctl: func(_ ...string) (string, error) { return "active", nil },
		probeLoc:  func(_ string, _ time.Duration) error { return nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, invJSON("VERIFIED", true, true, "READY", "READY"), nil
		},
		probePub: func(_ string, _ time.Duration) (int, error) { return 401, nil },
	})
	if rep.State != ServiceStateServing || rep.Health != HealthReady {
		t.Fatalf("expected SERVING/READY, got %+v", rep)
	}

	// 2. FAULTED + FAILED when unit failed
	repFault := inspectServiceStatus(baseRec, kp, keyID, serviceOps{
		systemctl: func(_ ...string) (string, error) { return "failed", errors.New("exit 1") },
		probeLoc:  func(_ string, _ time.Duration) error { return nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, invJSON("VERIFIED", true, false, "BLOCKED", "LEASE_OFFLINE"), nil
		},
	})
	if repFault.State != ServiceStateFaulted || repFault.Health != HealthFailed {
		t.Fatalf("expected FAULTED/FAILED, got %+v", repFault)
	}

	// 3. REVOKED + BLOCKED
	repRev := inspectServiceStatus(baseRec, kp, keyID, serviceOps{
		systemctl: func(_ ...string) (string, error) { return "inactive", nil },
		probeLoc:  func(_ string, _ time.Duration) error { return nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, invJSON("REVOKED", true, false, "BLOCKED", "PUBLICATION_REVOKED"), nil
		},
	})
	if repRev.State != ServiceStateRevoked || repRev.Health != HealthBlocked {
		t.Fatalf("expected REVOKED/BLOCKED, got %+v", repRev)
	}

	// 4. UNKNOWN + UNKNOWN when relay unreachable
	repUnk := inspectServiceStatus(baseRec, kp, keyID, serviceOps{
		systemctl: func(_ ...string) (string, error) { return "active", nil },
		probeLoc:  func(_ string, _ time.Duration) error { return nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 0, nil, errors.New("timeout")
		},
	})
	if repUnk.State != ServiceStateUnknown || repUnk.Health != HealthUnknown {
		t.Fatalf("expected UNKNOWN/UNKNOWN, got %+v", repUnk)
	}
}
