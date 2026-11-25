package cli

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func strPtr(s string) *string { return &s }

func TestCanonicalResolverExplicitRouteIDPrecedence(t *testing.T) {
	pubs := []relayPublication{
		{
			RouteID:          "ZmVsWJpoGX8yC3Jcc42M5A",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			PublicationState: "VERIFIED",
			DesiredEnabled:   true,
			HostBinding:      "MISMATCH",
			Admission:        "BLOCKED",
			AdmissionReason:  "HOST_MISMATCH",
		},
		{
			RouteID:          "jr8x2Txyoa1jPs22CROuBQ",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			URL:              strPtr("https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp"),
			PublicationState: "VERIFIED",
			DesiredEnabled:   true,
			SessionLive:      true,
			HostBinding:      "VALID",
			Admission:        "READY",
			AdmissionReason:  "READY",
		},
	}

	// Explicit route ID resolves ONLY that exact ID, even if HOST_MISMATCH.
	res := resolvePublicationFromInventory("ZmVsWJpoGX8yC3Jcc42M5A", nil, pubs)
	if res.Status != ResolutionExactID || res.Publication == nil || res.Publication.RouteID != "ZmVsWJpoGX8yC3Jcc42M5A" {
		t.Fatalf("expected EXACT_ID for ZmVsWJpoGX8yC3Jcc42M5A, got %+v", res)
	}

	res2 := resolvePublicationFromInventory("jr8x2Txyoa1jPs22CROuBQ", nil, pubs)
	if res2.Status != ResolutionExactID || res2.Publication == nil || res2.Publication.RouteID != "jr8x2Txyoa1jPs22CROuBQ" {
		t.Fatalf("expected EXACT_ID for jr8x2Txyoa1jPs22CROuBQ, got %+v", res2)
	}
}

func TestCanonicalResolverValidBindingPrecedenceAndDisabledRetention(t *testing.T) {
	pubs := []relayPublication{
		{
			RouteID:          "route-disabled-bound",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			URL:              strPtr("https://bamnlabs.duckdns.org/r/route-disabled-bound/mcp"),
			PublicationState: "DISABLED",
			DesiredEnabled:   false,
			SessionLive:      false,
			HostBinding:      "VALID",
			Admission:        "BLOCKED",
			AdmissionReason:  "PUBLICATION_DISABLED",
		},
		{
			RouteID:          "route-online-other",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			URL:              strPtr("https://bamnlabs.duckdns.org/r/route-online-other/mcp"),
			PublicationState: "VERIFIED",
			DesiredEnabled:   true,
			SessionLive:      true,
			HostBinding:      "VALID",
			Admission:        "READY",
			AdmissionReason:  "READY",
		},
	}

	rec := &config.ServiceRecord{
		Name:          "agentgateway",
		Auth:          "ocliv-managed",
		PublicationID: "route-disabled-bound",
	}
	res := resolvePublicationFromInventory("agentgateway", rec, pubs)
	if res.Status != ResolutionBoundValid || res.Publication == nil || res.Publication.RouteID != "route-disabled-bound" {
		t.Fatalf("valid disabled binding must retain identity over online sibling, got %+v", res)
	}
}

func TestCanonicalResolverStaleOrMissingBindingIgnoresHistoricalHostMismatch(t *testing.T) {
	pubs := []relayPublication{
		{
			RouteID:          "ZmVsWJpoGX8yC3Jcc42M5A",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			PublicationState: "VERIFIED",
			DesiredEnabled:   true,
			HostBinding:      "MISMATCH",
			Admission:        "BLOCKED",
			AdmissionReason:  "HOST_MISMATCH",
		},
		{
			RouteID:          "revoked-old-route",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			PublicationState: "REVOKED",
			RevokedAt:        strPtr("2026-11-01T00:00:00Z"),
			HostBinding:      "VALID",
			Admission:        "BLOCKED",
			AdmissionReason:  "PUBLICATION_REVOKED",
		},
		{
			RouteID:          "jr8x2Txyoa1jPs22CROuBQ",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			URL:              strPtr("https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp"),
			PublicationState: "VERIFIED",
			DesiredEnabled:   true,
			SessionLive:      true,
			HostBinding:      "VALID",
			Admission:        "READY",
			AdmissionReason:  "READY",
		},
	}

	// Case A: Unbound local record.
	resMissing := resolvePublicationFromInventory("agentgateway", &config.ServiceRecord{
		Name: "agentgateway",
		Auth: "ocliv-managed",
	}, pubs)
	if resMissing.Status != ResolutionRecoveredUnique || resMissing.Publication == nil || resMissing.Publication.RouteID != "jr8x2Txyoa1jPs22CROuBQ" {
		t.Fatalf("expected unique recovery to jr8x2Txyoa1jPs22CROuBQ, got %+v", resMissing)
	}

	// Case B: Stale local binding pointing to HOST_MISMATCH historical route.
	resStale := resolvePublicationFromInventory("agentgateway", &config.ServiceRecord{
		Name:          "agentgateway",
		Auth:          "ocliv-managed",
		PublicationID: "ZmVsWJpoGX8yC3Jcc42M5A",
	}, pubs)
	if resStale.Status != ResolutionRecoveredUnique || resStale.Publication == nil || resStale.Publication.RouteID != "jr8x2Txyoa1jPs22CROuBQ" {
		t.Fatalf("expected stale HOST_MISMATCH binding to uniquely recover to jr8x2Txyoa1jPs22CROuBQ, got %+v", resStale)
	}
	if resStale.PreviousBindingID != "ZmVsWJpoGX8yC3Jcc42M5A" {
		t.Fatalf("expected PreviousBindingID=ZmVsWJpoGX8yC3Jcc42M5A, got %q", resStale.PreviousBindingID)
	}
}

func TestCanonicalResolverFailsClosedOnGenuineAmbiguity(t *testing.T) {
	pubs := []relayPublication{
		{
			RouteID:          "route-valid-disabled",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			URL:              strPtr("https://bamnlabs.duckdns.org/r/route-valid-disabled/mcp"),
			PublicationState: "DISABLED",
			DesiredEnabled:   false,
			SessionLive:      false,
			HostBinding:      "VALID",
			Admission:        "BLOCKED",
			AdmissionReason:  "PUBLICATION_DISABLED",
		},
		{
			RouteID:          "route-valid-online",
			Name:             "agentgateway",
			Profile:          "managed-oauth",
			URL:              strPtr("https://bamnlabs.duckdns.org/r/route-valid-online/mcp"),
			PublicationState: "VERIFIED",
			DesiredEnabled:   true,
			SessionLive:      true,
			HostBinding:      "VALID",
			Admission:        "READY",
			AdmissionReason:  "READY",
		},
	}

	// Unbound lookup MUST fail closed rather than blindly choosing the online route.
	res := resolvePublicationFromInventory("agentgateway", &config.ServiceRecord{
		Name: "agentgateway",
		Auth: "ocliv-managed",
	}, pubs)
	if res.Status != ResolutionAmbiguous || res.Found() || !res.IsPermanentConflict() {
		t.Fatalf("expected ResolutionAmbiguous fail-closed, got %+v", res)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("expected 2 ambiguous candidates, got %d", len(res.Candidates))
	}
}

func TestReconcileAtomicBindingRepairConsolidatesStubAndStopsRetryLoop(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://bamnlabs.duckdns.org")
	k, keyID, kerr := loadKeyForProfile(config.ActiveProfile())
	if kerr != nil {
		t.Fatalf("loadKeyForProfile: %v", kerr)
	}
	store, err := openServices()
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := store.Put(config.ServiceRecord{
		Name:          "agentgateway",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:3000/mcp",
		Auth:          "ocliv-managed",
		Profile:       config.ActiveProfile(),
		RelayURL:      "https://bamnlabs.duckdns.org",
		DesiredState:  config.DesiredEnabled,
		SystemdUnit:   "ocliv-publisher@agentgateway.service",
		BackendUnit:   "ocliv-backend@agentgateway.service",
		PublicationID: "",
		PublicURL:     "",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     "svc_agentgateway_orig",
			Name:          "agentgateway",
			OwnerKeyID:    keyID,
			RelayID:       relayAuthority("https://bamnlabs.duckdns.org"),
		},
		Reconcile: &config.ReconcileStatus{
			Attempt:       1494,
			LastErrorCode: "TRANSIENT_NOT_SERVING",
		},
	}); err != nil {
		t.Fatalf("put agentgateway: %v", err)
	}
	// Seed redundant route-ID-named stub record holding live Google provider binding.
	if err := store.Put(config.ServiceRecord{
		Name:          "jr8x2Txyoa1jPs22CROuBQ",
		Type:          "mcp",
		Auth:          "ocliv-managed",
		Profile:       config.ActiveProfile(),
		PublicationID: "jr8x2Txyoa1jPs22CROuBQ",
		PublicURL:     "https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp",
		DesiredState:  config.DesiredConfigured,
		ProviderBindings: map[string]config.ProviderBinding{
			"google": {
				ClientID: "cli_google_live",
				AuthMode: "confidential+google_confidential",
				Status:   "active",
			},
		},
	}); err != nil {
		t.Fatalf("put stub record: %v", err)
	}

	invBody, _ := json.Marshal(map[string]any{
		"publications": []relayPublication{
			{
				RouteID:          "ZmVsWJpoGX8yC3Jcc42M5A",
				Name:             "agentgateway",
				Profile:          "managed-oauth",
				PublicationState: "VERIFIED",
				DesiredEnabled:   true,
				HostBinding:      "MISMATCH",
				Admission:        "BLOCKED",
				AdmissionReason:  "HOST_MISMATCH",
			},
			{
				RouteID:          "jr8x2Txyoa1jPs22CROuBQ",
				Name:             "agentgateway",
				Profile:          "managed-oauth",
				URL:              strPtr("https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp"),
				LeaseID:          strPtr("lease-live-1"),
				PublicationState: "VERIFIED",
				DesiredEnabled:   true,
				StateGeneration:  4,
				SessionLive:      true,
				HostBinding:      "VALID",
				Admission:        "READY",
				AdmissionReason:  "READY",
			},
		},
	})

	restartCalled := false
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "restart" {
				restartCalled = true
			}
			return "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n", nil
		},
		probeLoc: func(string, time.Duration) error { return nil },
		probePub: func(string, time.Duration) (int, error) { return http.StatusUnauthorized, nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, invBody, nil
			}
			if method == http.MethodGet && path == "/v1/agent/mcp-routes/jr8x2Txyoa1jPs22CROuBQ/authz/pending" {
				return http.StatusOK, []byte(`{"pending":[],"pending_transactions":[]}`), nil
			}
			return http.StatusNotFound, []byte("not found"), nil
		},
	}

	rep, err := reconcileServiceOnce(store, "agentgateway", k, keyID, ops, time.Now())
	if err != nil {
		t.Fatalf("reconcileServiceOnce: %v", err)
	}
	if restartCalled {
		t.Fatal("reconcile must NOT restart a healthy live tunnel during binding repair")
	}
	if rep.State != ServiceStateServing || rep.Health != HealthReady {
		t.Fatalf("expected SERVING/READY, got state=%s health=%s detail=%s", rep.State, rep.Health, rep.IngressDetail)
	}
	if rep.PublicationID != "jr8x2Txyoa1jPs22CROuBQ" {
		t.Fatalf("expected PublicationID=jr8x2Txyoa1jPs22CROuBQ, got %q", rep.PublicationID)
	}

	// Verify persisted ServiceRecord.
	updated, ok, err := store.Get("agentgateway")
	if err != nil || !ok {
		t.Fatalf("reload agentgateway: ok=%v err=%v", ok, err)
	}
	if updated.PublicationID != "jr8x2Txyoa1jPs22CROuBQ" {
		t.Fatalf("persisted PublicationID=%q, want jr8x2Txyoa1jPs22CROuBQ", updated.PublicationID)
	}
	if updated.PublicURL != "https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp" {
		t.Fatalf("persisted PublicURL=%q", updated.PublicURL)
	}
	if updated.Identity == nil || updated.Identity.ServiceID != "svc_agentgateway_orig" || updated.Identity.PublicationID != "jr8x2Txyoa1jPs22CROuBQ" {
		t.Fatalf("identity not preserved/updated: %+v", updated.Identity)
	}
	if updated.ProviderBindings["google"].ClientID != "cli_google_live" {
		t.Fatalf("google provider binding was not preserved from stub: %+v", updated.ProviderBindings)
	}
	if updated.Reconcile == nil || updated.Reconcile.Attempt != 0 || updated.Reconcile.LastConfirmedStage != "SERVING" {
		t.Fatalf("reconcile status not reset: %+v", updated.Reconcile)
	}
	// Redundant stub must have been consolidated and removed.
	if _, stubExists, _ := store.Get("jr8x2Txyoa1jPs22CROuBQ"); stubExists {
		t.Fatal("redundant route-ID stub record was not removed after consolidation")
	}

	// Verify `ocliv mcp url`, `ocliv service pending`, and `ocliv service approve` all resolve cleanly by service name.
	entry, code := resolveCatalogEntry("agentgateway", config.ActiveProfile(), ops)
	if code != apperr.ExitOK || entry.RouteID != "jr8x2Txyoa1jPs22CROuBQ" {
		t.Fatalf("resolveCatalogEntry(agentgateway) code=%d entry=%+v", code, entry)
	}
	if code := cmdServicePending([]string{"agentgateway", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("cmdServicePending(agentgateway) exit=%d, want 0", code)
	}
	if code := cmdServiceApprove([]string{"agentgateway", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("cmdServiceApprove(agentgateway) exit=%d, want 0", code)
	}
}

func TestReconcileStopsInfiniteRetriesOnPermanentHostMismatchAndAmbiguity(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://bamnlabs.duckdns.org")
	k, keyID, kerr := loadKeyForProfile(config.ActiveProfile())
	if kerr != nil {
		t.Fatalf("loadKeyForProfile: %v", kerr)
	}
	store, err := openServices()
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := store.Put(config.ServiceRecord{
		Name:          "mismatch-svc",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:3000/mcp",
		Auth:          "ocliv-managed",
		Profile:       config.ActiveProfile(),
		RelayURL:      "https://bamnlabs.duckdns.org",
		DesiredState:  config.DesiredEnabled,
		SystemdUnit:   "ocliv-publisher@mismatch-svc.service",
		PublicationID: "ZmVsWJpoGX8yC3Jcc42M5A",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     "svc_mismatch",
			Name:          "mismatch-svc",
			OwnerKeyID:    keyID,
			RelayID:       relayAuthority("https://bamnlabs.duckdns.org"),
			PublicationID: "ZmVsWJpoGX8yC3Jcc42M5A",
		},
	}); err != nil {
		t.Fatalf("put mismatch-svc: %v", err)
	}

	invBody, _ := json.Marshal(map[string]any{
		"publications": []relayPublication{
			{
				RouteID:          "ZmVsWJpoGX8yC3Jcc42M5A",
				Name:             "mismatch-svc",
				Profile:          "managed-oauth",
				Host:             "old.example.org",
				PublicationState: "VERIFIED",
				DesiredEnabled:   true,
				HostBinding:      "MISMATCH",
				Admission:        "BLOCKED",
				AdmissionReason:  "HOST_MISMATCH",
			},
		},
	})

	restartCalled := false
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "restart" {
				restartCalled = true
			}
			return "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n", nil
		},
		probeLoc: func(string, time.Duration) error { return nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, invBody, nil
			}
			return http.StatusNotFound, []byte("not found"), nil
		},
	}

	rep, err := reconcileServiceOnce(store, "mismatch-svc", k, keyID, ops, time.Now())
	if err != nil {
		t.Fatalf("reconcileServiceOnce: %v", err)
	}
	if restartCalled {
		t.Fatal("reconcile must NOT restart on permanent HOST_MISMATCH")
	}
	if rep.Health != HealthBlocked || rep.Layers.Publication != "host_mismatch" {
		t.Fatalf("expected HealthBlocked/host_mismatch, got health=%s layer=%s", rep.Health, rep.Layers.Publication)
	}
	rec, _, _ := store.Get("mismatch-svc")
	if rec.Reconcile == nil || !rec.Reconcile.Terminal || rec.Reconcile.ErrorClassification != "terminal" || rec.Reconcile.LastErrorCode != "TERMINAL_HOST_MISMATCH" {
		t.Fatalf("expected terminal HOST_MISMATCH classification (no retry loop), got %+v", rec.Reconcile)
	}
	if rec.Reconcile.Attempt != 0 {
		t.Fatalf("terminal conflict must not increment retry attempts, got attempt=%d", rec.Reconcile.Attempt)
	}
}
