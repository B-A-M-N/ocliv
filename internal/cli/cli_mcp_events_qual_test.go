package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestQualifyMCPEventsReadOnlyCatalogAndSubscription(t *testing.T) {
	const validTok = "tok-events-qual-secret-999"
	var unsubCalled atomic.Bool
	var pubEvents = []string{"job.completed", "build.failed"}
	var localEvents = []string{"build.failed", "job.completed"} // unsorted on wire, same canonical set

	var srvURL string
	newEventsHandler := func(requireAuth bool, catalog *[]string, deliverCallback bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource/r/ev1/mcp":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/ev1/mcp","authorization_servers":["` + srvURL + `/r/ev1/oauth"]}`))
				return
			case "/.well-known/oauth-authorization-server/r/ev1/oauth":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"issuer":"` + srvURL + `/r/ev1/oauth","authorization_endpoint":"` + srvURL + `/r/ev1/oauth/authorize","token_endpoint":"` + srvURL + `/r/ev1/oauth/token","registration_endpoint":"` + srvURL + `/r/ev1/oauth/register","code_challenge_methods_supported":["S256"]}`))
				return
			}
			if requireAuth && r.Header.Get("Authorization") != "Bearer "+validTok {
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srvURL+`/.well-known/oauth-protected-resource/r/ev1/mcp"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var req struct {
				ID     any            `json:"id"`
				Method string         `json:"method"`
				Params map[string]any `json:"params"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			switch req.Method {
			case "tools/list":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]any{"protocolVersion": "2026-07-28", "tools": []any{map[string]any{"name": "status"}}},
				})
			case "server/discover":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]any{
						"protocolVersion": "2026-07-28",
						"capabilities":    map[string]any{"events": map[string]any{"list": true, "subscribe": true}},
					},
				})
			case "events/list":
				evList := make([]map[string]any, 0, len(*catalog))
				for _, name := range *catalog {
					evList = append(evList, map[string]any{"name": name})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]any{"events": evList},
				})
			case "events/subscribe":
				cbURL, _ := req.Params["callbackUrl"].(string)
				cbSec, _ := req.Params["callbackSecret"].(string)
				if deliverCallback && cbURL != "" {
					go func() {
						// First send an unauthenticated callback to prove receiver rejects it.
						badReq, _ := http.NewRequest(http.MethodPost, cbURL, bytes.NewReader([]byte(`{"event":"forged"}`)))
						badReq.Header.Set("X-Ocliv-Callback-Secret", "wrong-secret")
						if resp, err := http.DefaultClient.Do(badReq); err == nil {
							_ = resp.Body.Close()
						}
						// Send an uncorrelated callback with wrong subscriptionId first (must be ignored).
						wrongSubReq, _ := http.NewRequest(http.MethodPost, cbURL, bytes.NewReader([]byte(`{"subscriptionId":"sub_other","event":"build.failed"}`)))
						wrongSubReq.Header.Set("Content-Type", "application/json")
						wrongSubReq.Header.Set("X-Ocliv-Callback-Secret", cbSec)
						if resp, err := http.DefaultClient.Do(wrongSubReq); err == nil {
							_ = resp.Body.Close()
						}
						// Then send the correlated authenticated callback.
						goodReq, _ := http.NewRequest(http.MethodPost, cbURL, bytes.NewReader([]byte(`{"subscriptionId":"sub_12345","event":"build.failed"}`)))
						goodReq.Header.Set("Content-Type", "application/json")
						goodReq.Header.Set("X-Ocliv-Callback-Secret", cbSec)
						if resp, err := http.DefaultClient.Do(goodReq); err == nil {
							_ = resp.Body.Close()
						}
					}()
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]any{"subscriptionId": "sub_12345"},
				})
			case "events/unsubscribe":
				if req.Params["subscriptionId"] == "sub_12345" {
					unsubCalled.Store(true)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]any{"unsubscribed": true},
				})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]any{"code": -32601, "message": "Method not found"},
				})
			}
		})
	}

	pubSrv := httptest.NewTLSServer(newEventsHandler(true, &pubEvents, true))
	defer pubSrv.Close()
	srvURL = pubSrv.URL

	localSrv := httptest.NewServer(newEventsHandler(false, &localEvents, false))
	defer localSrv.Close()

	pubEP, _ := url.Parse(srvURL + "/r/ev1/mcp")
	locEP, _ := url.Parse(localSrv.URL + "/mcp")

	// 1. Default read-only Events qualification: must NOT subscribe.
	ro := QualifyMCPEvents(MCPEventsQualificationConfig{
		PublicEndpoint: pubEP,
		LocalEndpoint:  locEP,
		AuthMode:       "mcp_managed_oauth",
		BearerToken:    validTok,
		Client:         pubSrv.Client(),
		LocalClient:    localSrv.Client(),
	})
	if !ro.OK() {
		t.Fatalf("read-only events qualification failed: %+v", ro)
	}
	if ro.AnonymousAuthorization != "PASS" || ro.InvalidTokenRejection != "PASS" ||
		ro.ServerDiscovery != "PASS" || ro.EventsAdvertised != "PASS" ||
		ro.EventsList != "PASS" || ro.CapabilityConsistency != "PASS" {
		t.Fatalf("unexpected read-only stages: %+v", ro)
	}
	if ro.Subscription != "NOT_REQUESTED" || ro.CallbackDelivery != "NOT_REQUESTED" {
		t.Fatalf("read-only qualification must not subscribe: %+v", ro)
	}
	if ro.HostSubscription != "UNVERIFIED" || ro.HostEventConsumption != "UNVERIFIED" {
		t.Fatalf("synthetic qualification must not claim host subscription/consumption: %+v", ro)
	}

	// 2. Explicit opt-in subscription + authenticated callback qualification + cleanup.
	subRes := QualifyMCPEvents(MCPEventsQualificationConfig{
		PublicEndpoint:      pubEP,
		LocalEndpoint:       locEP,
		AuthMode:            "mcp_managed_oauth",
		BearerToken:         validTok,
		Client:              pubSrv.Client(),
		LocalClient:         localSrv.Client(),
		QualifySubscription: true,
		SubscriptionTTL:     15 * time.Second,
		CallbackTimeout:     3 * time.Second,
	})
	if !subRes.OK() || subRes.Subscription != "PASS" || subRes.CallbackDelivery != "PASS" || subRes.SubscriptionCleanup != "PASS" {
		t.Fatalf("subscription qualification failed: %+v", subRes)
	}
	if subRes.QualificationLevel != EventsStageSubscriptionCleanupVerified {
		t.Fatalf("expected level %s, got %s", EventsStageSubscriptionCleanupVerified, subRes.QualificationLevel)
	}
	if !unsubCalled.Load() {
		t.Fatal("expected events/unsubscribe cleanup after subscription qualification")
	}
	if !slices.Contains(subRes.ObservedOutcomes, EventsStageSubscriptionVerified) ||
		!slices.Contains(subRes.ObservedOutcomes, EventsStageCallbackDeliveryVerified) {
		t.Fatalf("missing expected subscription outcomes: %v", subRes.ObservedOutcomes)
	}
	if slices.Contains(subRes.ObservedOutcomes, EventsStageHostSubscriptionObserved) ||
		slices.Contains(subRes.ObservedOutcomes, EventsStageHostConsumptionVerified) {
		t.Fatalf("synthetic subscription test must never claim host outcomes: %v", subRes.ObservedOutcomes)
	}

	// 3. Catalog divergence between local and public must fail consistency check.
	var mu sync.Mutex
	mu.Lock()
	localEvents = []string{"build.failed"}
	mu.Unlock()
	diff := QualifyMCPEvents(MCPEventsQualificationConfig{
		PublicEndpoint: pubEP,
		LocalEndpoint:  locEP,
		AuthMode:       "mcp_managed_oauth",
		BearerToken:    validTok,
		Client:         pubSrv.Client(),
		LocalClient:    localSrv.Client(),
	})
	if diff.OK() || diff.CapabilityConsistency != "FAIL" {
		t.Fatalf("expected catalog consistency failure, got %+v", diff)
	}

	// 4. End-to-end CLI command `ocliv mcp check NAME --client chatgpt --capability events --token-file PATH --json`.
	mu.Lock()
	localEvents = []string{"build.failed", "job.completed"}
	mu.Unlock()
	seedEnrolledProfileForTest(t, srvURL)
	tokPath := filepath.Join(t.TempDir(), "ev.tok")
	if err := os.WriteFile(tokPath, []byte(validTok+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, path string) (int, []byte, error) {
			if strings.HasSuffix(path, "/observations") {
				return 200, []byte(`{"route_id":"ev1","verification":{"highest_stage":"CLIENT_AUTHORIZED","client_registration":"OBSERVED","client_authorization":"OBSERVED","external_acceptance":"EXTERNAL_ACCEPTANCE_UNVERIFIED","observations":[{"route_id":"ev1","canonical_url":"` + srvURL + `/r/ev1/mcp","client_id":"cli_cgpt","client_kind":"chatgpt-preset","stage":"EVENTS_SUBSCRIPTION_OBSERVED","result_category":"ok","is_synthetic":false}]}}`), nil
			}
			return 200, []byte(`{"publications":[{"route_id":"ev1","pub_name":"evsvc","profile":"managed-oauth","url":"` + srvURL + `/r/ev1/mcp","publication_state":"ACTIVE","desired_enabled":true,"state_generation":2}]}`), nil
		},
	}
	if code := cmdMCPCheckWithOps([]string{
		"evsvc", "--client", "chatgpt", "--capability", "events",
		"--local-url", localSrv.URL + "/mcp",
		"--token-file", tokPath, "--json",
	}, ops, pubSrv.Client()); code != apperr.ExitOK {
		t.Fatalf("cli mcp check --capability events exit=%d, want 0", code)
	}
}

func TestHostObservationsDistinguishSyntheticFromExternalPreset(t *testing.T) {
	now := time.Now().UTC()
	// Only synthetic probes observed -> real host registration remains UNKNOWN.
	synthOnly := []authz.HostObservation{
		{
			RouteID: "r1", CanonicalURL: "https://relay.example/r/r1/mcp",
			ClientID: "cli_probe", ClientKind: "synthetic-probe",
			Stage: authz.StageEventsSubscriptionObserved, ResultCategory: "ok",
			IsSynthetic: true, ObservedAt: now,
		},
	}
	sumSynth := authz.SummarizeHostObservations(true, true, synthOnly)
	if sumSynth.HighestStage != authz.StageOAuthCompatible || sumSynth.ClientRegistration != "UNKNOWN" ||
		sumSynth.EventsSubscriptionObserved != "UNKNOWN" || sumSynth.PresetClientObserved {
		t.Fatalf("synthetic probe wrongly promoted to real host observation: %+v", sumSynth)
	}
	if !slices.Contains(sumSynth.SyntheticStagesObserved, authz.StageEventsSubscriptionObserved) {
		t.Fatalf("expected synthetic stage tracked separately: %+v", sumSynth)
	}

	// Real ChatGPT-preset client observed -> stages advance honestly, while
	// ExternalAcceptance stays EXTERNAL_ACCEPTANCE_UNVERIFIED until host-side
	// acceptance is independently proven.
	realObs := []authz.HostObservation{
		{
			RouteID: "r1", CanonicalURL: "https://relay.example/r/r1/mcp",
			ClientID: "cli_real", ClientKind: "chatgpt-preset",
			Stage: authz.StageClientRegistered, ResultCategory: "ok", ObservedAt: now,
		},
		{
			RouteID: "r1", CanonicalURL: "https://relay.example/r/r1/mcp",
			ClientID: "cli_real", ClientKind: "chatgpt-preset",
			Stage: authz.StageClientAuthorized, ResultCategory: "ok", ObservedAt: now.Add(time.Second),
		},
		{
			RouteID: "r1", CanonicalURL: "https://relay.example/r/r1/mcp",
			ClientID: "cli_real", ClientKind: "chatgpt-preset",
			Stage: authz.StageEventsDiscoveryObserved, ResultCategory: "ok", ObservedAt: now.Add(2 * time.Second),
		},
	}
	sumReal := authz.SummarizeHostObservations(true, true, realObs)
	if sumReal.HighestStage != authz.StageEventsDiscoveryObserved ||
		sumReal.ClientRegistration != "OBSERVED" ||
		sumReal.ClientAuthorization != "OBSERVED" ||
		sumReal.EventsDiscoveryObserved != "OBSERVED" ||
		!sumReal.PresetClientObserved ||
		sumReal.ExternalAcceptance != authz.StageExternalAcceptanceUnverified {
		t.Fatalf("unexpected real host summary: %+v", sumReal)
	}

	// Generation & freshness filtering: prior-generation and stale observations
	// move to HistoricalStagesObserved and are NEVER promoted to current stages.
	mixedObs := []authz.HostObservation{
		{
			TenantID: "t1", RouteID: "r1", CanonicalURL: "https://relay.example/r/r1/mcp",
			ClientID: "cli_old", ClientKind: "chatgpt-preset", PublicationGeneration: 1,
			Stage: authz.StageEventsSubscriptionObserved, TransportStatus: "ok", ResultCategory: "ok",
			ObservedAt: now,
		},
		{
			TenantID: "t1", RouteID: "r1", CanonicalURL: "https://relay.example/r/r1/mcp",
			ClientID: "cli_cur", ClientKind: "chatgpt-preset", PublicationGeneration: 2,
			Stage: authz.StageClientMCPObserved, TransportStatus: "ok", ResultCategory: "error",
			ObservedAt: now,
		},
	}
	filtered := authz.SummarizeHostObservationsFiltered(true, true, mixedObs, authz.HostObservationFilter{
		TenantID:              "t1",
		RouteID:               "r1",
		CanonicalURL:          "https://relay.example/r/r1/mcp",
		PublicationGeneration: 2,
		MaxAge:                time.Hour,
		Now:                   now,
	})
	if filtered.EventsSubscriptionObserved != "UNKNOWN" {
		t.Fatalf("prior-generation observation wrongly promoted to current: %+v", filtered)
	}
	if !slices.Contains(filtered.HistoricalStagesObserved, authz.StageEventsSubscriptionObserved) {
		t.Fatalf("expected prior-generation stage in HistoricalStagesObserved: %+v", filtered)
	}
	if filtered.ClientMCPObserved != "UNKNOWN" {
		t.Fatalf("JSON-RPC error observation wrongly promoted to ClientMCPObserved: %+v", filtered)
	}
}

func TestQualifyMCPEventsNegativeCleanupAndExternalCallback(t *testing.T) {
	const validTok = "tok-neg-events"
	var srvURL string
	failUnsub := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/r/ev2/mcp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/ev2/mcp","authorization_servers":["` + srvURL + `/r/ev2/oauth"]}`))
			return
		case "/.well-known/oauth-authorization-server/r/ev2/oauth":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + srvURL + `/r/ev2/oauth","authorization_endpoint":"` + srvURL + `/r/ev2/oauth/authorize","token_endpoint":"` + srvURL + `/r/ev2/oauth/token","registration_endpoint":"` + srvURL + `/r/ev2/oauth/register","code_challenge_methods_supported":["S256"]}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+validTok {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srvURL+`/.well-known/oauth-protected-resource/r/ev2/mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			ID     any            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"protocolVersion": "2026-07-28", "capabilities": map[string]any{"events": true}},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"protocolVersion": "2026-07-28", "tools": []any{}},
			})
		case "events/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"events": []any{map[string]any{"name": "job.done"}}},
			})
		case "events/subscribe":
			cbURL, _ := req.Params["callbackUrl"].(string)
			cbSec, _ := req.Params["callbackSecret"].(string)
			if strings.HasPrefix(cbURL, "http://127.0.0.1:") {
				go func() {
					goodReq, _ := http.NewRequest(http.MethodPost, cbURL, bytes.NewReader([]byte(`{"subscriptionId":"sub_neg_1","event":"job.done"}`)))
					goodReq.Header.Set("Content-Type", "application/json")
					goodReq.Header.Set("X-Ocliv-Callback-Secret", cbSec)
					if resp, err := http.DefaultClient.Do(goodReq); err == nil {
						_ = resp.Body.Close()
					}
				}()
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"subscriptionId": "sub_neg_1"},
			})
		case "events/unsubscribe":
			if failUnsub {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]any{"code": -32000, "message": "unsubscribe failed"},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"unsubscribed": true},
			})
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	pubEP, _ := url.Parse(srvURL + "/r/ev2/mcp")

	// 1. Failed events/unsubscribe MUST fail closed (not report OK).
	failUnsub = true
	resFailUnsub := QualifyMCPEvents(MCPEventsQualificationConfig{
		PublicEndpoint:      pubEP,
		AuthMode:            "mcp_managed_oauth",
		BearerToken:         validTok,
		Client:              srv.Client(),
		QualifySubscription: true,
		CallbackTimeout:     2 * time.Second,
	})
	if resFailUnsub.OK() || resFailUnsub.SubscriptionCleanup != "FAIL" {
		t.Fatalf("failed unsubscribe must fail closed: %+v", resFailUnsub)
	}

	// 2. External callback URL cannot be independently verified -> CallbackDelivery=UNVERIFIED, OK()=false.
	failUnsub = false
	resExt := QualifyMCPEvents(MCPEventsQualificationConfig{
		PublicEndpoint:      pubEP,
		AuthMode:            "mcp_managed_oauth",
		BearerToken:         validTok,
		Client:              srv.Client(),
		QualifySubscription: true,
		CallbackURL:         "https://external-receiver.example/cb",
	})
	if resExt.OK() || resExt.CallbackDelivery != "UNVERIFIED" || resExt.SubscriptionCleanup != "PASS" {
		t.Fatalf("external unverified callback must not report full OK: %+v", resExt)
	}
}
