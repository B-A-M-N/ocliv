package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestControlCenterSecuritySessionCSRFOriginHostAndOperatorApprovals(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://bamnlabs.duckdns.org")
	k, keyID, err := loadKeyForProfile(config.ActiveProfile())
	if err != nil {
		t.Fatalf("loadKeyForProfile: %v", err)
	}
	tmpDir := t.TempDir()
	t.Setenv("OCLIV_PERMISSIONS_FILE", filepath.Join(tmpDir, "agent-permissions.json"))
	t.Setenv("OCLIV_APPROVAL_REQUESTS_FILE", filepath.Join(tmpDir, "approval-requests.json"))

	store, err := openServices()
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := store.Put(config.ServiceRecord{
		Name:          "agentgateway",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       config.ActiveProfile(),
		RelayURL:      "https://bamnlabs.duckdns.org",
		DesiredState:  config.DesiredEnabled,
		PublicationID: "jr8x2Txyoa1jPs22CROuBQ",
		PublicURL:     "https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp",
	}); err != nil {
		t.Fatal(err)
	}

	approvedTx := false
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, []byte(`{"publications":[{"route_id":"jr8x2Txyoa1jPs22CROuBQ","pub_name":"agentgateway","profile":"managed-oauth","url":"https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp","publication_state":"VERIFIED","desired_enabled":true,"host_binding":"VALID","admission":"READY","admission_reason":"READY"}]}`), nil
			}
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/jr8x2Txyoa1jPs22CROuBQ/authz/consents/cns_live_1/approve" {
				approvedTx = true
				return http.StatusOK, []byte(`{"challenge":"cns_live_1","client_id":"cli_1","decision":"approved"}`), nil
			}
			return http.StatusNotFound, []byte("not found"), nil
		},
	}

	cc, err := newControlCenterServer("127.0.0.1:43210", "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("newControlCenterServer: %v", err)
	}

	// 1. Invalid Host header is rejected with 403.
	reqBadHost := httptest.NewRequest(http.MethodGet, "http://evil.example/api/status", nil)
	reqBadHost.Host = "evil.example"
	recBadHost := httptest.NewRecorder()
	cc.ServeHTTP(recBadHost, reqBadHost)
	if recBadHost.Code != http.StatusForbidden {
		t.Fatalf("invalid Host expected 403, got %d", recBadHost.Code)
	}

	// 2. Unauthenticated /api/status is rejected with 401.
	reqNoAuth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:43210/api/status", nil)
	reqNoAuth.Host = "127.0.0.1:43210"
	recNoAuth := httptest.NewRecorder()
	cc.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/status expected 401, got %d", recNoAuth.Code)
	}

	// 3. Single-use bootstrap token establishes HttpOnly SameSite=Strict session cookie, and replay fails.
	reqBoot := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:43210/auth?token="+cc.bootstrapToken, nil)
	reqBoot.Host = "127.0.0.1:43210"
	recBoot := httptest.NewRecorder()
	cc.ServeHTTP(recBoot, reqBoot)
	if recBoot.Code != http.StatusSeeOther {
		t.Fatalf("bootstrap expected 303, got %d", recBoot.Code)
	}
	cookies := recBoot.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != controlCenterSessionCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie: %+v", cookies)
	}
	sessCookie := cookies[0]

	recBootReplay := httptest.NewRecorder()
	cc.ServeHTTP(recBootReplay, reqBoot)
	if recBootReplay.Code != http.StatusUnauthorized {
		t.Fatalf("replayed bootstrap token expected 401, got %d", recBootReplay.Code)
	}

	// 4. Mutating request without CSRF or with bad Origin fails closed with 403.
	reqNoCSRF := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:43210/api/services/agentgateway/decide-tx", strings.NewReader(`{"challenge":"cns_live_1","decision":"approve"}`))
	reqNoCSRF.Host = "127.0.0.1:43210"
	reqNoCSRF.Header.Set("Origin", "http://127.0.0.1:43210")
	reqNoCSRF.AddCookie(sessCookie)
	recNoCSRF := httptest.NewRecorder()
	cc.ServeHTTP(recNoCSRF, reqNoCSRF)
	if recNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF expected 403, got %d", recNoCSRF.Code)
	}

	reqBadOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:43210/api/services/agentgateway/decide-tx", strings.NewReader(`{"challenge":"cns_live_1","decision":"approve"}`))
	reqBadOrigin.Host = "127.0.0.1:43210"
	reqBadOrigin.Header.Set("Origin", "https://evil.example")
	reqBadOrigin.Header.Set("X-Ocliv-CSRF", cc.csrfToken)
	reqBadOrigin.AddCookie(sessCookie)
	recBadOrigin := httptest.NewRecorder()
	cc.ServeHTTP(recBadOrigin, reqBadOrigin)
	if recBadOrigin.Code != http.StatusForbidden {
		t.Fatalf("evil Origin expected 403, got %d", recBadOrigin.Code)
	}

	// 5. Valid authenticated operator request approves native visitor OAuth transaction.
	reqApprove := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:43210/api/services/agentgateway/decide-tx", strings.NewReader(`{"challenge":"cns_live_1","decision":"approve"}`))
	reqApprove.Host = "127.0.0.1:43210"
	reqApprove.Header.Set("Origin", "http://127.0.0.1:43210")
	reqApprove.Header.Set("X-Ocliv-CSRF", cc.csrfToken)
	reqApprove.AddCookie(sessCookie)
	recApprove := httptest.NewRecorder()
	cc.ServeHTTP(recApprove, reqApprove)
	if recApprove.Code != http.StatusOK || !approvedTx {
		t.Fatalf("operator visitor approval failed: code=%d approvedTx=%v body=%s", recApprove.Code, approvedTx, recApprove.Body.String())
	}

	// 6. Operator approves a pending agent permission request persistently via Control Center.
	pendingReq, err := createOperatorApprovalRequest("agent-ci", "enable_service", "lifecycle", "agentgateway", "svc_agw", 0, "")
	if err != nil {
		t.Fatalf("createOperatorApprovalRequest: %v", err)
	}
	bodyBytes, _ := json.Marshal(map[string]string{"decision": "allow_persistent"})
	reqDecide := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:43210/api/agents/requests/"+pendingReq.RequestID+"/decide", bytes.NewReader(bodyBytes))
	reqDecide.Host = "127.0.0.1:43210"
	reqDecide.Header.Set("Origin", "http://127.0.0.1:43210")
	reqDecide.Header.Set("X-Ocliv-CSRF", cc.csrfToken)
	reqDecide.AddCookie(sessCookie)
	recDecide := httptest.NewRecorder()
	cc.ServeHTTP(recDecide, reqDecide)
	if recDecide.Code != http.StatusOK {
		t.Fatalf("operator approval decision failed: code=%d body=%s", recDecide.Code, recDecide.Body.String())
	}
	pol, err := loadAgentPermissionsPolicy()
	if err != nil {
		t.Fatalf("loadAgentPermissionsPolicy: %v", err)
	}
	if ok, _, reason := pol.check("agent-ci", "lifecycle", "agentgateway", "svc_agw", 0, ""); !ok {
		t.Fatalf("expected persistent lifecycle grant for agent-ci on agentgateway, denied: %s", reason)
	}
}
