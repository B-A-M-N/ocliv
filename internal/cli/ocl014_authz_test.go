package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOCL014ExactIntentBindingAndConcurrentSingleUseConsumption(t *testing.T) {
	tmp := t.TempDir()
	reqPath := filepath.Join(tmp, "approval-requests.json")
	polPath := filepath.Join(tmp, "agent-permissions.json")
	t.Setenv("OCLIV_APPROVAL_REQUESTS_FILE", reqPath)
	t.Setenv("OCLIV_PERMISSIONS_FILE", polPath)

	intentA := AuthorizationIntent{
		Operation:     "decide_authorization",
		Permission:    "authorize_visitor",
		Principal:     "agent-1",
		ServiceID:     "svc_agw",
		ServiceName:   "agentgateway",
		PublicationID: "pub_1",
		Revision:      3,
		Arguments:     map[string]any{"challenge": "cns_A", "decision": "approve"},
	}
	req, err := createOperatorApprovalRequest(intentA, 0, "")
	if err != nil {
		t.Fatalf("createOperatorApprovalRequest: %v", err)
	}
	if _, err := decideOperatorApprovalRequest(req.RequestID, "allow_once"); err != nil {
		t.Fatalf("decideOperatorApprovalRequest: %v", err)
	}

	// Modified challenge OR decision MUST NOT consume intentA's approval (OCL-014.1).
	tampered := intentA
	tampered.Arguments = map[string]any{"challenge": "cns_B", "decision": "approve"}
	if ok, err := consumeSingleUseApproval("agent-1", tampered.Digest()); err != nil || ok {
		t.Fatalf("tampered intent unexpectedly consumed approval: ok=%v err=%v", ok, err)
	}

	// Concurrent redemption across 8 goroutines under flock: EXACTLY ONE succeeds (OCL-014.2).
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := consumeSingleUseApproval("agent-1", intentA.Digest()); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("expected exactly 1 concurrent consumption win, got %d", wins.Load())
	}

	// Corrupted approval store MUST fail closed, never silently overwrite (OCL-014.2).
	if err := os.WriteFile(reqPath, []byte("{corrupted json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := consumeSingleUseApproval("agent-1", intentA.Digest()); err == nil {
		t.Fatal("expected corrupted approval-requests.json to fail closed")
	}
}

func TestOCL014NoCrossProductPermissionEscalation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OCLIV_APPROVAL_REQUESTS_FILE", filepath.Join(tmp, "approval-requests.json"))
	t.Setenv("OCLIV_PERMISSIONS_FILE", filepath.Join(tmp, "agent-permissions.json"))

	// Agent has lifecycle on service-a ONLY.
	if err := saveAgentPermissionsPolicy(AgentPermissionsPolicy{
		Agents: map[string]AgentPermissionRule{
			"agent-ops": {
				Grants: []ServiceGrant{
					{ServiceID: "svc-a", ServiceName: "service-a", Actions: []string{"inspect", "lifecycle"}},
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Operator persistently grants ONLY inspect on service-b.
	req, err := createOperatorApprovalRequest(AuthorizationIntent{
		Operation:   "get_service",
		Permission:  "inspect",
		Principal:   "agent-ops",
		ServiceID:   "svc-b",
		ServiceName: "service-b",
	}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decideOperatorApprovalRequest(req.RequestID, "allow_persistent"); err != nil {
		t.Fatal(err)
	}

	pol, err := loadAgentPermissionsPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := pol.check("agent-ops", "inspect", "service-b", "svc-b", 0, ""); !ok {
		t.Fatal("expected inspect on service-b to be granted")
	}
	if ok, _, _ := pol.check("agent-ops", "lifecycle", "service-b", "svc-b", 0, ""); ok {
		t.Fatal("cross-product escalation: granting inspect on service-b leaked lifecycle onto service-b!")
	}
	if ok, _, _ := pol.check("agent-ops", "lifecycle", "service-a", "svc-a", 0, ""); !ok {
		t.Fatal("existing lifecycle grant on service-a was lost")
	}
}

func TestOCL014ControlCenterHardeningLogoutCASAndStrictCSP(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://bamnlabs.duckdns.org")
	k, keyID, _ := loadKeyForProfile("default")
	tmp := t.TempDir()
	t.Setenv("OCLIV_PERMISSIONS_FILE", filepath.Join(tmp, "agent-permissions.json"))
	t.Setenv("OCLIV_APPROVAL_REQUESTS_FILE", filepath.Join(tmp, "approval-requests.json"))

	cc, err := newControlCenterServer("127.0.0.1:44123", "https://bamnlabs.duckdns.org", k, keyID, serviceOps{})
	if err != nil {
		t.Fatal(err)
	}
	// Bootstrap session.
	reqBoot := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:44123/auth?token="+cc.bootstrapToken, nil)
	reqBoot.Host = "127.0.0.1:44123"
	recBoot := httptest.NewRecorder()
	cc.ServeHTTP(recBoot, reqBoot)
	sessCookie := recBoot.Result().Cookies()[0]

	// 1. Strict CSP has script-src 'self' and NO unsafe-inline in script-src.
	csp := recBoot.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self';") {
		t.Fatalf("expected strict script-src 'self'; got %q", csp)
	}

	// 2. Refuses publishing Control Center's own loopback port (44123).
	reqSelf := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:44123/api/services", strings.NewReader(`{"name":"selfcc","port":44123,"type":"mcp"}`))
	reqSelf.Host = "127.0.0.1:44123"
	reqSelf.Header.Set("Origin", "http://127.0.0.1:44123")
	reqSelf.Header.Set("X-Ocliv-CSRF", cc.csrfToken)
	reqSelf.AddCookie(sessCookie)
	recSelf := httptest.NewRecorder()
	cc.ServeHTTP(recSelf, reqSelf)
	if recSelf.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 blocking Control Center self-publish, got %d", recSelf.Code)
	}

	// 3. Stale expected_revision on PUT /api/agents/permissions returns 409 Conflict.
	reqStale := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:44123/api/agents/permissions", strings.NewReader(`{"expected_revision":99,"policy":{"agents":{}}}`))
	reqStale.Host = "127.0.0.1:44123"
	reqStale.Header.Set("Origin", "http://127.0.0.1:44123")
	reqStale.Header.Set("X-Ocliv-CSRF", cc.csrfToken)
	reqStale.AddCookie(sessCookie)
	recStale := httptest.NewRecorder()
	cc.ServeHTTP(recStale, reqStale)
	if recStale.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for stale revision, got %d", recStale.Code)
	}

	// 4. Logout invalidates session so subsequent /api/status returns 401.
	reqOut := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:44123/api/auth/logout", strings.NewReader(`{}`))
	reqOut.Host = "127.0.0.1:44123"
	reqOut.Header.Set("Origin", "http://127.0.0.1:44123")
	reqOut.Header.Set("X-Ocliv-CSRF", cc.csrfToken)
	reqOut.AddCookie(sessCookie)
	recOut := httptest.NewRecorder()
	cc.ServeHTTP(recOut, reqOut)
	if recOut.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", recOut.Code)
	}
	reqAfter := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:44123/api/status", nil)
	reqAfter.Host = "127.0.0.1:44123"
	reqAfter.AddCookie(sessCookie)
	recAfter := httptest.NewRecorder()
	cc.ServeHTTP(recAfter, reqAfter)
	if recAfter.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", recAfter.Code)
	}
}
