package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHTTPDisableRevokesExistingVisitorSessions proves that revoking an HTTP
// lease via the signed agent management endpoint immediately invalidates
// already-established visitor session cookies and rejects subsequent public
// requests, even when no agent session is currently connected.
func TestHTTPDisableRevokesExistingVisitorSessions(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-http-fence", "tenant-http")

	label := "httpfence"
	ls, att, err := s.insertLease("tenant-http", "key-http-fence", label,
		LeaseIntent{Port: 3000, AccessMode: "protected"}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("insertLease: %v", err)
	}
	_, rawTok, ok := strings.Cut(att.ShareURL, "#t=")
	if !ok || rawTok == "" {
		t.Fatalf("expected initial share token in ShareURL, got %q", att.ShareURL)
	}

	// 1. Visitor redeems share token and receives a host-only session cookie.
	body, _ := json.Marshal(map[string]string{"token": rawTok})
	redeemReq := httptest.NewRequest(http.MethodPost, "https://"+ls.Hostname+"/_ocliv/redeem", bytes.NewReader(body))
	redeemReq.Host = ls.Hostname
	redeemReq.Header.Set("Content-Type", "application/json")
	redeemReq.Header.Set("Origin", "https://"+ls.Hostname)
	redeemW := httptest.NewRecorder()
	s.handleRedeem(redeemW, redeemReq)
	if redeemW.Code != http.StatusOK {
		t.Fatalf("redeem status=%d body=%s", redeemW.Code, redeemW.Body.String())
	}
	cookies := redeemW.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie after redeem")
	}
	sessCookie := cookies[0]

	// Verify session cookie is initially valid before revoke.
	rtBefore := &routeTarget{LeaseID: ls.ID, TokenGen: tokenGeneration(t, db.SQL(), ls.ID)}
	if !s.checkCookieSession(rtBefore, sessCookie.Value) {
		t.Fatal("expected freshly redeemed visitor cookie to be valid before revoke")
	}

	// 2. Owner revokes the HTTP lease remotely (agent is disconnected — no live yamux session).
	revReq := signedMgmtRequest(t, priv, "key-http-fence", http.MethodPost, "/v1/agent/lease/"+ls.ID+"/revoke")
	revW := httptest.NewRecorder()
	s.handleAgentLease(revW, revReq)
	if revW.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revW.Code, revW.Body.String())
	}

	// 3. Previously established visitor cookie must now be rejected immediately.
	rtAfter := &routeTarget{LeaseID: ls.ID, TokenGen: tokenGeneration(t, db.SQL(), ls.ID)}
	if s.checkCookieSession(rtAfter, sessCookie.Value) {
		t.Fatal("visitor session cookie remained valid after HTTP lease revoke")
	}

	// 4. Subsequent public HTTP request carrying the old cookie must be denied (never 200).
	pubReq := httptest.NewRequest(http.MethodGet, "https://"+ls.Hostname+"/", nil)
	pubReq.Host = ls.Hostname
	pubReq.AddCookie(sessCookie)
	pubW := httptest.NewRecorder()
	s.handlePublic(pubW, pubReq)
	if pubW.Code == http.StatusOK {
		t.Fatalf("revoked HTTP tunnel answered 200 to stale visitor cookie")
	}
	if pubW.Code != http.StatusNotFound && pubW.Code != http.StatusGone && pubW.Code != http.StatusUnauthorized && pubW.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected public status after revoke: %d (%s)", pubW.Code, pubW.Body.String())
	}
}

// TestAgentLeasesInventoryKeyScoped proves GET /v1/agent/leases returns only
// leases owned by the authenticated calling key (enabling remote-first HTTP
// disable even when local lease state is lost, without leaking sibling keys).
func TestAgentLeasesInventoryKeyScoped(t *testing.T) {
	s, db := newLifecycleServer(t)
	privA := enrollTestKey(t, db.SQL(), "key-inv-a", "tenant-inv")
	privB := enrollTestKey(t, db.SQL(), "key-inv-b", "tenant-inv")

	lblA := "svca"
	lsA, _, err := s.insertLease("tenant-inv", "key-inv-a", lblA,
		LeaseIntent{Port: 3001, AccessMode: "protected"}, time.Now().UTC(), &lblA)
	if err != nil {
		t.Fatal(err)
	}
	lblB := "svcb"
	if _, _, err := s.insertLease("tenant-inv", "key-inv-b", lblB,
		LeaseIntent{Port: 3002, AccessMode: "protected"}, time.Now().UTC(), &lblB); err != nil {
		t.Fatal(err)
	}

	reqA := signedMgmtRequest(t, privA, "key-inv-a", http.MethodGet, "/v1/agent/leases")
	wA := httptest.NewRecorder()
	s.handleAgentLeases(wA, reqA)
	if wA.Code != http.StatusOK {
		t.Fatalf("GET /v1/agent/leases status=%d body=%s", wA.Code, wA.Body.String())
	}
	var outA struct {
		Leases []struct {
			LeaseID string `json:"lease_id"`
			Label   string `json:"label"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(wA.Body.Bytes(), &outA); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(outA.Leases) != 1 || outA.Leases[0].LeaseID != lsA.ID || outA.Leases[0].Label != lblA {
		t.Fatalf("key A saw unexpected leases: %+v", outA.Leases)
	}

	// Key B must not see Key A's lease.
	reqB := signedMgmtRequest(t, privB, "key-inv-b", http.MethodGet, "/v1/agent/leases")
	wB := httptest.NewRecorder()
	s.handleAgentLeases(wB, reqB)
	var outB struct {
		Leases []struct {
			LeaseID string `json:"lease_id"`
		} `json:"leases"`
	}
	_ = json.Unmarshal(wB.Body.Bytes(), &outB)
	for _, l := range outB.Leases {
		if l.LeaseID == lsA.ID {
			t.Fatalf("cross-key lease leak: key B saw key A lease %s", lsA.ID)
		}
	}
}

// TestPersistentHTTPLeaseSurvivesOutageAndPreservesVisitorSessions proves that
// a persistent named protected HTTP lease:
//   - enters RECONNECTING with reconnect_until=NULL on disconnect and relay boot
//     (surviving >90s outages without ephemeral expiry),
//   - rebinds in-place for the same owner (including across local port changes)
//     preserving lease_id, hostname, and existing visitor session cookies,
//   - rejects cross-key reclaim, and
//   - immediately invalidates visitor sessions upon explicit revoke.
func TestPersistentHTTPLeaseSurvivesOutageAndPreservesVisitorSessions(t *testing.T) {
	s, db := newLifecycleServer(t)
	privOwner := enrollTestKey(t, db.SQL(), "key-persist-owner", "tenant-persist")
	_ = enrollTestKey(t, db.SQL(), "key-persist-other", "tenant-persist")

	label := "persistapp"
	ls, att, err := s.insertLease("tenant-persist", "key-persist-owner", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("insertLease persistent: %v", err)
	}
	_, rawTok, ok := strings.Cut(att.ShareURL, "#t=")
	if !ok || rawTok == "" {
		t.Fatalf("expected initial share token, got %q", att.ShareURL)
	}

	// 1. Visitor redeems share token and gets a host-only session cookie.
	body, _ := json.Marshal(map[string]string{"token": rawTok})
	redeemReq := httptest.NewRequest(http.MethodPost, "https://"+ls.Hostname+"/_ocliv/redeem", bytes.NewReader(body))
	redeemReq.Host = ls.Hostname
	redeemReq.Header.Set("Content-Type", "application/json")
	redeemReq.Header.Set("Origin", "https://"+ls.Hostname)
	redeemW := httptest.NewRecorder()
	s.handleRedeem(redeemW, redeemReq)
	if redeemW.Code != http.StatusOK {
		t.Fatalf("redeem status=%d body=%s", redeemW.Code, redeemW.Body.String())
	}
	sessCookie := redeemW.Result().Cookies()[0]

	// 2. Simulate agent disconnect & relay reboot reconciliation -> persistent lease
	//    must remain RECONNECTING with reconnect_until IS NULL (no 90s expiry!).
	if ok, err := s.markReconnecting(ls.ID, ls.Generation); err != nil || !ok {
		t.Fatalf("markReconnecting: ok=%v err=%v", ok, err)
	}
	if err := s.reconcileBoot(); err != nil {
		t.Fatalf("reconcileBoot: %v", err)
	}
	var st string
	var ru *string
	if err := db.SQL().QueryRow(`SELECT status, reconnect_until FROM leases WHERE id=?`, ls.ID).Scan(&st, &ru); err != nil {
		t.Fatal(err)
	}
	if st != "RECONNECTING" || ru != nil {
		t.Fatalf("persistent lease after disconnect/boot: status=%q reconnect_until=%v (want RECONNECTING, nil)", st, ru)
	}

	// 3. Cross-key reclaim must be denied.
	if _, _, err := s.insertLease("tenant-persist", "key-persist-other", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true}, time.Now().UTC(), &label); err == nil {
		t.Fatal("expected cross-key reclaim of persistent named lease to fail")
	}

	// 4. Same owner reattaches on a NEW local port (4000) -> in-place persistent rebind!
	ls2, _, err := s.insertLease("tenant-persist", "key-persist-owner", label,
		LeaseIntent{Port: 4000, AccessMode: "protected", Persistent: true}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("persistent same-owner rebind failed: %v", err)
	}
	if ls2.ID != ls.ID || ls2.Hostname != ls.Hostname || ls2.Port != 4000 || ls2.Generation <= ls.Generation {
		t.Fatalf("unexpected persistent rebind result: old=%+v new=%+v", ls, ls2)
	}

	// 5. Previously established visitor session cookie MUST STILL BE VALID after rebind!
	rtAfterRebind := &routeTarget{LeaseID: ls2.ID, TokenGen: tokenGeneration(t, db.SQL(), ls2.ID)}
	if !s.checkCookieSession(rtAfterRebind, sessCookie.Value) {
		t.Fatal("visitor session cookie was lost across persistent rebind/restart")
	}

	// 6. Explicit revoke MUST immediately invalidate the visitor session cookie.
	revReq := signedMgmtRequest(t, privOwner, "key-persist-owner", http.MethodPost, "/v1/agent/lease/"+ls2.ID+"/revoke")
	revW := httptest.NewRecorder()
	s.handleAgentLease(revW, revReq)
	if revW.Code != http.StatusOK {
		t.Fatalf("explicit revoke failed: %d %s", revW.Code, revW.Body.String())
	}
	rtAfterRevoke := &routeTarget{LeaseID: ls2.ID, TokenGen: tokenGeneration(t, db.SQL(), ls2.ID)}
	if s.checkCookieSession(rtAfterRevoke, sessCookie.Value) {
		t.Fatal("visitor session cookie survived explicit revoke")
	}
}

// TestEdgeHealthzRequiresAdmittedLiveRoute proves HEAD /_ocliv/healthz returns
// 404/503 for unknown or offline routes without leaking secrets.
func TestEdgeHealthzRequiresAdmittedLiveRoute(t *testing.T) {
	s, _ := newLifecycleServer(t)
	req := httptest.NewRequest(http.MethodHead, "https://missing.t.example.test/_ocliv/healthz", nil)
	req.Host = "missing.t.example.test"
	w := httptest.NewRecorder()
	s.handleEdgeHealthz(w, req)
	if w.Code != http.StatusNotFound && w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 404/503 for unknown host on /_ocliv/healthz, got %d", w.Code)
	}
}
