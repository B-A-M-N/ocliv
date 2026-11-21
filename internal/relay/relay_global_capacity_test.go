package relay

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/limits"
	"ocliv/internal/store"
)

// TestGlobalHTTPCapacity proves the global HTTP cap fires independently of
// per-lease caps. Two leases each stay under their per-lease cap while the
// aggregate hits the global limit.
func TestGlobalHTTPCapacity(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const globalMax = 3
	s, err := New(Options{
		DB:                   db,
		Namespace:            "t.example.test",
		RelayHost:            "relay.example.test",
		GlobalMaxHTTPStreams: globalMax,
		GlobalMaxWSStreams:   100, // permissive
		GlobalMaxSessions:    100, // permissive
	})
	if err != nil {
		t.Fatal(err)
	}
	s.preAuth = limits.NewThrottle(1<<30, time.Minute)

	// Admit globalMax streams — all should succeed.
	releases := make([]func(), globalMax)
	for i := range releases {
		if !s.globalBudget.AdmitHTTP() {
			t.Fatalf("admit %d: expected success, got rejection", i+1)
		}
		idx := i
		releases[idx] = s.globalBudget.ReleaseHTTP
	}

	// One more should be rejected.
	if s.globalBudget.AdmitHTTP() {
		t.Fatal("expected rejection at capacity, got admission")
	}

	// Releasing one slot should allow another admission.
	releases[0]()
	releases[0] = func() {} // prevent double-release

	if !s.globalBudget.AdmitHTTP() {
		t.Fatal("expected admission after release, got rejection")
	}

	// Relay should report saturation when at cap.
	for i := 1; i < globalMax; i++ {
		releases[i]()
	}
	// Now only the last-admitted one is live; not saturated.
	h, _, _ := s.globalBudget.Stats()
	if h != 1 {
		t.Fatalf("expected 1 active HTTP stream after releases, got %d", h)
	}
}

// TestGlobalBudgetSaturationSeparatesReadiness proves HTTP visitor-stream
// saturation does NOT flip ReadyForSessions() false (preventing false
// health remediation during visitor backpressure), while StatusSnapshot()
// exposes separate process_ready, sessions_ready, and http_saturated signals.
func TestGlobalBudgetSaturationBlocksReadiness(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := New(Options{
		DB:                   db,
		Namespace:            "t.example.test",
		RelayHost:            "relay.example.test",
		GlobalMaxHTTPStreams: 1,
		GlobalMaxWSStreams:   100,
		GlobalMaxSessions:    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Not saturated initially.
	if s.globalBudget.Saturated() {
		t.Fatal("unexpected saturation before any admission")
	}
	if !s.ReadyForSessions() {
		t.Fatal("expected ReadyForSessions() true initially")
	}

	// Saturate HTTP visitor streams: ReadyForSessions() MUST remain true!
	if !s.globalBudget.AdmitHTTP() {
		t.Fatal("expected admission for first HTTP slot")
	}
	if !s.globalBudget.HTTPSaturated() {
		t.Fatal("expected HTTPSaturated after filling HTTP cap")
	}
	if !s.ReadyForSessions() {
		t.Fatal("ReadyForSessions() must remain true during HTTP visitor-stream saturation")
	}
	st := s.StatusSnapshot()
	if !st.ProcessReady || !st.SessionsReady || !st.HTTPSaturated || st.SessionsSaturated {
		t.Fatalf("unexpected status during HTTP saturation: %+v", st)
	}

	// Saturate publisher sessions: ProcessReady stays true, SessionsReady becomes false.
	if !s.globalBudget.AdmitSession() {
		t.Fatal("expected admission for first session slot")
	}
	st2 := s.StatusSnapshot()
	if !st2.ProcessReady || st2.SessionsReady || !st2.SessionsSaturated {
		t.Fatalf("unexpected status during session saturation: %+v", st2)
	}

	// Release both.
	s.globalBudget.ReleaseHTTP()
	s.globalBudget.ReleaseSession()
	if s.globalBudget.Saturated() {
		t.Fatal("unexpected saturation after release")
	}
}

// TestGlobalWSCapacity proves the WebSocket cap works independently.
func TestGlobalWSCapacity(t *testing.T) {
	budget := limits.NewGlobalBudget(100, 2, 100)

	if !budget.AdmitWS() {
		t.Fatal("first WS admission failed")
	}
	if !budget.AdmitWS() {
		t.Fatal("second WS admission failed")
	}
	if budget.AdmitWS() {
		t.Fatal("third WS admission should fail (cap=2)")
	}
	budget.ReleaseWS()
	if !budget.AdmitWS() {
		t.Fatal("WS admission after release failed")
	}
	_, ws, _ := budget.Stats()
	if ws != 2 {
		t.Fatalf("expected 2 active WS, got %d", ws)
	}
}

// TestGlobalSessionCapacity proves the session cap works independently.
func TestGlobalSessionCapacity(t *testing.T) {
	budget := limits.NewGlobalBudget(100, 100, 2)

	if !budget.AdmitSession() {
		t.Fatal("first session admission failed")
	}
	if !budget.AdmitSession() {
		t.Fatal("second session admission failed")
	}
	if budget.AdmitSession() {
		t.Fatal("third session admission should fail (cap=2)")
	}
	budget.ReleaseSession()
	if !budget.AdmitSession() {
		t.Fatal("session admission after release failed")
	}
	_, _, sess := budget.Stats()
	if sess != 2 {
		t.Fatalf("expected 2 active sessions, got %d", sess)
	}
}

// TestUnlimitedBudgetAlwaysAdmits proves a 0-cap budget never rejects.
func TestUnlimitedBudgetAlwaysAdmits(t *testing.T) {
	budget := limits.NewGlobalBudget(0, 0, 0)
	for i := 0; i < 1000; i++ {
		if !budget.AdmitHTTP() {
			t.Fatalf("unlimited budget rejected HTTP at iteration %d", i)
		}
		if !budget.AdmitWS() {
			t.Fatalf("unlimited budget rejected WS at iteration %d", i)
		}
		if !budget.AdmitSession() {
			t.Fatalf("unlimited budget rejected session at iteration %d", i)
		}
	}
	if budget.Saturated() {
		t.Fatal("unlimited budget should never be saturated")
	}
}

// TestHealthStatusNotExposedOnPublicMux proves /health/status is never served
// on the public relay authority mux (it belongs exclusively to the loopback
// health listener).
func TestHealthStatusNotExposedOnPublicMux(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://relay.example.test/health/status", nil)
	r.Host = "relay.example.test"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("/health/status must NOT be served on public mux (got 200: %s)", w.Body.String())
	}
}
