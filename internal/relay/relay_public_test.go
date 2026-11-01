package relay

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"ocliv/internal/protocol"
)

// TestAdmittedSessionCurrent pins the P1-5 dispatch fence: liveness
// alone must not authorize a stream. Only the exact admitted session
// object at the admitted generation passes; a replacement (different
// object, same lease), a generation mismatch, or a missing session
// rejects the request before the request head is written.
func TestAdmittedSessionCurrent(t *testing.T) {
	admitted := &Session{LeaseID: "lse-1", Generation: 7}
	replacement := &Session{LeaseID: "lse-1", Generation: 8}
	for _, tc := range []struct {
		name string
		cur  *Session
		sess *Session
		gen  uint64
		want bool
	}{
		{"same object same generation", admitted, admitted, 7, true},
		{"replacement object rejected", replacement, admitted, 7, false},
		{"replacement at its own generation rejected", replacement, admitted, 8, false},
		{"same object wrong generation rejected", admitted, admitted, 8, false},
		{"nil current rejected", nil, admitted, 7, false},
		{"nil admitted rejected", admitted, nil, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := admittedSessionCurrent(tc.cur, tc.sess, tc.gen); got != tc.want {
				t.Fatalf("admittedSessionCurrent = %v, want %v", got, tc.want)
			}
		})
	}
}

// dispatchHarness wires a relay-side yamux session to a fake agent end
// that applies the agent-side generation contract (agent_serve
// handleStream): a head binding a generation the agent no longer owns
// is rejected without forwarding, never executed.
type dispatchHarness struct {
	relayYS *yamux.Session
	agentYS *yamux.Session
	gotHead chan protocol.RequestHead
	noHead  chan struct{}
}

func newDispatchHarness(t *testing.T) *dispatchHarness {
	t.Helper()
	a, b := net.Pipe()
	rys, err := yamux.Client(a, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ays, err := yamux.Server(b, yamux.DefaultConfig())
	if err != nil {
		_ = rys.Close()
		t.Fatal(err)
	}
	h := &dispatchHarness{
		relayYS: rys, agentYS: ays,
		gotHead: make(chan protocol.RequestHead, 1),
		noHead:  make(chan struct{}, 1),
	}
	t.Cleanup(func() { _ = rys.Close(); _ = ays.Close() })
	go func() {
		strm, err := ays.Accept()
		if err != nil {
			h.noHead <- struct{}{}
			return
		}
		defer strm.Close()
		_ = strm.SetReadDeadline(time.Now().Add(10 * time.Second))
		ftype, payload, err := protocol.ReadFrame(strm)
		if err != nil || ftype != protocol.FRequestHead {
			h.noHead <- struct{}{}
			return
		}
		var head protocol.RequestHead
		if err := json.Unmarshal(payload, &head); err != nil {
			h.noHead <- struct{}{}
			return
		}
		h.gotHead <- head
		// Agent-side gate: stale generation is never forwarded; the
		// stream dies here so the relay exchange fails visibly.
	}()
	return h
}

// TestDispatchReplacementBeforeCheckRejected proves the fence end to
// end: a replacement landing before dispatch is denied with 503 and no
// request head ever reaches the (fake) agent.
func TestDispatchReplacementBeforeCheckRejected(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = db
	insertLeaseRow(t, db, "lse-disp-a", "ACTIVE", 1, nil)
	h := newDispatchHarness(t)
	sess := &Session{LeaseID: "lse-disp-a", Generation: 1, Yamux: h.relayYS,
		Budget: s.budgets.For("lse-disp-a"), closed: make(chan struct{})}
	insertRegistrySession(s, sess)
	// Replacement wins the race before dispatch starts.
	replYS, replCleanup := liveYamux(t)
	defer replCleanup()
	insertRegistrySession(s, &Session{LeaseID: "lse-disp-a", Generation: 2, Yamux: replYS, closed: make(chan struct{})})

	tgt := &routeTarget{LeaseID: "lse-disp-a", Generation: 1, AccessMode: "public", Hostname: "a.t.example.test"}
	req := httptest.NewRequest("GET", "http://a.t.example.test/", nil)
	req.RequestURI = "/"
	rec := httptest.NewRecorder()
	s.serveProxied(rec, req, tgt, sess, true, false)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("stale dispatch: status=%d, want 503", rec.Code)
	}
	select {
	case <-h.noHead:
	case head := <-h.gotHead:
		t.Fatalf("stale dispatch wrote a head: gen=%d", head.Generation)
	case <-time.After(12 * time.Second):
		t.Fatal("fake agent saw neither head nor close")
	}
}

// TestDispatchReplacementInCheckWriteWindowBindsStaleGeneration proves
// the residual window fails closed. dispatchHold lands a gen-2
// replacement after the fence passed, so the head goes out — but it
// still binds the admitted gen 1, which the agent-side contract
// rejects. The visitor gets a 5xx, never a clean success, and a head
// minted for the replacement generation never exists.
func TestDispatchReplacementInCheckWriteWindowBindsStaleGeneration(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = db
	insertLeaseRow(t, db, "lse-disp-b", "ACTIVE", 1, nil)
	h := newDispatchHarness(t)
	sess := &Session{LeaseID: "lse-disp-b", Generation: 1, Yamux: h.relayYS,
		Budget: s.budgets.For("lse-disp-b"), closed: make(chan struct{})}
	insertRegistrySession(s, sess)
	release := make(chan struct{})
	replYS, replCleanup := liveYamux(t)
	defer replCleanup()
	s.dispatchHold = func() {
		insertRegistrySession(s, &Session{LeaseID: "lse-disp-b", Generation: 2, Yamux: replYS, closed: make(chan struct{})})
		close(release)
	}
	defer func() { s.dispatchHold = nil }()

	tgt := &routeTarget{LeaseID: "lse-disp-b", Generation: 1, AccessMode: "public", Hostname: "b.t.example.test"}
	req := httptest.NewRequest("GET", "http://b.t.example.test/", nil)
	req.RequestURI = "/"
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveProxied(rec, req, tgt, sess, true, false)
	}()
	select {
	case <-release:
	case <-time.After(10 * time.Second):
		t.Fatal("dispatch barrier never reached")
	}
	select {
	case head := <-h.gotHead:
		if head.Generation != 1 {
			t.Fatalf("wire head gen=%d, want admitted gen 1", head.Generation)
		}
		if head.LeaseID != "lse-disp-b" {
			t.Fatalf("wire head lease=%q, want lse-disp-b", head.LeaseID)
		}
		// The live session is already gen 2: nothing on the wire was
		// ever minted for the replacement.
		if cur, live := s.liveSession("lse-disp-b"); !live || cur.Generation != 2 {
			t.Fatalf("live generation moved: live=%v gen=%d", live, cur.Generation)
		}
	case <-h.noHead:
		t.Fatal("head never written; fence fired despite hold ordering")
	case <-time.After(12 * time.Second):
		t.Fatal("fake agent saw neither head nor close")
	}
	select {
	case <-done:
		if rec.Code/100 != 5 {
			t.Fatalf("stale-window dispatch: status=%d, want 5xx failure", rec.Code)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("dispatch never returned after stale write")
	}
}
