package integration

import (
	"testing"

	"ocliv/internal/cli"
)

// TestIssueEnrollDoesNotDisturbLiveLease: the operator enrollment path
// must never mutate unrelated live tunnel state (P0-01). Issuing a code
// while a lease is ACTIVE must leave its status, generation, and visitor
// traffic untouched.
func TestIssueEnrollDoesNotDisturbLiveLease(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("pre-enroll status %d", resp.StatusCode)
	}
	var status string
	var gen int64
	if err := h.db.SQL().QueryRow(`SELECT status, generation FROM leases WHERE id=?`,
		h.attached.LeaseID).Scan(&status, &gen); err != nil {
		t.Fatal(err)
	}
	if status != "ACTIVE" {
		t.Fatalf("pre-enroll lease status %q", status)
	}

	if code := cli.Run([]string{"relay", "issue-enroll", "--data=" + h.dir}); code != 0 {
		t.Fatalf("issue-enroll exit %d", code)
	}

	var statusAfter string
	var genAfter int64
	if err := h.db.SQL().QueryRow(`SELECT status, generation FROM leases WHERE id=?`,
		h.attached.LeaseID).Scan(&statusAfter, &genAfter); err != nil {
		t.Fatal(err)
	}
	if statusAfter != "ACTIVE" || genAfter != gen {
		t.Fatalf("live lease disturbed: status %q gen %d (was ACTIVE/%d)",
			statusAfter, genAfter, gen)
	}
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("post-enroll status %d: live tunnel disrupted", resp.StatusCode)
	}
}
