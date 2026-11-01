package cli

import (
	"strings"
	"testing"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func seedRecord(t *testing.T, dir, leaseID string, port int) {
	t.Helper()
	store, err := config.OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(config.LeaseRecord{LeaseID: leaseID, Hostname: "h.t", Port: port}); err != nil {
		t.Fatal(err)
	}
}

func attachedWithLease(leaseID string) agent.Attached {
	return agent.Attached{LeaseID: leaseID}
}

// Remote cleanup must be honest: an unconfirmed lease close or route
// deletion is a nonzero exit naming the affected IDs, never a silent
// zero. Both operations are attempted even if one fails (P1-8).
func TestCleanupResultExitCodes(t *testing.T) {
	ok := CleanupResult{LeaseID: "lse-1", LeaseCloseStatus: 200, RouteDeleteStatus: -1}
	if got := ok.ExitCode(apperr.ExitOK); got != apperr.ExitOK {
		t.Fatalf("confirmed cleanup exit = %d, want 0", got)
	}
	if msg := ok.Report(); msg != "" {
		t.Fatalf("confirmed cleanup reported %q", msg)
	}
	for _, tc := range []struct {
		name string
		res  CleanupResult
		base int
	}{
		{"relay timeout on lease close", CleanupResult{LeaseID: "lse-1", LeaseCloseStatus: 0, RouteDeleteStatus: -1}, apperr.ExitOK},
		{"permission denied on lease close", CleanupResult{LeaseID: "lse-1", LeaseCloseStatus: 403, LeaseDetail: "forbidden", RouteDeleteStatus: -1}, apperr.ExitOK},
		{"already-deleted route", CleanupResult{LeaseID: "lse-1", LeaseCloseStatus: 200, RouteID: "r-1", RouteDeleteStatus: 404, RouteDetail: "unknown route"}, apperr.ExitOK},
		{"route delete transport failure", CleanupResult{LeaseID: "lse-1", LeaseCloseStatus: 200, RouteID: "r-1", RouteDeleteStatus: 0}, apperr.ExitOK},
		{"both operations fail", CleanupResult{LeaseID: "lse-1", LeaseCloseStatus: 500, LeaseDetail: "boom", RouteID: "r-1", RouteDeleteStatus: 500, RouteDetail: "boom"}, apperr.ExitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.ExitCode(tc.base); got == apperr.ExitOK {
				t.Fatalf("%s: unconfirmed cleanup exited 0", tc.name)
			}
			msg := tc.res.Report()
			if msg == "" {
				t.Fatalf("%s: unconfirmed cleanup reported nothing", tc.name)
			}
			// A confirmed lease close emits no lease warning; only an
			// unconfirmed one must name the lease.
			if tc.res.LeaseCloseStatus != 200 && !contains(msg, tc.res.LeaseID) {
				t.Fatalf("%s: report omits lease id: %q", tc.name, msg)
			}
			if tc.res.RouteDeleteStatus != -1 && tc.res.RouteDeleteStatus != 200 && !contains(msg, tc.res.RouteID) {
				t.Fatalf("%s: report omits route id: %q", tc.name, msg)
			}
		})
	}
	// A local failure already nonzero stays nonzero (its own code wins;
	// remote confirmation cannot mask it, and vice versa).
	failed := CleanupResult{LeaseID: "lse-1", LeaseCloseStatus: 0, RouteDeleteStatus: -1}
	if got := failed.ExitCode(apperr.ExitLocalTarget); got != apperr.ExitLocalTarget {
		t.Fatalf("local failure exit = %d, want %d", got, apperr.ExitLocalTarget)
	}
}

// A confirmed remote close drops the local resume hint so a later run
// cannot resume a closed lease; an unconfirmed close keeps it (the lease
// may linger until TTL expiry). The stubbed closer simulates relay
// timeout, denial, and already-deleted routes without a network (P1-8).
func TestCloseTunnelWithRemovesRecordOnlyOnConfirm(t *testing.T) {
	newReady := func(dir string) tunnelReady {
		return tunnelReady{dir: dir}
	}
	confirmed := func(ready tunnelReady, leaseID string) (int, string) { return 200, "ok" }
	denied := func(ready tunnelReady, leaseID string) (int, string) { return 403, "forbidden" }
	unreachable := func(ready tunnelReady, leaseID string) (int, string) { return 0, "" }

	dir := t.TempDir()
	seedRecord(t, dir, "lse-1", 3000)
	if got := closeTunnelWith(confirmed, newReady(dir), attachedWithLease("lse-1"), apperr.ExitOK); got != apperr.ExitOK {
		t.Fatalf("confirmed close exit = %d, want 0", got)
	}
	if got := lastLeaseID(dir); got != "" {
		t.Fatalf("closed lease record kept: %q", got)
	}

	seedRecord(t, dir, "lse-2", 3000)
	if got := closeTunnelWith(denied, newReady(dir), attachedWithLease("lse-2"), apperr.ExitOK); got == apperr.ExitOK {
		t.Fatal("denied close exited 0")
	}
	if got := lastLeaseID(dir); got != "lse-2" {
		t.Fatalf("unconfirmed close dropped the record: %q", got)
	}

	seedRecord(t, dir, "lse-3", 3000)
	if got := closeTunnelWith(unreachable, newReady(dir), attachedWithLease("lse-3"), apperr.ExitOK); got == apperr.ExitOK {
		t.Fatal("unreachable relay exited 0")
	}
	if got := lastLeaseID(dir); got != "lse-3" {
		t.Fatalf("unconfirmed close dropped the record: %q", got)
	}
}

// Shutdown without a live attachment identity must never guess from the
// store: in a shared data directory the latest record may belong to
// another tunnel. The other lease is left untouched and the exit is
// nonzero (unconfirmed remote state), never a silent zero (P1-1).
func TestCloseTunnelWithoutAttachmentNeverClosesOtherLease(t *testing.T) {
	dir := t.TempDir()
	seedRecord(t, dir, "lse-other", 3001)
	called := false
	closer := func(ready tunnelReady, leaseID string) (int, string) {
		called = true
		return 200, "ok"
	}
	if got := closeTunnelWith(closer, tunnelReady{dir: dir}, attachedWithLease(""), apperr.ExitOK); got == apperr.ExitOK {
		t.Fatal("unconfirmed shutdown exited 0")
	}
	if called {
		t.Fatal("shutdown without attachment identity invoked a remote close")
	}
	if got := lastLeaseID(dir); got != "lse-other" {
		t.Fatalf("other tunnel's record disturbed: %q", got)
	}
}
