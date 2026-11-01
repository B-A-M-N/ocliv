package lease

import (
	"strings"
	"testing"
)

func TestTransitionLegalPaths(t *testing.T) {
	l := &Lease{ID: "l1", State: StateProvisioning}
	for _, to := range []string{StateActive, StateReconnecting, StateClosed} {
		if err := l.Transition(to); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
	if l.State != StateClosed {
		t.Fatalf("state = %q, want CLOSED", l.State)
	}
}

func TestTransitionTerminalStatesFrozen(t *testing.T) {
	for _, terminal := range []string{StateClosed, StateExpired, StateRevoked} {
		l := &Lease{ID: "l1", State: terminal}
		for _, to := range []string{StateActive, StateReconnecting, StateClosed} {
			if err := l.Transition(to); err == nil {
				t.Fatalf("%s -> %s accepted from terminal state", terminal, to)
			}
		}
	}
}

func TestTransitionSkipsIllegal(t *testing.T) {
	l := &Lease{ID: "l1", State: StateActive}
	if err := l.Transition(StateProvisioning); err == nil {
		t.Fatal("ACTIVE -> PROVISIONING accepted")
	}
	l.State = StateReconnecting
	if err := l.Transition(StateDraining); err == nil {
		t.Fatal("RECONNECTING -> DRAINING accepted")
	}
}

func TestCheckGeneration(t *testing.T) {
	l := &Lease{ID: "l1", State: StateActive, Generation: 7}
	if err := l.CheckGeneration(7); err != nil {
		t.Fatalf("live generation rejected: %v", err)
	}
	if err := l.CheckGeneration(6); err == nil {
		t.Fatal("stale generation accepted")
	}
	if err := l.CheckGeneration(8); err == nil {
		t.Fatal("future generation accepted")
	}
	l.State = StateReconnecting
	if err := l.CheckGeneration(7); err == nil {
		t.Fatal("non-active lease accepted traffic generation")
	}
	if l.Live() {
		t.Fatal("RECONNECTING reports live")
	}
}

func TestFenceSupersedes(t *testing.T) {
	l := &Lease{ID: "l1", State: StateActive, Generation: 3}
	if got := l.Fence(); got != 4 {
		t.Fatalf("fence = %d, want 4", got)
	}
	if err := l.CheckGeneration(3); err == nil {
		t.Fatal("pre-fence generation still valid")
	}
}

func TestValidateLabel(t *testing.T) {
	for _, ok := range []string{"abc", "a1-b2", "x", strings.Repeat("a", 63)} {
		if err := ValidateLabel(ok); err != nil {
			t.Fatalf("label %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ABC", "a_b", "-ab", "ab-", strings.Repeat("a", 64), "a.b"} {
		if err := ValidateLabel(bad); err == nil {
			t.Fatalf("label %q accepted", bad)
		}
	}
}

func TestSplitHost(t *testing.T) {
	label, ok := SplitHost("chat.t.example.com:443", "t.example.com")
	if !ok || label != "chat" {
		t.Fatalf("split = %q,%v", label, ok)
	}
	for _, bad := range []string{
		"t.example.com", "a.b.t.example.com", "other.com",
		"chat.t.example.com.evil.com", "",
	} {
		if _, ok := SplitHost(bad, "t.example.com"); ok {
			t.Fatalf("host %q accepted", bad)
		}
	}
}

func TestMintFormats(t *testing.T) {
	id1, err := MintID()
	if err != nil || !strings.HasPrefix(id1, "lse-") {
		t.Fatalf("MintID = %q, %v", id1, err)
	}
	id2, _ := MintID()
	if id1 == id2 {
		t.Fatal("MintID collision")
	}
	hn, err := RandomHostname()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLabel(strings.SplitN(hn, "-", 2)[1][:24]); err != nil {
		t.Fatalf("hostname suffix invalid: %q: %v", hn, err)
	}
}
