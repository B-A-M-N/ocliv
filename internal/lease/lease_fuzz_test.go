package lease

import (
	"testing"
)

var fuzzStates = []string{
	StateProvisioning, StateActive, StateReconnecting, StateDraining,
	StateClosed, StateExpired, StateRevoked, "BOGUS",
}

func FuzzLeaseTransition(f *testing.F) {
	f.Add(1, 1, 1, 1)
	f.Fuzz(func(t *testing.T, s0, s1, s2, s3 int) {
		idx := func(i int) int {
			if i < 0 {
				i = -i
			}
			return i % len(fuzzStates)
		}
		l := &Lease{ID: "fuzz", State: fuzzStates[idx(s0)]}
		for _, step := range []int{s1, s2, s3} {
			before := l.State
			to := fuzzStates[idx(step)]
			err := l.Transition(to)
			if isTerminal(before) {
				// Terminal states are absorbing: nothing leaves them.
				if err == nil {
					t.Fatalf("transition out of terminal %s to %s accepted", before, to)
				}
				if l.State != before {
					t.Fatalf("failed transition mutated state %s -> %s", before, l.State)
				}
				continue
			}
			if err == nil {
				// Accepted transitions land exactly on the target.
				if l.State != to {
					t.Fatalf("accepted transition %s -> %s landed on %s", before, to, l.State)
				}
			} else if l.State != before {
				t.Fatalf("rejected transition %s -> %s mutated state to %s", before, to, l.State)
			}
		}
	})
}

func isTerminal(s string) bool {
	return s == StateClosed || s == StateExpired || s == StateRevoked
}

func FuzzLeaseFenceMonotonic(f *testing.F) {
	f.Add(uint(0), uint(3))
	f.Fuzz(func(t *testing.T, start uint, n uint) {
		l := &Lease{ID: "fuzz", State: StateActive, Generation: uint64(start)}
		prev := uint64(start)
		for i := 0; i < int(n%16); i++ {
			if got := l.Fence(); got != prev+1 {
				t.Fatalf("fence not monotonic: %d -> %d", prev, got)
			} else {
				prev = got
			}
		}
		if err := l.CheckGeneration(prev); err != nil {
			t.Fatalf("live generation rejected: %v", err)
		}
		if err := l.CheckGeneration(prev + 1); err == nil {
			t.Fatal("unfenced generation accepted")
		}
	})
}
