package limits

import (
	"fmt"
	"testing"
	"time"
)

// TestThrottleBoundsKeys: unique-key floods must not grow the map without
// bound; idle keys are evicted and a hard cap fails closed (G08).
func TestThrottleBoundsKeys(t *testing.T) {
	// Hour window: the 10x-cap flood loop itself takes tens of seconds
	// under -race, so a minute window would expire mid-flood and the
	// reclaim path (tested separately below with th2) would mask the
	// cardinality cap this half asserts.
	th := NewThrottle(1000000, time.Hour)
	for i := 0; i < 10*MaxThrottleKeys; i++ {
		th.Allow(fmt.Sprintf("k-%d", i))
	}
	if n := th.Keys(); n > MaxThrottleKeys {
		t.Fatalf("throttle keys unbounded: %d", n)
	}
	// Fresh keys beyond the cap are denied.
	if th.Allow("one-more") {
		t.Fatal("throttle admitted past hard key cap")
	}
	// At capacity with fresh keys, a new key is denied even though no
	// window has passed: the cap is a cardinality bound, not a timer.
	// Generous window so a slow fill loop under -race cannot expire
	// early keys mid-fill and mask the cap.
	th2 := NewThrottle(1000000, 5*time.Minute)
	for i := 0; i < MaxThrottleKeys; i++ {
		th2.Allow(fmt.Sprintf("f-%d", i))
	}
	if th2.Allow("blocked") {
		t.Fatal("throttle admitted past hard key cap")
	}
	// Expired per-key hits are pruned on re-allow: at max=2, two hits
	// deny a third, but after the window passes the slate is clean.
	// Tiny and deterministic — no fill loop racing the clock.
	th3 := NewThrottle(2, 50*time.Millisecond)
	th3.Allow("k")
	th3.Allow("k")
	if th3.Allow("k") {
		t.Fatal("per-key max not enforced")
	}
	time.Sleep(100 * time.Millisecond)
	if !th3.Allow("k") {
		t.Fatal("expired hits not pruned on re-allow")
	}
	// Sweep reclaims idle keys at capacity: a stale entry plus fresh
	// keys to the cap must still admit one more after the sweep drops
	// the stale entry. Stale timestamp is injected directly (same
	// package) so no sleep races the assertion; the hour window keeps
	// the fresh fill from expiring mid-loop under -race load.
	th4 := NewThrottle(1000000, time.Hour)
	th4.mu.Lock()
	th4.hits["stale"] = []time.Time{time.Now().Add(-2 * time.Hour)}
	th4.mu.Unlock()
	for i := 0; i < MaxThrottleKeys-1; i++ {
		th4.Allow(fmt.Sprintf("s-%d", i))
	}
	if !th4.Allow("after-sweep") {
		t.Fatal("sweep did not reclaim idle key at capacity")
	}
}
