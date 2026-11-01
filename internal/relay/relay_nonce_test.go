package relay

// nonceCache ownership tests: reserve/consume semantics must match the
// previous inline Server implementation exactly — sweep-then-cap on
// reserve, delete-exactly-once on consume.

import (
	"testing"
	"time"
)

func TestNonceReserveConsume(t *testing.T) {
	c := newNonceCache()
	if !c.reserve("n1", time.Now().Add(time.Minute)) {
		t.Fatal("reserve failed on empty cache")
	}
	exp, ok := c.consume("n1")
	if !ok || exp.IsZero() {
		t.Fatal("consume lost a reserved nonce")
	}
	if _, ok := c.consume("n1"); ok {
		t.Fatal("replay accepted: consume is not exactly-once")
	}
}

func TestNonceReserveSweepsExpired(t *testing.T) {
	c := newNonceCache()
	past := time.Now().Add(-time.Minute)
	for _, n := range []string{"old1", "old2"} {
		c.mu.Lock()
		c.m[n] = past
		c.mu.Unlock()
	}
	if !c.reserve("fresh", time.Now().Add(time.Minute)) {
		t.Fatal("reserve failed despite only expired entries")
	}
	c.mu.Lock()
	_, stale := c.m["old1"]
	c.mu.Unlock()
	if stale {
		t.Fatal("expired nonce survived the reserve sweep")
	}
}

func TestNonceConsumeMissing(t *testing.T) {
	c := newNonceCache()
	if _, ok := c.consume("never-issued"); ok {
		t.Fatal("unknown nonce consumed")
	}
}
