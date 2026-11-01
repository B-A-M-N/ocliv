package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Two deployments sharing one hostname label must never resolve by
// guessing: a name matching more than one record fails closed with the
// candidate lease IDs, and the caller must use --lease (P1-4).
func TestFindByNameFailsClosedOnAmbiguity(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := LeaseRecord{LeaseID: "lse-one", Hostname: "demo.t", Port: 3000, RelayURL: "https://r1.test", KeyID: "key-1"}
	b := LeaseRecord{LeaseID: "lse-two", Hostname: "demo.t", Port: 3000, RelayURL: "https://r2.test", KeyID: "key-1"}
	if err := s.Save(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(b); err != nil {
		t.Fatal(err)
	}
	_, err = s.FindByName("demo")
	var amb *AmbiguousNameError
	if !errors.As(err, &amb) {
		t.Fatalf("ambiguous name: want AmbiguousNameError, got %v", err)
	}
	if len(amb.Candidates) != 2 {
		t.Fatalf("candidates = %v, want both lease IDs", amb.Candidates)
	}
}

// The store isolates tunnels: saving B never disturbs A, records carry
// no secrets, resume requires the full deployment identity, and a legacy
// singleton imports once without becoming auto-resumable.
func TestLeaseStoreIsolatesTunnels(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := LeaseRecord{LeaseID: "lse-a", Hostname: "a.t", Port: 3000, RelayURL: "https://r.test", KeyID: "key-1"}
	b := LeaseRecord{LeaseID: "lse-b", Hostname: "b.t", Port: 3001, RelayURL: "https://r.test", KeyID: "key-1"}
	if err := s.Save(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(b); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Load("lse-a"); !ok || got.Hostname != "a.t" {
		t.Fatalf("lease A disturbed by B: %+v ok=%v", got, ok)
	}
	base := ResumeQuery{RelayURL: "https://r.test", KeyID: "key-1", Port: 3000}
	if rec, ok := s.FindResume(base); !ok || rec.LeaseID != "lse-a" {
		t.Fatalf("resume A: %+v ok=%v", rec, ok)
	}
	// Changed identity misses: every dimension of the canonical
	// deployment identity (P1-5) requires a fresh lease.
	mutate := func(f func(*ResumeQuery)) ResumeQuery {
		q := base
		f(&q)
		return q
	}
	for _, tc := range []struct {
		name string
		q    ResumeQuery
	}{
		{"port", mutate(func(q *ResumeQuery) { q.Port = 3002 })},
		{"mode", mutate(func(q *ResumeQuery) { q.AccessMode = "mcp_upstream_oauth" })},
		{"name", mutate(func(q *ResumeQuery) { q.Name = "renamed" })},
		{"public", mutate(func(q *ResumeQuery) { q.Public = true })},
		{"relay", mutate(func(q *ResumeQuery) { q.RelayURL = "https://other.test" })},
		{"key", mutate(func(q *ResumeQuery) { q.KeyID = "key-2" })},
		{"ipv6", mutate(func(q *ResumeQuery) { q.IPv6 = true })},
		{"ttl", mutate(func(q *ResumeQuery) { q.TTLSeconds = 3600 })},
		{"upstream-host", mutate(func(q *ResumeQuery) { q.UpstreamHost = "internal.local" })},
	} {
		if rec, ok := s.FindResume(tc.q); ok {
			t.Fatalf("%s change resumed %+v", tc.name, rec)
		}
	}
	// Name lookup selects exactly one tunnel; unknown names fail closed.
	if rec, err := s.FindByName("b"); err != nil || rec.LeaseID != "lse-b" {
		t.Fatalf("FindByName b: %+v err=%v", rec, err)
	}
	if _, err := s.FindByName("nope"); !errors.Is(err, ErrLeaseNameNotFound) {
		t.Fatalf("FindByName unknown: want not-found, got %v", err)
	}
	// Latest orders by recency; removal is idempotent.
	if rec, ok := s.Latest(); !ok || rec.LeaseID != "lse-b" {
		t.Fatalf("Latest: %+v ok=%v", rec, ok)
	}
	if err := s.Remove("lse-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("lse-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Load("lse-a"); ok {
		t.Fatal("removed record still loads")
	}
	if _, ok := s.FindResume(base); ok {
		t.Fatal("removed lease still resumable")
	}
	// Path traversal in an id never escapes the store.
	if err := s.Save(LeaseRecord{LeaseID: "../evil"}); err == nil {
		t.Fatal("traversal lease id accepted")
	}
	if _, ok := s.Load("../evil"); ok {
		t.Fatal("traversal lease id loads")
	}
}

func TestLeaseStoreMigratesLegacyOnce(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"lease_id":"lse-old","hostname":"old.t","port":3000,"generation":3}`
	if err := os.WriteFile(filepath.Join(dir, LeaseFile), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, LeaseFile)); !os.IsNotExist(err) {
		t.Fatal("legacy singleton not removed after import")
	}
	rec, ok := s.Load("lse-old")
	if !ok || rec.Port != 3000 || rec.Generation != 3 {
		t.Fatalf("legacy record not imported: %+v ok=%v", rec, ok)
	}
	if _, ok := s.FindResume(ResumeQuery{RelayURL: "https://r.test", KeyID: "key-1", Port: 3000}); ok {
		t.Fatal("identity-less legacy record auto-resumes")
	}
	// Second open is a no-op: no duplicate, no resurrection.
	s2, err := OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s2.List()); got != 1 {
		t.Fatalf("records after re-open: %d, want 1", got)
	}
}

// Probe contract is deployment identity (Domain A): a changed probe
// path or expected status misses resume, so the caller allocates a
// fresh lease instead of inheriting another contract's readiness.
func TestFindResumeProbeContractMismatch(t *testing.T) {
	s, err := OpenLeaseStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := LeaseRecord{LeaseID: "lse-probe", Hostname: "p.t", Port: 3000,
		RelayURL: "https://r.test", KeyID: "key-1",
		ProbePath: "/healthz", ProbeStatus: 200}
	if err := s.Save(rec); err != nil {
		t.Fatal(err)
	}
	base := ResumeQuery{RelayURL: "https://r.test", KeyID: "key-1", Port: 3000,
		ProbePath: "/healthz", ProbeStatus: 200}
	if _, ok := s.FindResume(base); !ok {
		t.Fatal("identical probe contract missed")
	}
	changed := base
	changed.ProbePath = "/readyz"
	if _, ok := s.FindResume(changed); ok {
		t.Fatal("changed probe path resumed the old lease")
	}
	changed = base
	changed.ProbeStatus = 201
	if _, ok := s.FindResume(changed); ok {
		t.Fatal("changed expected status resumed the old lease")
	}
}
