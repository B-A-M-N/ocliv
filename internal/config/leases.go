package config

// Per-lease agent state (P1-7). The old singleton lease.json let two
// independent tunnels under one account overwrite each other's resume
// state, and resume matched on port alone. Each lease now owns one
// atomic JSON record keyed by lease ID; resume matches the full
// deployment identity (relay, key, port, mode, name, public flag), so a
// changed invocation never silently resumes the wrong tunnel.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// LeaseStoreDir holds one JSON record per lease inside the agent data dir.
const LeaseStoreDir = "leases"

// LeaseRecord is the resumable identity of one tunnel. No secrets: the
// lease ID names the lease; authorization still comes from the agent key
// and the relay's live session.
type LeaseRecord struct {
	LeaseID    string `json:"lease_id"`
	Hostname   string `json:"hostname"`
	URL        string `json:"url"`
	Port       int    `json:"port"`
	AccessMode string `json:"access_mode"`
	Public     bool   `json:"public"`
	Name       string `json:"name"`
	RelayURL   string `json:"relay_url"`
	KeyID      string `json:"key_id"`
	Generation uint64 `json:"generation"`
	UpdatedAt  string `json:"updated_at"`
	// IPv6 records the loopback family the tunnel was started with, so
	// diagnostics probe the exact local target instead of assuming
	// IPv4. Absent (zero value) means IPv4: pre-family records keep
	// their historical behavior with no migration.
	IPv6 bool `json:"ipv6,omitempty"`
	// TTLSeconds and UpstreamHost complete the deployment identity
	// (P1-5): a changed TTL or local service target allocates a fresh
	// lease instead of silently resuming under new terms.
	TTLSeconds   int64  `json:"ttl_seconds,omitempty"`
	UpstreamHost string `json:"upstream_host,omitempty"`
}

// ResumeQuery is the canonical deployment identity (P1-5). Every field
// must match a stored record for resume; any change allocates a fresh
// lease, never a silent resume of a differently-configured tunnel.
type ResumeQuery struct {
	RelayURL, KeyID string
	Port            int
	AccessMode      string
	Name            string
	Public          bool
	IPv6            bool
	TTLSeconds      int64
	UpstreamHost    string
}

// LeaseStore persists lease records under dir/leases/.
type LeaseStore struct {
	dir string // the leases/ directory itself
}

// OpenLeaseStore creates the store (0700) and migrates a legacy
// lease.json exactly once: the old record imports with an empty
// relay/key identity, so it stays visible to status but can never
// auto-resume the wrong deployment (fail closed).
func OpenLeaseStore(dataDir string) (*LeaseStore, error) {
	dir := filepath.Join(dataDir, LeaseStoreDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &LeaseStore{dir: dir}
	if err := s.migrateLegacy(dataDir); err != nil {
		return nil, err
	}
	return s, nil
}

func validLeaseID(id string) bool {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, `/\.`) {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (s *LeaseStore) path(leaseID string) (string, error) {
	if !validLeaseID(leaseID) {
		return "", fmt.Errorf("invalid lease id")
	}
	return filepath.Join(s.dir, leaseID+".json"), nil
}

// withLock serializes writers across processes sharing the data dir.
func (s *LeaseStore) withLock(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// Save writes one lease record atomically (temp file + rename, 0600).
func (s *LeaseStore) Save(rec LeaseRecord) error {
	if !validLeaseID(rec.LeaseID) {
		return fmt.Errorf("invalid lease id")
	}
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	p, _ := s.path(rec.LeaseID)
	return s.withLock(func() error {
		tmp, err := os.CreateTemp(s.dir, ".tmp-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)
		if _, err := tmp.Write(raw); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Chmod(0o600); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmpName, p); err != nil {
			return err
		}
		if dfd, err := os.Open(s.dir); err == nil {
			_ = dfd.Sync()
			_ = dfd.Close()
		}
		return nil
	})
}

// Load returns one record by lease ID.
func (s *LeaseStore) Load(leaseID string) (LeaseRecord, bool) {
	var rec LeaseRecord
	p, err := s.path(leaseID)
	if err != nil {
		return rec, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return rec, false
	}
	if err := json.Unmarshal(raw, &rec); err != nil || rec.LeaseID == "" {
		return LeaseRecord{}, false
	}
	return rec, true
}

// List returns all records, most recently updated first.
func (s *LeaseStore) List() []LeaseRecord {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var out []LeaseRecord
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec LeaseRecord
		raw, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(raw, &rec); err != nil || rec.LeaseID == "" {
			continue
		}
		// Skip files that do not match their name: never let a stray
		// or swapped file impersonate another lease's identity.
		if e.Name() != rec.LeaseID+".json" {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out
}

// Remove deletes one record. Missing records are not errors (delete is
// idempotent for shutdown paths).
func (s *LeaseStore) Remove(leaseID string) error {
	p, err := s.path(leaseID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// FindResume returns the record matching the canonical deployment
// identity. Any change — relay, key, port, mode, name, public flag,
// loopback family, TTL, or upstream host — misses, so the caller
// allocates a fresh lease instead of resuming the wrong one.
func (s *LeaseStore) FindResume(q ResumeQuery) (LeaseRecord, bool) {
	if q.RelayURL == "" || q.KeyID == "" {
		return LeaseRecord{}, false
	}
	for _, rec := range s.List() {
		if rec.RelayURL == q.RelayURL && rec.KeyID == q.KeyID && rec.Port == q.Port &&
			rec.AccessMode == q.AccessMode && rec.Name == q.Name && rec.Public == q.Public &&
			rec.IPv6 == q.IPv6 && rec.TTLSeconds == q.TTLSeconds && rec.UpstreamHost == q.UpstreamHost {
			return rec, true
		}
	}
	return LeaseRecord{}, false
}

// Latest returns the most recently updated record, the successor to the
// old singleton for status/shutdown fallbacks.
func (s *LeaseStore) Latest() (LeaseRecord, bool) {
	recs := s.List()
	if len(recs) == 0 {
		return LeaseRecord{}, false
	}
	return recs[0], true
}

// ErrLeaseNameNotFound reports a name matching no record.
var ErrLeaseNameNotFound = errors.New("no recorded lease with that name")

// AmbiguousNameError reports a name matching more than one record,
// e.g. the same label on two relay deployments. Candidates are lease
// IDs, sorted; the caller must ask for --lease instead of guessing.
type AmbiguousNameError struct {
	Name       string
	Candidates []string
}

func (e *AmbiguousNameError) Error() string {
	return fmt.Sprintf("ambiguous lease name %q: matches %s; use --lease", e.Name, strings.Join(e.Candidates, ", "))
}

// FindByName resolves a tunnel by hostname label, failing closed on
// mismatch so diagnostics never report on the wrong tunnel. A name
// matching records on multiple deployments is ambiguous, not
// latest-wins: it returns *AmbiguousNameError (P1-4).
func (s *LeaseStore) FindByName(name string) (LeaseRecord, error) {
	if name == "" {
		return LeaseRecord{}, ErrLeaseNameNotFound
	}
	var matches []LeaseRecord
	for _, rec := range s.List() {
		if rec.Hostname == name || strings.HasPrefix(rec.Hostname, name+".") {
			matches = append(matches, rec)
		}
	}
	switch len(matches) {
	case 0:
		return LeaseRecord{}, ErrLeaseNameNotFound
	case 1:
		return matches[0], nil
	default:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.LeaseID)
		}
		sort.Strings(ids)
		return LeaseRecord{}, &AmbiguousNameError{Name: name, Candidates: ids}
	}
}

// migrateLegacy imports lease.json once, then removes it so the two
// sources can never disagree. The imported record carries no relay/key
// identity and therefore never auto-resumes.
func (s *LeaseStore) migrateLegacy(dataDir string) error {
	legacy := filepath.Join(dataDir, LeaseFile)
	raw, err := os.ReadFile(legacy)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var old struct {
		LeaseID    string `json:"lease_id"`
		Hostname   string `json:"hostname"`
		URL        string `json:"url"`
		Port       int    `json:"port"`
		AccessMode string `json:"access_mode"`
		Generation uint64 `json:"generation"`
	}
	if err := json.Unmarshal(raw, &old); err != nil || old.LeaseID == "" {
		return nil // unreadable legacy cache: ignore, do not block startup
	}
	rec := LeaseRecord{
		LeaseID: old.LeaseID, Hostname: old.Hostname, URL: old.URL,
		Port: old.Port, AccessMode: old.AccessMode, Generation: old.Generation,
	}
	if err := s.Save(rec); err != nil {
		return err
	}
	return os.Remove(legacy)
}
