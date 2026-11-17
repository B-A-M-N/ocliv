package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

var validServiceNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,47}$`)

// Service desired states stored durably in services.json.
const (
	DesiredConfigured = "configured"
	DesiredEnabled    = "enabled"
	DesiredDisabled   = "disabled"
)

// Backend ownership modes.
const (
	BackendAttached = "attached" // external process listens on LocalURL
	BackendManaged  = "managed"  // Ocliv supervises BackendExec -> LocalURL
)

// VerificationEvidence records the exact proven readiness stage for a
// publication, bound to its identity, URL, generation, and expiration.
type VerificationEvidence struct {
	Stage           string `json:"stage"`
	RouteID         string `json:"route_id,omitempty"`
	PublicURL       string `json:"public_url,omitempty"`
	Issuer          string `json:"issuer,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	StateGeneration int64  `json:"state_generation,omitempty"`
	VerifiedAt      string `json:"verified_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	FailureReason   string `json:"failure_reason,omitempty"`
}

// ServiceRecord is the durable operator-configured service definition.
// Publication identity is bound to Name (never derived from a local TCP port)
// and Profile/RelayURL (never silently switched by active-profile changes).
type ServiceRecord struct {
	Name                 string                `json:"name"`
	Type                 string                `json:"type"`                   // "mcp" | "http"
	BackendMode          string                `json:"backend_mode,omitempty"` // "attached" | "managed"
	BackendExec          string                `json:"backend_exec,omitempty"`
	BackendArgs          []string              `json:"backend_args,omitempty"`
	LocalURL             string                `json:"local_url,omitempty"`
	StdioCmd             []string              `json:"stdio_cmd,omitempty"`
	StdioDir             string                `json:"stdio_dir,omitempty"`
	StdioEnv             []string              `json:"stdio_env,omitempty"`
	Auth                 string                `json:"auth"`
	RelayURL             string                `json:"relay_url,omitempty"`
	Profile              string                `json:"profile,omitempty"`
	DesiredState         string                `json:"desired_state"`
	Revision             int64                 `json:"revision"`
	StateGeneration      int64                 `json:"state_generation,omitempty"`
	PublicationID        string                `json:"publication_id,omitempty"`
	PublicURL            string                `json:"public_url,omitempty"`
	PublicVerified       bool                  `json:"public_verified,omitempty"`
	VerificationEvidence *VerificationEvidence `json:"verification_evidence,omitempty"`
	SystemdUnit          string                `json:"systemd_unit,omitempty"`
	BackendUnit          string                `json:"backend_unit,omitempty"`
	LastVerifiedAt       string                `json:"last_verified_at,omitempty"`
	LastFailure          string                `json:"last_failure,omitempty"`
	LastRecoveryAction   string                `json:"last_recovery_action,omitempty"`
	CreatedAt            string                `json:"created_at"`
	UpdatedAt            string                `json:"updated_at"`
}

// ValidateServiceName enforces a safe, explicit service identifier.
func ValidateServiceName(name string) error {
	if !validServiceNameRe.MatchString(name) {
		return fmt.Errorf("invalid service name %q: must match ^[A-Za-z][A-Za-z0-9_-]{0,47}$", name)
	}
	return nil
}

// ValidateServiceLocalURL enforces loopback HTTP or an absolute Unix socket path.
func ValidateServiceLocalURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid local URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http":
		h := u.Hostname()
		if h != "127.0.0.1" && h != "::1" && h != "localhost" {
			return fmt.Errorf("local URL %q must target loopback (127.0.0.1, ::1, or localhost)", raw)
		}
		if u.Port() == "" {
			return fmt.Errorf("local URL %q must include an explicit port", raw)
		}
		if u.User != nil {
			return fmt.Errorf("local URL %q must not contain userinfo", raw)
		}
		return nil
	case "unix":
		if u.Path == "" || !filepath.IsAbs(u.Path) {
			return fmt.Errorf("unix socket URL %q must have an absolute path", raw)
		}
		return nil
	default:
		return fmt.Errorf("unsupported local URL scheme %q (want http or unix)", u.Scheme)
	}
}

// ServiceStore manages owner-only (0600) durable service records in
// services.json with interprocess file locking (flock) and monotonic revisions.
type ServiceStore struct {
	path     string
	lockPath string
}

// OpenServiceStore returns a ServiceStore backed by <dir>/services.json.
func OpenServiceStore(dir string) *ServiceStore {
	return &ServiceStore{
		path:     filepath.Join(dir, "services.json"),
		lockPath: filepath.Join(dir, "services.lock"),
	}
}

func (s *ServiceStore) withLock(fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(s.lockPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
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

func (s *ServiceStore) loadMap() (map[string]ServiceRecord, error) {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return map[string]ServiceRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]ServiceRecord
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("corrupt service store %s: %w", s.path, err)
	}
	if m == nil {
		m = map[string]ServiceRecord{}
	}
	return m, nil
}

func (s *ServiceStore) saveMap(m map[string]ServiceRecord) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".services-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.path)
}

func (s *ServiceStore) List() ([]ServiceRecord, error) {
	var out []ServiceRecord
	err := s.withLock(func() error {
		m, err := s.loadMap()
		if err != nil {
			return err
		}
		out = make([]ServiceRecord, 0, len(m))
		for _, r := range m {
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return nil
	})
	return out, err
}

func (s *ServiceStore) Get(name string) (ServiceRecord, bool, error) {
	var rec ServiceRecord
	var ok bool
	err := s.withLock(func() error {
		m, err := s.loadMap()
		if err != nil {
			return err
		}
		rec, ok = m[name]
		return nil
	})
	return rec, ok, err
}

// Put writes rec under flock, incrementing Revision monotonically.
func (s *ServiceStore) Put(rec ServiceRecord) error {
	if err := ValidateServiceName(rec.Name); err != nil {
		return err
	}
	return s.withLock(func() error {
		m, err := s.loadMap()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if prev, ok := m[rec.Name]; ok {
			if rec.CreatedAt == "" && prev.CreatedAt != "" {
				rec.CreatedAt = prev.CreatedAt
			}
			if prev.Revision >= rec.Revision {
				rec.Revision = prev.Revision + 1
			}
		} else {
			if rec.CreatedAt == "" {
				rec.CreatedAt = now
			}
			if rec.Revision <= 0 {
				rec.Revision = 1
			}
		}
		rec.UpdatedAt = now
		m[rec.Name] = rec
		return s.saveMap(m)
	})
}

// UpdateCAS atomically mutates an existing record if its Revision matches expectedRev.
func (s *ServiceStore) UpdateCAS(name string, expectedRev int64, fn func(*ServiceRecord) error) (ServiceRecord, error) {
	var updated ServiceRecord
	err := s.withLock(func() error {
		m, err := s.loadMap()
		if err != nil {
			return err
		}
		rec, ok := m[name]
		if !ok {
			return fmt.Errorf("unknown service %q", name)
		}
		if expectedRev > 0 && rec.Revision != expectedRev {
			return fmt.Errorf("concurrent modification on service %q (revision %d != %d)", name, rec.Revision, expectedRev)
		}
		if err := fn(&rec); err != nil {
			return err
		}
		rec.Revision++
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		m[name] = rec
		updated = rec
		return s.saveMap(m)
	})
	return updated, err
}

func (s *ServiceStore) Delete(name string) (bool, error) {
	var deleted bool
	err := s.withLock(func() error {
		m, err := s.loadMap()
		if err != nil {
			return err
		}
		if _, ok := m[name]; !ok {
			return nil
		}
		delete(m, name)
		deleted = true
		return s.saveMap(m)
	})
	return deleted, err
}
