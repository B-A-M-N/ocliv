// Package lease owns the lease state machine and fencing epoch (F01-F05,
// F13). It is the sole authority for lease lifecycle transitions and
// generation checks. Relay and agent both consult it; neither duplicates it.
package lease

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"ocliv/internal/apperr"
)

// States.
const (
	StateProvisioning = "PROVISIONING"
	StateActive       = "ACTIVE"
	StateReconnecting = "RECONNECTING"
	StateDraining     = "DRAINING"
	StateClosed       = "CLOSED"
	StateExpired      = "EXPIRED"
	StateRevoked      = "REVOKED"
)

// Policy knobs per spec section 6.
const (
	ReconnectGrace = 90 * time.Second
	DrainWindow    = 10 * time.Second
)

// Lease is the authoritative in-memory lifecycle record.
type Lease struct {
	ID         string
	TenantID   string
	AgentKeyID string
	Hostname   string
	Port       int
	AccessMode string // "protected" | "public"
	State      string
	Generation uint64
	ExpiresAt  time.Time
	UpdatedAt  time.Time
}

// Allowed transitions (F01).
var transitions = map[string][]string{
	StateProvisioning: {StateActive, StateClosed, StateRevoked, StateExpired},
	StateActive:       {StateReconnecting, StateDraining, StateClosed, StateExpired, StateRevoked},
	StateReconnecting: {StateActive, StateExpired, StateRevoked, StateClosed},
	StateDraining:     {StateClosed, StateExpired, StateRevoked},
	StateClosed:       {},
	StateExpired:      {},
	StateRevoked:      {},
}

// Transition validates and applies a state change.
func (l *Lease) Transition(to string) error {
	for _, ok := range transitions[l.State] {
		if ok == to {
			l.State = to
			l.UpdatedAt = time.Now()
			return nil
		}
	}
	return apperr.E(apperr.CodeInternal,
		fmt.Sprintf("illegal lease transition %s -> %s", l.State, to), nil)
}

// CheckGeneration rejects stale generations (F02, F03, F13). Equality is the
// only live generation; anything else is rejected even on late frames.
func (l *Lease) CheckGeneration(gen uint64) error {
	if gen != l.Generation {
		return apperr.E(apperr.CodeStaleGen,
			fmt.Sprintf("stale session generation %d; live is %d", gen, l.Generation), nil)
	}
	if l.State != StateActive {
		return apperr.E(apperr.CodeAgentOffline,
			fmt.Sprintf("lease %s not active (state %s)", l.ID, l.State), nil)
	}
	return nil
}

// Fence atomically supersedes the current generation (F03).
func (l *Lease) Fence() uint64 {
	l.Generation++
	l.UpdatedAt = time.Now()
	return l.Generation
}

// Live reports whether new requests may be routed (F06, F07).
func (l *Lease) Live() bool { return l.State == StateActive }

// MintID creates a random lease id with >=80 bits entropy.
func MintID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", apperr.E(apperr.CodeInternal, "CSPRNG failure minting lease id", err)
	}
	return "lse-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// RandomHostname allocates a non-recycled random subdomain label (D05).
// Lowercase hex keeps the label valid under ValidateLabel; 12 bytes carry
// 96 unpredictable bits plus a readable prefix word.
func RandomHostname() (string, error) {
	words := []string{"bright", "swift", "quiet", "amber", "north", "cedar", "harbor", "meadow", "ember", "willow"}
	raw := make([]byte, 13)
	if _, err := rand.Read(raw); err != nil {
		return "", apperr.E(apperr.CodeInternal, "CSPRNG failure minting hostname", err)
	}
	w := words[int(raw[0])%len(words)]
	return fmt.Sprintf("%s-%s", w, hex.EncodeToString(raw[1:])), nil
}

// ValidateLabel enforces exact one-label hostname syntax (D01-D03).
func ValidateLabel(label string) error {
	if len(label) == 0 || len(label) > 63 {
		return apperr.E(apperr.CodeBadHost, "hostname label length invalid", nil)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return apperr.E(apperr.CodeBadHost, "hostname label must be lowercase alphanumerics and hyphens", nil)
		}
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return apperr.E(apperr.CodeBadHost, "hostname label may not start or end with hyphen", nil)
	}
	return nil
}

// SplitHost extracts the single left label for host t.example.com lookups.
// Returns ok=false for anything that is not exactly one label under ns.
func SplitHost(hostport, ns string) (label string, ok bool) {
	host := hostport
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// Careful: strip port only when it is numeric after the last colon.
		if _, rest := host[:i], host[i+1:]; isNumeric(rest) {
			host = host[:i]
		}
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ns = strings.ToLower(ns)
	if !strings.HasSuffix(host, "."+ns) {
		return "", false
	}
	label = strings.TrimSuffix(host, "."+ns)
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	if err := ValidateLabel(label); err != nil {
		return "", false
	}
	return label, true
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
