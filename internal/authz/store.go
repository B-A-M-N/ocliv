package authz

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"
)

// GrantStatus is the operator approval state of a client grant.
type GrantStatus string

const (
	// GrantPending means the client registered but no operator has approved
	// it. A pending grant cannot mint a code or token.
	GrantPending GrantStatus = "pending"
	// GrantActive means an operator approved the client for this route.
	GrantActive GrantStatus = "active"
	// GrantRevoked means the operator revoked the client. Existing tokens
	// fail closed at admission.
	GrantRevoked GrantStatus = "revoked"
)

// Client is a dynamically registered OAuth client (RFC 7591). Registration
// never implies access.
type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

// Grant is an operator approval binding one client to one tenant + route.
type Grant struct {
	ClientID  string
	Tenant    string
	Route     string
	Status    GrantStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Code is a single-use authorization code with its PKCE binding.
type Code struct {
	Code            string
	ClientID        string
	Tenant          string
	Route           string
	RedirectURI     string
	Challenge       string
	ChallengeMethod string
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
}

// Expired reports whether the code has passed its expiry.
func (c *Code) Expired() bool { return time.Now().After(c.ExpiresAt) }

// Store is the authorization state. Implementations must be safe for
// concurrent use. The relay's SQL implementation (schemaV8) is added in
// Phase 2; the in-memory implementation here backs unit and security tests.
type Store interface {
	RegisterClient(c Client) error
	GetClient(id string) (*Client, error)
	RevokeClient(id string) error

	CreateGrant(g Grant) error
	GetGrant(clientID, tenant, route string) (*Grant, error)
	ApproveGrant(clientID, tenant, route string) error
	RevokeGrant(clientID, tenant, route string) error

	CreateCode(c Code) error
	ConsumeCode(code string) (*Code, error)
}

// MemStore is an in-memory Store for tests and local evaluation.
type MemStore struct {
	mu      sync.Mutex
	clients map[string]*Client
	grants  map[string]*Grant // key: clientID + "\x00" + tenant + "\x00" + route
	codes   map[string]*Code
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		clients: map[string]*Client{},
		grants:  map[string]*Grant{},
		codes:   map[string]*Code{},
	}
}

func grantKey(clientID, tenant, route string) string {
	return clientID + "\x00" + tenant + "\x00" + route
}

// RegisterClient adds a client. Re-registering an existing id is rejected.
func (m *MemStore) RegisterClient(c Client) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[c.ID]; ok {
		return fmt.Errorf("authz: client %q already registered", c.ID)
	}
	cp := c
	m.clients[c.ID] = &cp
	return nil
}

// GetClient returns a copy of the client.
func (m *MemStore) GetClient(id string) (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return nil, fmt.Errorf("authz: unknown client %q", id)
	}
	cp := *c
	cp.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	return &cp, nil
}

// RevokeClient marks a client revoked. It does not delete it: the id stays
// reserved so it cannot be re-registered to bypass the revocation.
func (m *MemStore) RevokeClient(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return fmt.Errorf("authz: unknown client %q", id)
	}
	now := time.Now()
	c.RevokedAt = &now
	return nil
}

// CreateGrant stores a grant. Re-creating an existing grant is rejected so a
// pending approval cannot be silently overwritten.
func (m *MemStore) CreateGrant(g Grant) error {
	if g.ClientID == "" || g.Tenant == "" || g.Route == "" {
		return fmt.Errorf("authz: grant requires client, tenant, and route")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := grantKey(g.ClientID, g.Tenant, g.Route)
	if _, ok := m.grants[k]; ok {
		return fmt.Errorf("authz: grant already exists for client %q route %q", g.ClientID, g.Route)
	}
	cp := g
	m.grants[k] = &cp
	return nil
}

// GetGrant returns a copy of the grant.
func (m *MemStore) GetGrant(clientID, tenant, route string) (*Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantKey(clientID, tenant, route)]
	if !ok {
		return nil, fmt.Errorf("authz: no grant for client %q route %q", clientID, route)
	}
	cp := *g
	return &cp, nil
}

// ApproveGrant flips a pending grant to active. If the client has not yet
// initiated an authorize request for this route, the grant is created active
// (the operator approval is the security boundary; a token still requires a
// code exchange).
func (m *MemStore) ApproveGrant(clientID, tenant, route string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := grantKey(clientID, tenant, route)
	g, ok := m.grants[k]
	if !ok {
		m.grants[k] = &Grant{
			ClientID:  clientID,
			Tenant:    tenant,
			Route:     route,
			Status:    GrantActive,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		return nil
	}
	g.Status = GrantActive
	g.UpdatedAt = time.Now()
	return nil
}

// RevokeGrant flips a grant to revoked. It is immediate and permanent.
func (m *MemStore) RevokeGrant(clientID, tenant, route string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantKey(clientID, tenant, route)]
	if !ok {
		return fmt.Errorf("authz: no grant to revoke for client %q route %q", clientID, route)
	}
	g.Status = GrantRevoked
	g.UpdatedAt = time.Now()
	return nil
}

// CreateCode stores a code. Codes are single-use and short-lived.
func (m *MemStore) CreateCode(c Code) error {
	if c.Code == "" {
		return fmt.Errorf("authz: code is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.codes[c.Code]; ok {
		return fmt.Errorf("authz: code collision")
	}
	cp := c
	m.codes[c.Code] = &cp
	return nil
}

// ConsumeCode atomically marks a code consumed and returns it. A code can
// only be consumed once; an expired code is rejected.
func (m *MemStore) ConsumeCode(code string) (*Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[code]
	if !ok {
		return nil, fmt.Errorf("authz: unknown authorization code")
	}
	if c.ConsumedAt != nil {
		return nil, fmt.Errorf("authz: authorization code already used")
	}
	if c.Expired() {
		return nil, fmt.Errorf("authz: authorization code expired")
	}
	now := time.Now()
	c.ConsumedAt = &now
	cp := *c
	return &cp, nil
}

// MintCode returns a fresh 32-byte URL-safe authorization code.
func MintCode() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authz: code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// MintClientID returns a fresh 16-byte URL-safe client id.
func MintClientID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authz: client id: %w", err)
	}
	return "cli_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// SortedGrants returns a deterministic list of grants (for the operator UX).
func (m *MemStore) SortedGrants() []Grant {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Grant, 0, len(m.grants))
	for _, g := range m.grants {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Route != out[j].Route {
			return out[i].Route < out[j].Route
		}
		return out[i].ClientID < out[j].ClientID
	})
	return out
}
