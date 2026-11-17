package authz

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Policy bounds for the managed authorization plane. They live beside the
// store because both the durable store (pruning) and the HTTP handlers
// (quotas) enforce them.
const (
	// DefaultPairingTTL bounds one pairing credential: it is single-use,
	// and an unused one dies within this window.
	DefaultPairingTTL = time.Hour
	// DefaultRevocationRetention bounds how long token revocations are
	// retained. It far exceeds any token lifetime, so pruning can never
	// resurrect access.
	DefaultRevocationRetention = 30 * 24 * time.Hour
	// MaxClientsPerRoute bounds public dynamic registration per route.
	MaxClientsPerRoute = 200
	// MaxPendingConsentsPerRoute bounds outstanding (unconsumed,
	// unexpired) consent challenges per route.
	MaxPendingConsentsPerRoute = 100
	// MaxPendingClientAge bounds the normal retention of a registration
	// that has never received operator approval. Public DCR is
	// unauthenticated, so abandoned entries are pruned after this window.
	// At quota, the oldest unrevoked no-grant entry may be evicted earlier;
	// every identity with a grant row and every revoked ID reservation is
	// retained.
	MaxPendingClientAge = 7 * 24 * time.Hour
)

// ErrClientQuota reports a route whose client table is full and contains
// no safely evictable unapproved registration.
var ErrClientQuota = fmt.Errorf("authz: route client quota exhausted")

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
	// Tenant + Route scope the registration to the route it was made
	// through: the relay is a route-scoped Authorization Server, so a
	// client_id minted for one route is not an identity on another.
	Tenant string
	Route  string
}

// Grant is an operator approval binding one client to one tenant + route.
//
// A public client_id is not a credential: anyone who learns it can start an
// authorization flow. The approval therefore also issues a pairing secret
// (stored only as a hash) that the client must present to obtain a code.
// The pairing secret is single-use and expires: each authorization
// transaction consumes one credential, and an ACTIVE grant by itself never
// mints a code. Losing the pairing secret is a compromise of that grant
// until it expires or is rotated, exactly as losing a client secret would be.
type Grant struct {
	ClientID  string
	Tenant    string
	Route     string
	Status    GrantStatus
	CreatedAt time.Time
	UpdatedAt time.Time
	// PairingHash is the hex SHA-256 of the pairing secret. Empty means no
	// pairing secret has been issued; consent then always fails closed.
	PairingHash string
	// PairingIssuedAt is when the current pairing secret was minted.
	PairingIssuedAt time.Time
	// PairingExpiresAt bounds the current pairing secret. Zero means no
	// secret was ever issued.
	PairingExpiresAt time.Time
	// PairingConsumedAt is set once the secret has been used; a consumed
	// secret never authorizes a second transaction.
	PairingConsumedAt *time.Time
	// SkipPairing is true when an operator explicitly approved this grant
	// with --direct, allowing /oauth/authorize to issue an authorization code
	// without showing the interactive pairing_secret consent form.
	SkipPairing bool
	// ClientName and RedirectURIs are populated by ListGrants from
	// authz_clients for operator display.
	ClientName   string
	RedirectURIs []string
}

// Consent is a one-time, expiring, transaction-bound pairing challenge.
// It carries the authorization request it was created for, so a stolen
// challenge cannot be replayed against a different transaction.
type Consent struct {
	Challenge     string
	ClientID      string
	Tenant        string
	Route         string
	RedirectURI   string
	CodeChallenge string
	State         string
	Resource      string
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

// Expired reports whether the challenge has passed its expiry.
func (c *Consent) Expired() bool { return time.Now().After(c.ExpiresAt) }

// AuthzAudit is one authorization-plane decision record.
type AuthzAudit struct {
	Time     time.Time
	Actor    string
	Tenant   string
	Route    string
	ClientID string
	Action   string
	Result   string
	Detail   string
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
	// ApproveGrant flips a grant active. It never resurrects a revoked
	// grant: a revocation is terminal until the grant row is deleted.
	ApproveGrant(clientID, tenant, route string) error
	// ApproveGrantWithPairingSecret atomically activates the grant AND
	// issues the pairing secret: an approval that cannot persist its
	// credential must not leave an ACTIVE grant that no consent can ever
	// complete. It refuses a revoked grant.
	ApproveGrantWithPairingSecret(clientID, tenant, route, secret string, ttl time.Duration) error
	// ApproveGrantDirect activates a grant with skip_pairing=true for a
	// client belonging to the same tenant (including cross-route grants).
	// It refuses unknown clients, cross-tenant clients, and revoked grants.
	ApproveGrantDirect(clientID, tenant, route string) error
	RevokeGrant(clientID, tenant, route string) error
	// RevokeGrantsForRoute revokes every grant of one route in a single
	// step and returns how many rows changed. Removing a route must
	// retire its approvals: an approval is authority over a route that
	// no longer exists, and leaving it active would let a later route
	// with the same id inherit it.
	RevokeGrantsForRoute(tenant, route string) (int, error)

	// SetPairingSecret issues (or rotates) the pairing secret for a grant,
	// storing only its hash. The plaintext is returned once to the
	// operator. ttl bounds the credential; the store stamps its expiry.
	SetPairingSecret(clientID, tenant, route, secret string, ttl time.Duration) error
	// ConsumePairingSecret atomically validates and burns a pairing secret:
	// a secret authorizes exactly one consent transaction and is then
	// dead. Expired or already-consumed secrets fail closed, and the
	// check-and-burn happen in one step so a replay cannot race it.
	ConsumePairingSecret(clientID, tenant, route, secret string) (bool, error)

	// CreateConsent stores a one-time consent challenge.
	CreateConsent(c Consent) error
	// ConsumeConsent atomically marks a challenge consumed and returns it.
	ConsumeConsent(challenge string) (*Consent, error)

	// CountClients reports clients registered for a route.
	CountClients(tenant, route string) (int, error)
	// CountPendingConsents reports unconsumed, unexpired consent
	// challenges for a route.
	CountPendingConsents(tenant, route string) (int, error)
	// TryRegisterClient enforces the per-route client bound and inserts
	// atomically. If full, it evicts the oldest unrevoked registration
	// with no grant; granted identities and revoked ID reservations are
	// retained. ErrClientQuota reports a full route with no safe eviction.
	TryRegisterClient(c Client) error
	// PruneAbandonedClients deletes registrations that are older than
	// MaxPendingClientAge and have NO grant row on this route: pending
	// registrations nobody ever completed are reclaimable so the table
	// cannot be permanently exhausted, while approved and revoked
	// identities (and any client a grant row attaches to) are preserved.
	// It returns how many rows were reclaimed.
	PruneAbandonedClients(now time.Time) (int, error)
	// PruneAuthzExpired deletes lifecycle-expired authorization rows:
	// consumed or expired codes, consumed or expired challenges, and
	// revocations past their retention window. Pruning can never
	// resurrect access: authority lives in grants and clients.
	PruneAuthzExpired(now time.Time) error

	// RevokeToken durably revokes one token by its jti.
	RevokeToken(jti, clientID, tenant, route string) error
	// BurnToken atomically revokes one token by its jti and reports
	// whether THIS call performed the burn. It is the single-use
	// primitive for refresh rotation: exactly one concurrent caller can
	// burn a given refresh token, and every other caller is told it
	// lost. A separate method from RevokeToken because RFC 7009
	// revocation is idempotent (a repeat revoke is a success), while a
	// rotation burn must be observable to the loser.
	BurnToken(jti, clientID, tenant, route string) (bool, error)
	// IsTokenRevoked reports whether a jti is revoked for this tenant+route.
	// Revocation is scoped so one route's revocation cannot affect another.
	IsTokenRevoked(jti, tenant, route string) (bool, error)

	// AuditAuthz records an authorization-plane decision.
	AuditAuthz(actor, tenant, route, clientID, action, result, detail string) error
	// ListAuthzAudit returns the most recent audit records.
	ListAuthzAudit(limit int) ([]AuthzAudit, error)

	CreateCode(c Code) error
	// ConsumeCode atomically marks a code consumed and returns it, scoped
	// to the expected client + tenant + route. The scope check happens
	// before any consumption write, so a foreign route's redemption
	// attempt can neither mint tokens nor destroy another route's code.
	ConsumeCode(code, client, tenant, route string) (*Code, error)
}

// MemStore is an in-memory Store for tests and local evaluation.
type MemStore struct {
	mu          sync.Mutex
	clients     map[string]*Client
	grants      map[string]*Grant // key: clientID + "\x00" + tenant + "\x00" + route
	codes       map[string]*Code
	revocations map[string]time.Time // key: jti\x00tenant\x00route -> revokedAt
	consent     map[string]*Consent
	audit       []AuthzAudit
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		clients: map[string]*Client{},
		grants:  map[string]*Grant{},
		codes:   map[string]*Code{},
	}
}

// HashSecret returns the hex SHA-256 of a secret. Only hashes are stored.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// MintJTI returns a fresh token identifier for revocation tracking.
func MintJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authz: jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// MintPairingSecret returns a fresh pairing secret for an approved grant.
func MintPairingSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authz: pairing secret: %w", err)
	}
	return "pair_" + base64.RawURLEncoding.EncodeToString(buf), nil
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
	c, ok := m.clients[g.ClientID]
	if !ok {
		return fmt.Errorf("authz: grant for unknown client %q", g.ClientID)
	}
	if c.Tenant == "" || c.Route == "" {
		return fmt.Errorf("authz: client %q has no route registration scope; refusing grant", g.ClientID)
	}
	if c.Tenant != g.Tenant || c.Route != g.Route {
		return fmt.Errorf("authz: client %q is registered for tenant %q route %q, not tenant %q route %q",
			g.ClientID, c.Tenant, c.Route, g.Tenant, g.Route)
	}
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
// initiated an authorize request for this route, the grant is created active.
// A revoked grant is never resurrected: approval is not un-revocation.
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
	if g.Status == GrantRevoked {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", clientID, route)
	}
	g.Status = GrantActive
	g.UpdatedAt = time.Now()
	return nil
}

// ApproveGrantWithPairingSecret atomically activates the grant and issues
// the pairing credential. A failure at any step leaves the grant exactly as
// it was: no ACTIVE grant without a usable credential, and no credential
// for an unapproved grant.
func (m *MemStore) ApproveGrantWithPairingSecret(clientID, tenant, route, secret string, ttl time.Duration) error {
	if secret == "" {
		return fmt.Errorf("authz: pairing secret is required")
	}
	if ttl <= 0 {
		return fmt.Errorf("authz: pairing ttl must be positive")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, cok := m.clients[clientID]
	if !cok {
		return fmt.Errorf("authz: approve grant for unknown client %q", clientID)
	}
	if c.Tenant == "" || c.Route == "" {
		return fmt.Errorf("authz: client %q has no route registration scope; refusing approval", clientID)
	}
	if c.Tenant != tenant || c.Route != route {
		return fmt.Errorf("authz: client %q is registered for tenant %q route %q, not tenant %q route %q",
			clientID, c.Tenant, c.Route, tenant, route)
	}
	k := grantKey(clientID, tenant, route)
	now := time.Now()
	g, ok := m.grants[k]
	if !ok {
		g = &Grant{
			ClientID: clientID,
			Tenant:   tenant,
			Route:    route,
			Status:   GrantActive,
		}
		m.grants[k] = g
	}
	if g.Status == GrantRevoked {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", clientID, route)
	}
	g.Status = GrantActive
	g.PairingHash = HashSecret(secret)
	g.PairingIssuedAt = now
	g.PairingExpiresAt = now.Add(ttl)
	g.PairingConsumedAt = nil
	g.UpdatedAt = now
	return nil
}

// ApproveGrantDirect activates a grant with SkipPairing=true for a client
// registered in the same tenant (allowing cross-route grants).
func (m *MemStore) ApproveGrantDirect(clientID, tenant, route string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, cok := m.clients[clientID]
	if !cok {
		return fmt.Errorf("authz: approve grant for unknown client %q", clientID)
	}
	if c.Tenant == "" {
		return fmt.Errorf("authz: client %q has no tenant registration scope; refusing approval", clientID)
	}
	if c.Tenant != tenant {
		return fmt.Errorf("authz: client %q is registered for tenant %q, not tenant %q",
			clientID, c.Tenant, tenant)
	}
	k := grantKey(clientID, tenant, route)
	now := time.Now()
	g, ok := m.grants[k]
	if !ok {
		g = &Grant{
			ClientID:  clientID,
			Tenant:    tenant,
			Route:     route,
			Status:    GrantActive,
			CreatedAt: now,
		}
		m.grants[k] = g
	}
	if g.Status == GrantRevoked {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", clientID, route)
	}
	g.Status = GrantActive
	g.SkipPairing = true
	g.UpdatedAt = now
	return nil
}

// RevokeGrantsForRoute revokes every grant of one route.
func (m *MemStore) RevokeGrantsForRoute(tenant, route string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, g := range m.grants {
		if g.Tenant != tenant || g.Route != route || g.Status == GrantRevoked {
			continue
		}
		g.Status = GrantRevoked
		g.UpdatedAt = time.Now()
		n++
	}
	return n, nil
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

// SetPairingSecret issues (or rotates) the pairing secret for a grant,
// storing only its hash, and stamps its expiry. Rotation clears any
// previous consumption state so a fresh credential starts clean.
func (m *MemStore) SetPairingSecret(clientID, tenant, route, secret string, ttl time.Duration) error {
	if secret == "" {
		return fmt.Errorf("authz: pairing secret is required")
	}
	if ttl <= 0 {
		return fmt.Errorf("authz: pairing ttl must be positive")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantKey(clientID, tenant, route)]
	if !ok {
		return fmt.Errorf("authz: no grant for client %q route %q", clientID, route)
	}
	now := time.Now()
	g.PairingHash = HashSecret(secret)
	g.PairingIssuedAt = now
	g.PairingExpiresAt = now.Add(ttl)
	g.PairingConsumedAt = nil
	g.UpdatedAt = now
	return nil
}

// ConsumePairingSecret validates and burns the secret in one step. A
// missing, expired, consumed, or mismatched secret fails closed; only the
// single correct use marks the credential consumed.
func (m *MemStore) ConsumePairingSecret(clientID, tenant, route, secret string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantKey(clientID, tenant, route)]
	if !ok {
		return false, fmt.Errorf("authz: no grant for client %q route %q", clientID, route)
	}
	if g.PairingHash == "" {
		return false, nil
	}
	if g.PairingConsumedAt != nil {
		return false, nil
	}
	if !g.PairingExpiresAt.IsZero() && time.Now().After(g.PairingExpiresAt) {
		return false, nil
	}
	if !hmac.Equal([]byte(g.PairingHash), []byte(HashSecret(secret))) {
		return false, nil
	}
	now := time.Now()
	g.PairingConsumedAt = &now
	return true, nil
}

// CountClients reports clients registered through one tenant + route.
func (m *MemStore) CountClients(tenant, route string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.clients {
		if c.Tenant == tenant && c.Route == route {
			n++
		}
	}
	return n, nil
}

// TryRegisterClient is the in-memory bound check, safe LRU eviction, and
// insert under the store mutex, so the operation is atomic by construction.
// It deliberately does NOT call RegisterClient: sync.Mutex is not
// reentrant, so the insert is inlined here under the same lock hold.
func (m *MemStore) TryRegisterClient(c Client) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[c.ID]; ok {
		return fmt.Errorf("authz: client %q already registered", c.ID)
	}
	n := 0
	claimed := make(map[string]bool, len(m.grants))
	for _, g := range m.grants {
		if g.Status == GrantActive || g.Status == GrantRevoked {
			claimed[grantKey(g.ClientID, g.Tenant, g.Route)] = true
		}
	}
	oldestID := ""
	var oldest time.Time
	for _, existing := range m.clients {
		if existing.Tenant == c.Tenant && existing.Route == c.Route {
			n++
			if existing.RevokedAt == nil && !claimed[grantKey(existing.ID, existing.Tenant, existing.Route)] &&
				(oldestID == "" || existing.CreatedAt.Before(oldest) ||
					existing.CreatedAt.Equal(oldest) && existing.ID < oldestID) {
				oldestID = existing.ID
				oldest = existing.CreatedAt
			}
		}
	}
	if n >= MaxClientsPerRoute {
		if oldestID == "" {
			return ErrClientQuota
		}
		if victim, ok := m.clients[oldestID]; ok {
			delete(m.grants, grantKey(oldestID, victim.Tenant, victim.Route))
		}
		delete(m.clients, oldestID)
	}
	cp := c
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.clients[c.ID] = &cp
	return nil
}

// PruneAbandonedClients removes registrations older than
// MaxPendingClientAge that no grant row attaches to. A revoked client
// and any client with a grant (active OR revoked) are preserved.
func (m *MemStore) PruneAbandonedClients(now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := now.Add(-MaxPendingClientAge)
	claimed := make(map[string]bool, len(m.grants))
	for _, g := range m.grants {
		if g.Status == GrantActive || g.Status == GrantRevoked {
			claimed[grantKey(g.ClientID, g.Tenant, g.Route)] = true
		}
	}
	n := 0
	for id, c := range m.clients {
		if c.RevokedAt != nil || claimed[grantKey(id, c.Tenant, c.Route)] {
			continue
		}
		if c.CreatedAt.Before(cutoff) {
			delete(m.grants, grantKey(id, c.Tenant, c.Route))
			delete(m.clients, id)
			n++
		}
	}
	return n, nil
}

// CountPendingConsents reports unconsumed, unexpired challenges for a route.
func (m *MemStore) CountPendingConsents(tenant, route string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.consent {
		if c.Tenant == tenant && c.Route == route && c.ConsumedAt == nil && !c.Expired() {
			n++
		}
	}
	return n, nil
}

// PruneAuthzExpired drops consumed/expired codes, consumed/expired
// challenges, and revocations past DefaultRevocationRetention.
func (m *MemStore) PruneAuthzExpired(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for code, c := range m.codes {
		if c.ConsumedAt != nil || now.After(c.ExpiresAt) {
			delete(m.codes, code)
		}
	}
	for ch, c := range m.consent {
		if c.ConsumedAt != nil || now.After(c.ExpiresAt) {
			delete(m.consent, ch)
		}
	}
	cutoff := now.Add(-DefaultRevocationRetention)
	for key, at := range m.revocations {
		if at.Before(cutoff) {
			delete(m.revocations, key)
		}
	}
	return nil
}

// RevokeToken durably revokes a token by jti.
func (m *MemStore) RevokeToken(jti, clientID, tenant, route string) error {
	if jti == "" {
		return fmt.Errorf("authz: token jti is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revocations == nil {
		m.revocations = map[string]time.Time{}
	}
	m.revocations[revocationKey(jti, tenant, route)] = time.Now()
	return nil
}

// BurnToken atomically revokes a token by jti and reports whether THIS
// call performed the burn. The check and the write share the mutex, so
// exactly one of several concurrent callers can burn a given token.
func (m *MemStore) BurnToken(jti, clientID, tenant, route string) (bool, error) {
	if jti == "" {
		return false, fmt.Errorf("authz: token jti is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revocations == nil {
		m.revocations = map[string]time.Time{}
	}
	key := revocationKey(jti, tenant, route)
	if _, already := m.revocations[key]; already {
		return false, nil
	}
	m.revocations[key] = time.Now()
	return true, nil
}

// IsTokenRevoked reports whether a jti is revoked for this tenant+route.
func (m *MemStore) IsTokenRevoked(jti, tenant, route string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revocations[revocationKey(jti, tenant, route)]
	return ok, nil
}

func revocationKey(jti, tenant, route string) string {
	return jti + "\x00" + tenant + "\x00" + route
}

// CreateConsent stores a one-time consent challenge.
func (m *MemStore) CreateConsent(c Consent) error {
	if c.Challenge == "" {
		return fmt.Errorf("authz: consent challenge is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consent == nil {
		m.consent = map[string]*Consent{}
	}
	if _, ok := m.consent[c.Challenge]; ok {
		return fmt.Errorf("authz: consent challenge collision")
	}
	cp := c
	m.consent[c.Challenge] = &cp
	return nil
}

// ConsumeConsent atomically marks a challenge consumed and returns it.
func (m *MemStore) ConsumeConsent(challenge string) (*Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consent[challenge]
	if !ok {
		return nil, fmt.Errorf("authz: unknown consent challenge")
	}
	if c.ConsumedAt != nil {
		return nil, fmt.Errorf("authz: consent challenge already used")
	}
	if c.Expired() {
		return nil, fmt.Errorf("authz: consent challenge expired")
	}
	now := time.Now()
	c.ConsumedAt = &now
	cp := *c
	return &cp, nil
}

// AuditAuthz records an authorization-plane decision.
func (m *MemStore) AuditAuthz(actor, tenant, route, clientID, action, result, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, AuthzAudit{
		Time: time.Now(), Actor: actor, Tenant: tenant, Route: route,
		ClientID: clientID, Action: action, Result: result, Detail: detail,
	})
	return nil
}

// ListAuthzAudit returns the most recent audit records, newest first.
func (m *MemStore) ListAuthzAudit(limit int) ([]AuthzAudit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuthzAudit, 0, len(m.audit))
	for _, a := range m.audit {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
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

// ConsumeCode atomically marks a code consumed and returns it, scoped to
// the expected client + tenant + route. The scope check happens before any
// consumption write, so a foreign route's redemption attempt can neither
// mint tokens nor destroy another route's pending code. A code can only be
// consumed once; an expired code is rejected.
func (m *MemStore) ConsumeCode(code, expectedClient, expectedTenant, expectedRoute string) (*Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[code]
	if !ok {
		return nil, fmt.Errorf("authz: unknown authorization code")
	}
	if c.ClientID != expectedClient || c.Tenant != expectedTenant || c.Route != expectedRoute {
		return nil, fmt.Errorf("authz: authorization code is not bound to this client and route")
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
