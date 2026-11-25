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

// ErrTrustPolicyInactive reports that a trust policy matched prior to
// registration is no longer active, enabled, unrevoked, or exact-matching
// inside the atomic registration transaction.
var ErrTrustPolicyInactive = fmt.Errorf("authz: trust policy is inactive or revoked")

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
	// ClientMode is "public" (default, DCR) or "confidential" (pre-registered
	// with a secret hash, e.g. for Google persistent-linking opaque refresh).
	ClientMode       string
	ClientSecretHash string
	// RefreshPolicy is "" (default rotating) or "google_confidential" (stable
	// opaque refresh token extended in place for Google Connected Apps).
	RefreshPolicy string
}

// OpaqueRefresh represents a persistent, non-rotating opaque refresh token
// bound to a confidential client, tenant, and route.
type OpaqueRefresh struct {
	TokenHash         string
	ClientID          string
	Tenant            string
	Route             string
	Scope             string
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	LastUsedAt        time.Time
	RevokedAt         *time.Time
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
	// Provenance tracks how this grant was authorized (OCL-006): legacy,
	// pairing, direct_operator, trust_policy, or federated_oidc with bound
	// policy/issuer/subject identifiers.
	Provenance GrantProvenance
	// ClientName and RedirectURIs are populated by ListGrants from
	// authz_clients for operator display.
	ClientName   string
	RedirectURIs []string
}

// Consent is a one-time, expiring, transaction-bound authorization challenge.
// It carries the authorization request it was created for, so a stolen
// challenge cannot be replayed against a different transaction. In native
// Ocliv authentication (canonical default), the operator approves or denies
// the specific challenge over the Ed25519-signed management channel without
// copying pairing secrets.
type Consent struct {
	Challenge      string     `json:"challenge"`
	ClientID       string     `json:"client_id"`
	ClientName     string     `json:"client_name,omitempty"`
	Tenant         string     `json:"tenant_id,omitempty"`
	Route          string     `json:"route_id,omitempty"`
	RedirectURI    string     `json:"redirect_uri"`
	CodeChallenge  string     `json:"-"`
	State          string     `json:"-"`
	Resource       string     `json:"resource,omitempty"`
	Scope          string     `json:"scope,omitempty"`
	Decision       string     `json:"decision"` // "pending" | "approved" | "denied"
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	DecidedByKeyID string     `json:"decided_by_key_id,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
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
	Scope           string
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
	// TryRegisterClientWithPendingGrant atomically registers a client and
	// creates its initial GrantPending row in one transaction.
	TryRegisterClientWithPendingGrant(c Client, tenant, route string) error
	// TryRegisterClientWithTrustPolicy atomically verifies that policyID is
	// still active, unrevoked, scoped to (tenant, route), and exact-matching
	// c.RedirectURIs, then registers the client and creates an ACTIVE Grant
	// with SkipPairing=true in one transaction. Returns ErrTrustPolicyInactive
	// if the policy was revoked or modified concurrently.
	TryRegisterClientWithTrustPolicy(c Client, tenant, route, policyID string) error

	// Trust policy management (route-scoped exact-redirect policies).
	CreateTrustPolicy(p ClientTrustPolicy) error
	ListTrustPolicies(tenant, route string) ([]ClientTrustPolicy, error)
	RevokeTrustPolicy(tenant, route, idOrKind string) (int, error)
	MatchTrustPolicy(tenant, route string, redirectURIs []string) (*ClientTrustPolicy, error)

	// Federated visitor authorization policies & single-use OIDC transactions (OCL-005).
	SetVisitorAuthPolicy(p VisitorAuthPolicy) error
	GetVisitorAuthPolicy(tenant, route string) (*VisitorAuthPolicy, error)
	RevokeVisitorAuthPolicy(tenant, route string) (int, error)
	CreateOIDCTransaction(tx OIDCTransaction) error
	ConsumeOIDCTransaction(state, expectedTenant, expectedRoute string) (*OIDCTransaction, error)
	CountPendingOIDCTransactions(tenant, route string) (int, error)

	// ApproveGrantWithProvenance atomically activates a grant with explicit
	// provenance (e.g. federated_oidc + trust_policy_id + issuer + subject).
	// It refuses unknown/wrong-tenant clients and never resurrects a revoked grant.
	ApproveGrantWithProvenance(clientID, tenant, route string, skipPairing bool, prov GrantProvenance) error
	// ApproveFederatedGrantAtomic transactionally validates client identity,
	// publication state, current trust policy, current visitor policy state &
	// revision, allowed issuer/subject, and grant revocation state in ONE
	// atomic transaction before activating a federated grant (OCL-005).
	ApproveFederatedGrantAtomic(req FederatedGrantActivation) error
	CreateOpaqueRefresh(r OpaqueRefresh) error
	RotateOpaqueRefresh(oldHash, newHash, clientID, tenant, route string, now time.Time, extendBy time.Duration) (*OpaqueRefresh, error)
	ExtendOpaqueRefresh(tokenHash, clientID, tenant, route string, now time.Time, extendBy time.Duration) (*OpaqueRefresh, error)
	RevokeOpaqueRefresh(tokenHash, tenant, route string, now time.Time) error
	RevokeOpaqueRefreshForClient(clientID string) error

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
	// ListPendingConsents returns unconsumed, unexpired, pending consent
	// transactions for (tenant, route), newest first.
	ListPendingConsents(tenant, route string) ([]Consent, error)
	// GetConsentStatus returns the current state of a consent challenge
	// scoped to (tenant, route) without consuming it.
	GetConsentStatus(challenge, tenant, route string) (*Consent, error)
	// DecideConsentTransaction atomically approves or denies one pending
	// consent transaction on behalf of the authenticated publisher operator
	// (Ed25519 keyID). Approval activates the durable grant (operator_tx) in
	// the same transaction without issuing or copying pairing secrets.
	DecideConsentTransaction(challenge, tenant, route, operatorKeyID string, approve bool) (*Consent, error)
	// ConsumeDecidedConsent atomically consumes an approved or denied consent
	// transaction scoped to (tenant, route) so it can complete the OAuth
	// browser redirect at most once.
	ConsumeDecidedConsent(challenge, expectedTenant, expectedRoute string) (*Consent, error)

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

	// RecordHostObservation records a privacy-safe external host OAuth/MCP
	// lifecycle observation (OCL-009).
	RecordHostObservation(obs HostObservation) error
	// ListHostObservations returns recent host observations for a route, newest first.
	ListHostObservations(tenant, route string, limit int) ([]HostObservation, error)

	CreateCode(c Code) error
	// ConsumeCode atomically marks a code consumed and returns it, scoped
	// to the expected client + tenant + route. The scope check happens
	// before any consumption write, so a foreign route's redemption
	// attempt can neither mint tokens nor destroy another route's code.
	ConsumeCode(code, client, tenant, route string) (*Code, error)
}

// MemStore is an in-memory Store for tests and local evaluation.
type MemStore struct {
	mu              sync.Mutex
	clients         map[string]*Client
	grants          map[string]*Grant // key: clientID + "\x00" + tenant + "\x00" + route
	codes           map[string]*Code
	revocations     map[string]time.Time // key: jti\x00tenant\x00route -> revokedAt
	consent         map[string]*Consent
	audit           []AuthzAudit
	hostObs         []HostObservation
	opaqueRefresh   map[string]*OpaqueRefresh
	trustPolicies   map[string]*ClientTrustPolicy
	visitorPolicies map[string]*VisitorAuthPolicy // key: tenant + "\x00" + route
	oidcTx          map[string]*OIDCTransaction
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
	if vp, ok := m.visitorPolicies[visitorPolicyKey(tenant, route)]; ok && vp.IsActiveFederated() {
		return fmt.Errorf("%w: pairing approval is prohibited on federated route", ErrFederatedPolicyRequired)
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
	g.Provenance = GrantProvenance{Method: GrantMethodPairing}
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
	if vp, ok := m.visitorPolicies[visitorPolicyKey(tenant, route)]; ok && vp.IsActiveFederated() {
		return fmt.Errorf("%w: direct approval is prohibited on federated route", ErrFederatedPolicyRequired)
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
	g.Provenance = GrantProvenance{Method: GrantMethodDirectOperator}
	g.UpdatedAt = now
	return nil
}

// ApproveGrantWithProvenance atomically activates a grant with explicit
// authorization provenance (OCL-005, OCL-006).
func (m *MemStore) ApproveGrantWithProvenance(clientID, tenant, route string, skipPairing bool, prov GrantProvenance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, cok := m.clients[clientID]
	if !cok {
		return fmt.Errorf("authz: approve grant for unknown client %q", clientID)
	}
	if c.Tenant == "" || c.Tenant != tenant {
		return fmt.Errorf("authz: client %q is not registered for tenant %q", clientID, tenant)
	}
	if prov.Method == "" {
		prov.Method = GrantMethodLegacy
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
	g.SkipPairing = skipPairing
	g.Provenance = prov
	g.UpdatedAt = now
	return nil
}

// ApproveFederatedGrantAtomic transactionally validates client identity,
// redirect URI, current visitor policy state & revision, allowed issuer &
// subject, current trust policy, and grant revocation under the store lock
// before activating the federated grant (OCL-005).
func (m *MemStore) ApproveFederatedGrantAtomic(req FederatedGrantActivation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, cok := m.clients[req.ClientID]
	if !cok || c.RevokedAt != nil {
		return fmt.Errorf("authz: client %q unknown or revoked", req.ClientID)
	}
	if c.Tenant == "" || c.Tenant != req.Tenant || (c.Route != "" && c.Route != req.Route) {
		return fmt.Errorf("authz: client %q is not bound to tenant %q route %q", req.ClientID, req.Tenant, req.Route)
	}
	if req.RedirectURI != "" {
		if err := ValidateRedirectURI(req.RedirectURI, c.RedirectURIs); err != nil {
			return fmt.Errorf("authz: redirect_uri not bound to client: %w", err)
		}
	}
	vp, ok := m.visitorPolicies[visitorPolicyKey(req.Tenant, req.Route)]
	if !ok || !vp.IsActiveFederated() {
		return fmt.Errorf("%w: visitor auth policy inactive", ErrPolicyRevisionMismatch)
	}
	if req.ExpectedPolicyRevision > 0 && vp.Revision != req.ExpectedPolicyRevision {
		return fmt.Errorf("%w: expected revision %d, current %d", ErrPolicyRevisionMismatch, req.ExpectedPolicyRevision, vp.Revision)
	}
	if !vp.AllowsSubject(req.OwnerIssuer, req.OwnerSubject) {
		return fmt.Errorf("authz: subject %q under issuer %q is not allowed by active visitor policy", req.OwnerSubject, req.OwnerIssuer)
	}
	if vp.ClientPolicy != "" || req.TrustPolicyID != "" {
		if req.TrustPolicyID == "" {
			return fmt.Errorf("%w: missing required trust policy binding", ErrTrustPolicyInactive)
		}
		tp, tpok := m.trustPolicies[req.TrustPolicyID]
		if !tpok || !tp.Enabled || tp.RevokedAt != nil || tp.TenantID != req.Tenant || tp.RouteID != req.Route {
			return ErrTrustPolicyInactive
		}
		if !ExactRedirectURISetEqual(tp.RedirectURIs, c.RedirectURIs) {
			return ErrTrustPolicyInactive
		}
		if vp.ClientPolicy != "" && vp.ClientPolicy != "custom" && tp.Kind != vp.ClientPolicy {
			return ErrTrustPolicyInactive
		}
	}
	k := grantKey(req.ClientID, req.Tenant, req.Route)
	now := time.Now().UTC()
	g, exists := m.grants[k]
	if exists && g.Status == GrantRevoked {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", req.ClientID, req.Route)
	}
	if !exists {
		g = &Grant{
			ClientID:  req.ClientID,
			Tenant:    req.Tenant,
			Route:     req.Route,
			CreatedAt: now,
		}
		m.grants[k] = g
	}
	g.Status = GrantActive
	g.SkipPairing = false
	g.Provenance = GrantProvenance{
		Method:        GrantMethodFederatedOIDC,
		TrustPolicyID: req.TrustPolicyID,
		OwnerIssuer:   req.OwnerIssuer,
		OwnerSubject:  req.OwnerSubject,
	}
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
	return m.tryRegisterClientLocked(c)
}

func (m *MemStore) tryRegisterClientLocked(c Client) error {
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

// ListPendingConsents returns unconsumed, unexpired, pending consent
// transactions for (tenant, route), newest first.
func (m *MemStore) ListPendingConsents(tenant, route string) ([]Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Consent, 0)
	for _, c := range m.consent {
		dec := c.Decision
		if dec == "" {
			dec = "pending"
		}
		if c.Tenant == tenant && c.Route == route && c.ConsumedAt == nil && !c.Expired() && dec == "pending" {
			cp := *c
			cp.Decision = dec
			if cl, ok := m.clients[c.ClientID]; ok && cl != nil {
				cp.ClientName = cl.Name
			}
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExpiresAt.After(out[j].ExpiresAt)
	})
	return out, nil
}

// GetConsentStatus returns the current state of a consent challenge scoped to
// (tenant, route) without consuming it.
func (m *MemStore) GetConsentStatus(challenge, tenant, route string) (*Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consent[challenge]
	if !ok || c.Tenant != tenant || c.Route != route {
		return nil, fmt.Errorf("authz: unknown consent challenge")
	}
	cp := *c
	if cp.Decision == "" {
		cp.Decision = "pending"
	}
	return &cp, nil
}

// DecideConsentTransaction atomically approves or denies one pending consent
// transaction on behalf of the authenticated publisher operator (Ed25519 keyID).
func (m *MemStore) DecideConsentTransaction(challenge, tenant, route, operatorKeyID string, approve bool) (*Consent, error) {
	if challenge == "" || tenant == "" || route == "" {
		return nil, fmt.Errorf("authz: challenge, tenant, and route are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if vp, ok := m.visitorPolicies[visitorPolicyKey(tenant, route)]; ok && vp.IsActiveFederated() {
		return nil, fmt.Errorf("%w: native consent decision prohibited on federated route", ErrFederatedPolicyRequired)
	}
	c, ok := m.consent[challenge]
	if !ok || c.Tenant != tenant || c.Route != route {
		return nil, fmt.Errorf("authz: unknown consent challenge")
	}
	if c.ConsumedAt != nil {
		return nil, fmt.Errorf("authz: consent challenge already consumed")
	}
	if c.Expired() {
		return nil, fmt.Errorf("authz: consent challenge expired")
	}
	if c.Decision != "" && c.Decision != "pending" {
		return nil, fmt.Errorf("authz: consent challenge already %s", c.Decision)
	}
	cl, cok := m.clients[c.ClientID]
	if !cok || cl.RevokedAt != nil || cl.Tenant != tenant || (cl.Route != "" && cl.Route != route) {
		return nil, fmt.Errorf("authz: client %q is unknown or revoked", c.ClientID)
	}
	now := time.Now().UTC()
	if approve {
		k := grantKey(c.ClientID, tenant, route)
		g, gok := m.grants[k]
		if gok && g.Status == GrantRevoked {
			return nil, fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", c.ClientID, route)
		}
		if !gok {
			g = &Grant{ClientID: c.ClientID, Tenant: tenant, Route: route, CreatedAt: now}
			m.grants[k] = g
		}
		g.Status = GrantActive
		g.SkipPairing = false
		g.Provenance = GrantProvenance{Method: GrantMethodOperatorTx}
		g.UpdatedAt = now
		c.Decision = "approved"
	} else {
		c.Decision = "denied"
	}
	t := now
	c.DecidedAt = &t
	c.DecidedByKeyID = operatorKeyID
	cp := *c
	cp.ClientName = cl.Name
	return &cp, nil
}

// ConsumeDecidedConsent atomically consumes an approved or denied consent
// transaction scoped to (tenant, route) so it can complete at most once.
func (m *MemStore) ConsumeDecidedConsent(challenge, expectedTenant, expectedRoute string) (*Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consent[challenge]
	if !ok || c.Tenant != expectedTenant || c.Route != expectedRoute {
		return nil, fmt.Errorf("authz: unknown consent challenge")
	}
	if c.ConsumedAt != nil {
		return nil, fmt.Errorf("authz: consent challenge already consumed")
	}
	if c.Expired() {
		return nil, fmt.Errorf("authz: consent challenge expired")
	}
	if c.Decision != "approved" && c.Decision != "denied" {
		return nil, fmt.Errorf("authz: consent challenge is still pending operator decision")
	}
	now := time.Now().UTC()
	c.ConsumedAt = &now
	cp := *c
	return &cp, nil
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
	for st, tx := range m.oidcTx {
		if tx.ConsumedAt != nil || now.After(tx.ExpiresAt) {
			delete(m.oidcTx, st)
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

// RecordHostObservation stores a non-secret host observation in memory.
func (m *MemStore) RecordHostObservation(obs HostObservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	if obs.TransportStatus == "" {
		obs.TransportStatus = "ok"
	}
	if obs.ResultCategory == "" {
		obs.ResultCategory = "ok"
	}
	m.hostObs = append(m.hostObs, obs)
	// Enforce bounded per-route retention (OCL-009).
	count := 0
	for _, o := range m.hostObs {
		if o.TenantID == obs.TenantID && o.RouteID == obs.RouteID {
			count++
		}
	}
	if count > MaxHostObservationsPerRoute {
		excess := count - MaxHostObservationsPerRoute
		kept := make([]HostObservation, 0, len(m.hostObs)-excess)
		for _, o := range m.hostObs {
			if excess > 0 && o.TenantID == obs.TenantID && o.RouteID == obs.RouteID {
				excess--
				continue
			}
			kept = append(kept, o)
		}
		m.hostObs = kept
	}
	return nil
}

// ListHostObservations returns recent observations for (tenant, route), newest first.
func (m *MemStore) ListHostObservations(tenant, route string, limit int) ([]HostObservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 {
		limit = 50
	}
	out := make([]HostObservation, 0)
	for i := len(m.hostObs) - 1; i >= 0; i-- {
		o := m.hostObs[i]
		if o.TenantID == tenant && o.RouteID == route {
			out = append(out, o)
			if len(out) >= limit {
				break
			}
		}
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

func (m *MemStore) TryRegisterClientWithPendingGrant(c Client, tenant, route string) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	if tenant == "" || route == "" {
		return fmt.Errorf("authz: tenant and route are required for pending grant")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.tryRegisterClientLocked(c); err != nil {
		return err
	}
	now := time.Now()
	cp := Grant{
		ClientID:  c.ID,
		Tenant:    tenant,
		Route:     route,
		Status:    GrantPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	m.grants[grantKey(c.ID, tenant, route)] = &cp
	return nil
}

func (m *MemStore) CreateOpaqueRefresh(r OpaqueRefresh) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.opaqueRefresh == nil {
		m.opaqueRefresh = map[string]*OpaqueRefresh{}
	}
	cp := r
	m.opaqueRefresh[r.TokenHash] = &cp
	return nil
}

func (m *MemStore) RotateOpaqueRefresh(oldHash, newHash, clientID, tenant, route string, now time.Time, extendBy time.Duration) (*OpaqueRefresh, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.opaqueRefresh == nil {
		return nil, fmt.Errorf("authz: opaque refresh not found")
	}
	r, ok := m.opaqueRefresh[oldHash]
	if !ok {
		return nil, fmt.Errorf("authz: opaque refresh not found")
	}
	if r.ClientID != clientID || r.Tenant != tenant || r.Route != route {
		return nil, fmt.Errorf("authz: opaque refresh binding mismatch")
	}
	if r.RevokedAt != nil {
		// Replay detected: revoke the entire opaque refresh lineage for this client.
		for _, tok := range m.opaqueRefresh {
			if tok.ClientID == clientID && tok.Tenant == tenant && tok.Route == route && tok.RevokedAt == nil {
				t := now
				tok.RevokedAt = &t
			}
		}
		return nil, fmt.Errorf("authz: opaque refresh replay detected")
	}
	if now.After(r.ExpiresAt) || now.After(r.AbsoluteExpiresAt) {
		return nil, fmt.Errorf("authz: opaque refresh expired")
	}
	t := now
	r.RevokedAt = &t
	nextExp := now.Add(extendBy)
	if nextExp.After(r.AbsoluteExpiresAt) {
		nextExp = r.AbsoluteExpiresAt
	}
	next := &OpaqueRefresh{
		TokenHash:         newHash,
		ClientID:          clientID,
		Tenant:            tenant,
		Route:             route,
		Scope:             r.Scope,
		ExpiresAt:         nextExp,
		AbsoluteExpiresAt: r.AbsoluteExpiresAt,
		LastUsedAt:        now,
	}
	m.opaqueRefresh[newHash] = next
	cp := *next
	return &cp, nil
}

func (m *MemStore) ExtendOpaqueRefresh(tokenHash, clientID, tenant, route string, now time.Time, extendBy time.Duration) (*OpaqueRefresh, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.opaqueRefresh == nil {
		return nil, fmt.Errorf("authz: opaque refresh not found")
	}
	r, ok := m.opaqueRefresh[tokenHash]
	if !ok || r.RevokedAt != nil {
		return nil, fmt.Errorf("authz: opaque refresh revoked or not found")
	}
	if r.ClientID != clientID || r.Tenant != tenant || r.Route != route {
		return nil, fmt.Errorf("authz: opaque refresh binding mismatch")
	}
	if now.After(r.ExpiresAt) || now.After(r.AbsoluteExpiresAt) {
		return nil, fmt.Errorf("authz: opaque refresh expired")
	}
	nextExp := now.Add(extendBy)
	if nextExp.After(r.AbsoluteExpiresAt) {
		nextExp = r.AbsoluteExpiresAt
	}
	r.ExpiresAt = nextExp
	r.LastUsedAt = now
	cp := *r
	return &cp, nil
}

func (m *MemStore) RevokeOpaqueRefresh(tokenHash, tenant, route string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.opaqueRefresh == nil {
		return nil
	}
	if r, ok := m.opaqueRefresh[tokenHash]; ok && r.Tenant == tenant && r.Route == route && r.RevokedAt == nil {
		t := now
		r.RevokedAt = &t
	}
	return nil
}

func (m *MemStore) RevokeOpaqueRefreshForClient(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, r := range m.opaqueRefresh {
		if r.ClientID == clientID && r.RevokedAt == nil {
			t := now
			r.RevokedAt = &t
		}
	}
	return nil
}

// TryRegisterClientWithTrustPolicy atomically verifies policyID under the
// store mutex, registers the client, and creates its ACTIVE direct grant.
func (m *MemStore) TryRegisterClientWithTrustPolicy(c Client, tenant, route, policyID string) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	if tenant == "" || route == "" || policyID == "" {
		return ErrTrustPolicyInactive
	}
	if c.Tenant != tenant || c.Route != route {
		return ErrTrustPolicyInactive
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pol, ok := m.trustPolicies[policyID]
	if !ok || !pol.Enabled || pol.RevokedAt != nil || pol.TenantID != tenant || pol.RouteID != route {
		return ErrTrustPolicyInactive
	}
	if !ExactRedirectURISetEqual(pol.RedirectURIs, c.RedirectURIs) {
		return ErrTrustPolicyInactive
	}
	if err := m.tryRegisterClientLocked(c); err != nil {
		return err
	}
	now := c.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	m.grants[grantKey(c.ID, tenant, route)] = &Grant{
		ClientID:    c.ID,
		Tenant:      tenant,
		Route:       route,
		Status:      GrantActive,
		SkipPairing: true,
		Provenance: GrantProvenance{
			Method:        GrantMethodTrustPolicy,
			TrustPolicyID: policyID,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	return nil
}

// CreateTrustPolicy stores a route-scoped exact-redirect trust policy.
func (m *MemStore) CreateTrustPolicy(p ClientTrustPolicy) error {
	if p.ID == "" || p.TenantID == "" || p.RouteID == "" {
		return fmt.Errorf("authz: trust policy requires id, tenant_id, and route_id")
	}
	uris, err := ValidateTrustRedirectURIs(p.RedirectURIs)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.trustPolicies == nil {
		m.trustPolicies = map[string]*ClientTrustPolicy{}
	}
	if _, exists := m.trustPolicies[p.ID]; exists {
		return fmt.Errorf("authz: trust policy %q already exists", p.ID)
	}
	cp := p
	cp.RedirectURIs = uris
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	m.trustPolicies[p.ID] = &cp
	return nil
}

// ListTrustPolicies returns active, unrevoked trust policies for a route.
func (m *MemStore) ListTrustPolicies(tenant, route string) ([]ClientTrustPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ClientTrustPolicy, 0)
	for _, p := range m.trustPolicies {
		if p.TenantID == tenant && p.RouteID == route && p.Enabled && p.RevokedAt == nil {
			cp := *p
			cp.RedirectURIs = append([]string(nil), p.RedirectURIs...)
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// RevokeTrustPolicy revokes matching active trust policies by ID or kind, and
// atomically revokes all grants and opaque refresh tokens derived from those
// policies while leaving separately authorized grants intact (OCL-006).
func (m *MemStore) RevokeTrustPolicy(tenant, route, idOrKind string) (int, error) {
	if idOrKind == "" {
		return 0, fmt.Errorf("authz: policy id or kind is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	revokedIDs := map[string]bool{}
	n := 0
	for _, p := range m.trustPolicies {
		if p.TenantID == tenant && p.RouteID == route && p.RevokedAt == nil && (p.ID == idOrKind || p.Kind == idOrKind) {
			t := now
			p.Enabled = false
			p.RevokedAt = &t
			revokedIDs[p.ID] = true
			n++
		}
	}
	if len(revokedIDs) > 0 {
		for _, g := range m.grants {
			if g.Tenant == tenant && g.Route == route && g.Status != GrantRevoked && revokedIDs[g.Provenance.TrustPolicyID] {
				g.Status = GrantRevoked
				g.UpdatedAt = now
				for _, r := range m.opaqueRefresh {
					if r.ClientID == g.ClientID && r.Tenant == tenant && r.Route == route && r.RevokedAt == nil {
						t := now
						r.RevokedAt = &t
					}
				}
			}
		}
	}
	return n, nil
}

func visitorPolicyKey(tenant, route string) string {
	return tenant + "\x00" + route
}

// SetVisitorAuthPolicy configures or updates the route's visitor auth policy.
func (m *MemStore) SetVisitorAuthPolicy(p VisitorAuthPolicy) error {
	clean, err := ValidateVisitorAuthPolicy(p)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.visitorPolicies == nil {
		m.visitorPolicies = map[string]*VisitorAuthPolicy{}
	}
	key := visitorPolicyKey(clean.TenantID, clean.RouteID)
	now := time.Now().UTC()
	var rev int64 = 1
	if prev, ok := m.visitorPolicies[key]; ok && prev != nil {
		rev = prev.Revision + 1
		if clean.Mode == VisitorAuthModeFederated && clean.ClientSecret == "" &&
			prev.Issuer == clean.Issuer && prev.ClientID == clean.ClientID {
			clean.ClientSecret = prev.ClientSecret
		}
	}
	if clean.CreatedAt.IsZero() {
		clean.CreatedAt = now
	}
	clean.Revision = rev
	clean.UpdatedAt = now
	clean.RevokedAt = nil
	cp := clean
	m.visitorPolicies[key] = &cp
	return nil
}

// GetVisitorAuthPolicy returns the active, unrevoked visitor auth policy for (tenant, route).
func (m *MemStore) GetVisitorAuthPolicy(tenant, route string) (*VisitorAuthPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.visitorPolicies[visitorPolicyKey(tenant, route)]
	if !ok || !p.Enabled || p.RevokedAt != nil {
		return nil, nil
	}
	cp := *p
	cp.AllowedSubjects = append([]string(nil), p.AllowedSubjects...)
	return &cp, nil
}

// RevokeVisitorAuthPolicy disables the route's visitor auth policy and
// atomically revokes dependent federated grants and opaque refresh tokens.
func (m *MemStore) RevokeVisitorAuthPolicy(tenant, route string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.visitorPolicies[visitorPolicyKey(tenant, route)]
	if !ok || p.RevokedAt != nil {
		return 0, nil
	}
	now := time.Now().UTC()
	t := now
	p.Enabled = false
	p.RevokedAt = &t
	p.UpdatedAt = now
	for _, g := range m.grants {
		if g.Tenant == tenant && g.Route == route && g.Status != GrantRevoked && g.Provenance.Method == GrantMethodFederatedOIDC {
			g.Status = GrantRevoked
			g.UpdatedAt = now
			for _, r := range m.opaqueRefresh {
				if r.ClientID == g.ClientID && r.Tenant == tenant && r.Route == route && r.RevokedAt == nil {
					rt := now
					r.RevokedAt = &rt
				}
			}
		}
	}
	return 1, nil
}

func (m *MemStore) CreateOIDCTransaction(tx OIDCTransaction) error {
	if tx.State == "" || tx.Nonce == "" {
		return fmt.Errorf("authz: oidc transaction requires state and nonce")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.oidcTx == nil {
		m.oidcTx = map[string]*OIDCTransaction{}
	}
	if _, dup := m.oidcTx[tx.State]; dup {
		return fmt.Errorf("authz: oidc transaction state collision")
	}
	cp := tx
	m.oidcTx[tx.State] = &cp
	return nil
}

func (m *MemStore) ConsumeOIDCTransaction(state, expectedTenant, expectedRoute string) (*OIDCTransaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.oidcTx[state]
	if !ok {
		return nil, fmt.Errorf("authz: unknown oidc transaction state")
	}
	if tx.Tenant != expectedTenant || tx.Route != expectedRoute {
		return nil, fmt.Errorf("authz: oidc transaction is not bound to this route")
	}
	if tx.ConsumedAt != nil {
		return nil, fmt.Errorf("authz: oidc transaction already consumed")
	}
	if tx.Expired() {
		return nil, fmt.Errorf("authz: oidc transaction expired")
	}
	now := time.Now().UTC()
	tx.ConsumedAt = &now
	cp := *tx
	return &cp, nil
}

func (m *MemStore) CountPendingOIDCTransactions(tenant, route string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, tx := range m.oidcTx {
		if tx.Tenant == tenant && tx.Route == route && tx.ConsumedAt == nil && !tx.Expired() {
			n++
		}
	}
	return n, nil
}

// MatchTrustPolicy returns the first active policy on (tenant, route) whose
// RedirectURIs set exactly equals redirectURIs.
func (m *MemStore) MatchTrustPolicy(tenant, route string, redirectURIs []string) (*ClientTrustPolicy, error) {
	policies, err := m.ListTrustPolicies(tenant, route)
	if err != nil {
		return nil, err
	}
	for i := range policies {
		if ExactRedirectURISetEqual(policies[i].RedirectURIs, redirectURIs) {
			cp := policies[i]
			cp.RedirectURIs = append([]string(nil), policies[i].RedirectURIs...)
			return &cp, nil
		}
	}
	return nil, nil
}
