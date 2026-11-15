package authz

import (
	"bytes"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SQLStore is the durable Store backed by the relay database (schemaV8).
// It is safe for concurrent use; SQLite serializes writers.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore wraps a database handle. The schemaV8 tables must exist.
func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// RegisterClient inserts a client. A duplicate id is rejected. The client
// is scoped to the tenant + route it registered through: a public
// registration is never a cross-route identity.
func (s *SQLStore) RegisterClient(c Client) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("authz: redirect uris: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id) VALUES(?,?,?,?,?,?)`,
		c.ID, c.Name, string(uris), now, c.Tenant, c.Route)
	if err != nil {
		return fmt.Errorf("authz: register client: %w", err)
	}
	return nil
}

// GetClient loads a client. A revoked client is returned with RevokedAt set.
func (s *SQLStore) GetClient(id string) (*Client, error) {
	var (
		c         Client
		uris      string
		createdAt string
		revoked   sql.NullString
	)
	err := s.db.QueryRow(
		`SELECT id, name, redirect_uris, created_at, revoked_at, tenant_id, route_id
		 FROM authz_clients WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &uris, &createdAt, &revoked, &c.Tenant, &c.Route)
	if err != nil {
		return nil, fmt.Errorf("authz: get client: %w", err)
	}
	_ = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		c.CreatedAt = t
	}
	if revoked.Valid {
		t, _ := time.Parse(time.RFC3339Nano, revoked.String)
		c.RevokedAt = &t
	}
	return &c, nil
}

// CountClients reports clients registered through one tenant + route.
// Revoked clients still count: their id reservation is permanent.
func (s *SQLStore) CountClients(tenant, route string) (int, error) {
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(1) FROM authz_clients WHERE tenant_id=? AND route_id=?`, tenant, route).Scan(&n); err != nil {
		return 0, fmt.Errorf("authz: count clients: %w", err)
	}
	return n, nil
}

// TryRegisterClient registers a client only if the route's client table
// still has room, with the bound check and the insert inside ONE
// transaction: two separate statements would let concurrent public
// registrations both observe room for one and both insert, crossing the
// bound. Revoked registrations still count: their id reservation is
// permanent.
func (s *SQLStore) TryRegisterClient(c Client) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("authz: redirect uris: %w", err)
	}
	createdAt := c.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("authz: register tx: %w", err)
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(
		`SELECT COUNT(1) FROM authz_clients WHERE tenant_id=? AND route_id=?`,
		c.Tenant, c.Route).Scan(&n); err != nil {
		return fmt.Errorf("authz: count clients: %w", err)
	}
	if n >= MaxClientsPerRoute {
		return ErrClientQuota
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id) VALUES(?,?,?,?,?,?)`,
		c.ID, c.Name, string(uris), createdAt.UTC().Format(time.RFC3339Nano), c.Tenant, c.Route); err != nil {
		return fmt.Errorf("authz: register client: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: register commit: %w", err)
	}
	return nil
}

// PruneAbandonedClients reclaims registrations that are older than
// MaxPendingClientAge and have NO grant row on their route. The predicate
// preserves every identity with authorization state: a revoked client
// (its id reservation is security-relevant), and any client a grant row
// attaches to — active or revoked. Deleting those would forge a new
// identity over retained authority.
func (s *SQLStore) PruneAbandonedClients(now time.Time) (int, error) {
	cutoff := now.Add(-MaxPendingClientAge).UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`DELETE FROM authz_clients
		 WHERE created_at < ? AND revoked_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM authz_grants g
		                    WHERE g.client_id=authz_clients.id
		                      AND g.tenant_id=authz_clients.tenant_id
		                      AND g.route_id=authz_clients.route_id)`,
		cutoff)
	if err != nil {
		return 0, fmt.Errorf("authz: prune abandoned clients: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RevokeClient marks a client revoked. The row is retained so the id cannot
// be re-registered to bypass the revocation.
func (s *SQLStore) RevokeClient(id string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`UPDATE authz_clients SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, now, id)
	if err != nil {
		return fmt.Errorf("authz: revoke client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("authz: unknown client %q", id)
	}
	return nil
}

// CreateGrant inserts a grant. An existing grant is rejected so a pending
// approval cannot be silently overwritten.
func (s *SQLStore) CreateGrant(g Grant) error {
	if g.ClientID == "" || g.Tenant == "" || g.Route == "" {
		return fmt.Errorf("authz: grant requires client, tenant, and route")
	}
	client, cerr := s.GetClient(g.ClientID)
	if cerr != nil {
		return fmt.Errorf("authz: grant for unknown client %q: %w", g.ClientID, cerr)
	}
	if client.Tenant == "" || client.Route == "" {
		return fmt.Errorf("authz: client %q has no route registration scope; refusing grant", g.ClientID)
	}
	if client.Tenant != g.Tenant || client.Route != g.Route {
		return fmt.Errorf("authz: client %q is registered for tenant %q route %q, not tenant %q route %q",
			g.ClientID, client.Tenant, client.Route, g.Tenant, g.Route)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
		g.ClientID, g.Tenant, g.Route, string(g.Status), now, now)
	if err != nil {
		return fmt.Errorf("authz: create grant: %w", err)
	}
	return nil
}

// GetGrant loads a grant.
func (s *SQLStore) GetGrant(clientID, tenant, route string) (*Grant, error) {
	var (
		g              Grant
		status         string
		createdAt      string
		updatedAt      string
		pairingHash    string
		pairingIssued  string
		pairingExpires string
		pairingUsed    sql.NullString
	)
	err := s.db.QueryRow(
		`SELECT client_id, tenant_id, route_id, status, created_at, updated_at,
		        pairing_hash, pairing_issued_at, pairing_expires_at, pairing_consumed_at
		 FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).
		Scan(&g.ClientID, &g.Tenant, &g.Route, &status, &createdAt, &updatedAt,
			&pairingHash, &pairingIssued, &pairingExpires, &pairingUsed)
	if err != nil {
		return nil, fmt.Errorf("authz: get grant: %w", err)
	}
	g.Status = GrantStatus(status)
	g.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	g.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	g.PairingHash = pairingHash
	g.PairingIssuedAt, _ = time.Parse(time.RFC3339Nano, pairingIssued)
	g.PairingExpiresAt, _ = time.Parse(time.RFC3339Nano, pairingExpires)
	if pairingUsed.Valid {
		t, _ := time.Parse(time.RFC3339Nano, pairingUsed.String)
		g.PairingConsumedAt = &t
	}
	return &g, nil
}

// SetPairingSecret stores only the hash of the pairing secret, stamps its
// expiry, and clears any prior consumption so a rotated credential starts
// clean. It fails if the grant does not exist: a silently-dropped secret
// would look like a successful approval while the consent step can never
// succeed.
func (s *SQLStore) SetPairingSecret(clientID, tenant, route, secret string, ttl time.Duration) error {
	if secret == "" {
		return fmt.Errorf("authz: pairing secret is required")
	}
	if ttl <= 0 {
		return fmt.Errorf("authz: pairing ttl must be positive")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	expires := time.Now().UTC().Add(ttl).Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`UPDATE authz_grants SET pairing_hash=?, pairing_issued_at=?, pairing_expires_at=?,
		 pairing_consumed_at=NULL, updated_at=?
		 WHERE client_id=? AND tenant_id=? AND route_id=?`,
		HashSecret(secret), now, expires, now, clientID, tenant, route)
	if err != nil {
		return fmt.Errorf("authz: set pairing secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("authz: set pairing secret: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("authz: no grant for client %q tenant %q route %q", clientID, tenant, route)
	}
	return nil
}

// ConsumePairingSecret atomically validates and burns the pairing secret:
// read, expiry, consumption, and compare all happen in one transaction, so
// a replay cannot race the single-use consumption. A wrong, expired, or
// already-used secret fails closed without burning anything.
func (s *SQLStore) ConsumePairingSecret(clientID, tenant, route, secret string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("authz: pairing tx: %w", err)
	}
	defer tx.Rollback()
	var (
		stored  string
		expires string
		used    sql.NullString
	)
	err = tx.QueryRow(
		`SELECT pairing_hash, pairing_expires_at, pairing_consumed_at
		 FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).Scan(&stored, &expires, &used)
	if err != nil {
		return false, fmt.Errorf("authz: check pairing secret: %w", err)
	}
	if stored == "" || used.Valid {
		return false, nil
	}
	// Fail closed on unusable expiry state: an empty or unparseable
	// timestamp means the persisted state is corrupt, and a credential
	// whose expiry cannot be proven unexpired is denied. The old
	// condition (perr == nil && expired) skipped the check entirely
	// when parsing failed, turning corruption into an eternal
	// credential.
	exp, perr := time.Parse(time.RFC3339Nano, expires)
	if perr != nil || exp.IsZero() || time.Now().After(exp) {
		return false, nil
	}
	if !hmac.Equal([]byte(stored), []byte(HashSecret(secret))) {
		return false, nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(
		`UPDATE authz_grants SET pairing_consumed_at=?, updated_at=?
		 WHERE client_id=? AND tenant_id=? AND route_id=?`,
		now, now, clientID, tenant, route); err != nil {
		return false, fmt.Errorf("authz: consume pairing secret: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("authz: pairing commit: %w", err)
	}
	return true, nil
}

// RevokeToken durably revokes a token by jti.
func (s *SQLStore) RevokeToken(jti, clientID, tenant, route string) error {
	if jti == "" {
		return fmt.Errorf("authz: token jti is required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`INSERT INTO authz_revocations(jti, client_id, tenant_id, route_id, revoked_at)
		 VALUES(?,?,?,?,?) ON CONFLICT(jti) DO NOTHING`,
		jti, clientID, tenant, route, now); err != nil {
		return fmt.Errorf("authz: revoke token: %w", err)
	}
	return nil
}

// BurnToken atomically revokes a token by jti and reports whether THIS
// call performed the burn.
//
// The insert is the whole decision: the row is created only by the caller
// that wins, and every other caller sees zero affected rows. That makes
// the burn single-use under concurrency without a separate read, so two
// simultaneous rotations of one refresh token cannot both succeed.
func (s *SQLStore) BurnToken(jti, clientID, tenant, route string) (bool, error) {
	if jti == "" {
		return false, fmt.Errorf("authz: token jti is required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`INSERT INTO authz_revocations(jti, client_id, tenant_id, route_id, revoked_at)
		 VALUES(?,?,?,?,?) ON CONFLICT(jti) DO NOTHING`,
		jti, clientID, tenant, route, now)
	if err != nil {
		return false, fmt.Errorf("authz: burn token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("authz: burn token: %w", err)
	}
	return n == 1, nil
}

// IsTokenRevoked reports whether a jti is revoked for this tenant+route.
func (s *SQLStore) IsTokenRevoked(jti, tenant, route string) (bool, error) {
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(1) FROM authz_revocations WHERE jti=? AND tenant_id=? AND route_id=?`,
		jti, tenant, route).Scan(&n); err != nil {
		return false, fmt.Errorf("authz: token revocation check: %w", err)
	}
	return n > 0, nil
}

// CreateConsent stores a one-time consent challenge, including the
// canonical resource so the completion step can rebind every field of the
// transaction.
func (s *SQLStore) CreateConsent(c Consent) error {
	if c.Challenge == "" {
		return fmt.Errorf("authz: consent challenge is required")
	}
	if _, err := s.db.Exec(
		`INSERT INTO authz_consent(challenge, client_id, tenant_id, route_id, redirect_uri,
		   code_challenge, state, resource, expires_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		c.Challenge, c.ClientID, c.Tenant, c.Route, c.RedirectURI,
		c.CodeChallenge, c.State, c.Resource, c.ExpiresAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("authz: create consent: %w", err)
	}
	return nil
}

// CountPendingConsents reports unconsumed, unexpired challenges for a route.
func (s *SQLStore) CountPendingConsents(tenant, route string) (int, error) {
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(1) FROM authz_consent
		 WHERE tenant_id=? AND route_id=? AND consumed_at IS NULL AND expires_at > ?`,
		tenant, route, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&n); err != nil {
		return 0, fmt.Errorf("authz: count consents: %w", err)
	}
	return n, nil
}

// PruneAuthzExpired deletes lifecycle-expired authorization rows. Codes and
// challenges go once consumed or expired; revocations are retained for
// DefaultRevocationRetention (far beyond any token lifetime) so a pruned
// row can never resurrect access.
func (s *SQLStore) PruneAuthzExpired(now time.Time) error {
	nowStr := now.UTC().Format(time.RFC3339Nano)
	revCutoff := now.UTC().Add(-DefaultRevocationRetention).Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`DELETE FROM authz_codes WHERE consumed_at IS NOT NULL OR expires_at < ?`, nowStr); err != nil {
		return fmt.Errorf("authz: prune codes: %w", err)
	}
	if _, err := s.db.Exec(
		`DELETE FROM authz_consent WHERE consumed_at IS NOT NULL OR expires_at < ?`, nowStr); err != nil {
		return fmt.Errorf("authz: prune consents: %w", err)
	}
	if _, err := s.db.Exec(
		`DELETE FROM authz_revocations WHERE revoked_at < ?`, revCutoff); err != nil {
		return fmt.Errorf("authz: prune revocations: %w", err)
	}
	return nil
}

// ConsumeConsent atomically marks a challenge consumed and returns it.
func (s *SQLStore) ConsumeConsent(challenge string) (*Consent, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: consent tx: %w", err)
	}
	defer tx.Rollback()
	var (
		c        Consent
		expires  string
		consumed sql.NullString
	)
	err = tx.QueryRow(
		`SELECT challenge, client_id, tenant_id, route_id, redirect_uri, code_challenge,
		        state, resource, expires_at, consumed_at FROM authz_consent WHERE challenge=?`,
		challenge).
		Scan(&c.Challenge, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI,
			&c.CodeChallenge, &c.State, &c.Resource, &expires, &consumed)
	if err != nil {
		return nil, fmt.Errorf("authz: unknown consent challenge: %w", err)
	}
	c.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if c.ExpiresAt.IsZero() || time.Now().After(c.ExpiresAt) {
		return nil, fmt.Errorf("authz: consent challenge expired")
	}
	if consumed.Valid {
		return nil, fmt.Errorf("authz: consent challenge already used")
	}
	if _, err := tx.Exec(
		`UPDATE authz_consent SET consumed_at=? WHERE challenge=?`,
		time.Now().UTC().Format(time.RFC3339Nano), challenge); err != nil {
		return nil, fmt.Errorf("authz: consume consent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: consent commit: %w", err)
	}
	now := time.Now()
	c.ConsumedAt = &now
	return &c, nil
}

// AuditAuthz records an authorization-plane decision.
func (s *SQLStore) AuditAuthz(actor, tenant, route, clientID, action, result, detail string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`INSERT INTO authz_audit(time, actor, tenant_id, route_id, client_id, action, result, detail)
		 VALUES(?,?,?,?,?,?,?,?)`,
		now, actor, tenant, route, clientID, action, result, detail); err != nil {
		return fmt.Errorf("authz: audit: %w", err)
	}
	return nil
}

// ListAuthzAudit returns the most recent audit records, newest first.
func (s *SQLStore) ListAuthzAudit(limit int) ([]AuthzAudit, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT time, actor, tenant_id, route_id, client_id, action, result, detail
		 FROM authz_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("authz: list audit: %w", err)
	}
	defer rows.Close()
	var out []AuthzAudit
	for rows.Next() {
		var a AuthzAudit
		var ts string
		if err := rows.Scan(&ts, &a.Actor, &a.Tenant, &a.Route, &a.ClientID,
			&a.Action, &a.Result, &a.Detail); err != nil {
			return nil, fmt.Errorf("authz: scan audit: %w", err)
		}
		a.Time, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ApproveGrant sets a grant active, creating it if the client has not yet
// initiated an authorize request. A revoked grant is never resurrected:
// the conditional upsert leaves a revoked row untouched, and a
// zero-row-count result is reported as a refusal.
func (s *SQLStore) ApproveGrant(clientID, tenant, route string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(client_id, tenant_id, route_id)
		 DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at
		 WHERE authz_grants.status <> 'revoked'`,
		clientID, tenant, route, string(GrantActive), now, now)
	if err != nil {
		return fmt.Errorf("authz: approve grant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", clientID, route)
	}
	return nil
}

// ApproveGrantWithPairingSecret activates the grant and issues the pairing
// credential in ONE transaction. An approval whose credential cannot be
// persisted must not leave an ACTIVE grant that no consent can complete,
// and a revoked grant is refused.
func (s *SQLStore) ApproveGrantWithPairingSecret(clientID, tenant, route, secret string, ttl time.Duration) error {
	if secret == "" {
		return fmt.Errorf("authz: pairing secret is required")
	}
	if ttl <= 0 {
		return fmt.Errorf("authz: pairing ttl must be positive")
	}
	client, cerr := s.GetClient(clientID)
	if cerr != nil {
		return fmt.Errorf("authz: approve grant for unknown client %q: %w", clientID, cerr)
	}
	if client.Tenant == "" || client.Route == "" {
		return fmt.Errorf("authz: client %q has no route registration scope; refusing approval", clientID)
	}
	if client.Tenant != tenant || client.Route != route {
		return fmt.Errorf("authz: client %q is registered for tenant %q route %q, not tenant %q route %q",
			clientID, client.Tenant, client.Route, tenant, route)
	}
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)
	expires := now.Add(ttl).Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("authz: approve tx: %w", err)
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRow(
		`SELECT status FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).Scan(&status)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("authz: approve grant: %w", err)
	}
	if err == nil && status == string(GrantRevoked) {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", clientID, route)
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at,
		   pairing_hash, pairing_issued_at, pairing_expires_at, pairing_consumed_at)
		 VALUES(?,?,?,?,?,?,?,?,?,NULL)
		 ON CONFLICT(client_id, tenant_id, route_id)
		 DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at,
		   pairing_hash=excluded.pairing_hash, pairing_issued_at=excluded.pairing_issued_at,
		   pairing_expires_at=excluded.pairing_expires_at, pairing_consumed_at=NULL
		 WHERE authz_grants.status <> 'revoked'`,
		clientID, tenant, route, string(GrantActive), nowStr, nowStr,
		HashSecret(secret), nowStr, expires); err != nil {
		return fmt.Errorf("authz: approve grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: approve commit: %w", err)
	}
	return nil
}

// RevokeGrant sets a grant revoked. It is immediate and permanent.
// RevokeGrantsForRoute revokes every grant of one route in one statement.
func (s *SQLStore) RevokeGrantsForRoute(tenant, route string) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`UPDATE authz_grants SET status='revoked', updated_at=?
		 WHERE tenant_id=? AND route_id=? AND status<>'revoked'`,
		now, tenant, route)
	if err != nil {
		return 0, fmt.Errorf("authz: revoke grants for route: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLStore) RevokeGrant(clientID, tenant, route string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`UPDATE authz_grants SET status=?, updated_at=? WHERE client_id=? AND tenant_id=? AND route_id=?`,
		string(GrantRevoked), now, clientID, tenant, route)
	if err != nil {
		return fmt.Errorf("authz: revoke grant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("authz: no grant to revoke for client %q route %q", clientID, route)
	}
	return nil
}

// CreateCode inserts a single-use authorization code.
func (s *SQLStore) CreateCode(c Code) error {
	if c.Code == "" {
		return fmt.Errorf("authz: code is required")
	}
	_, err := s.db.Exec(
		`INSERT INTO authz_codes(code, client_id, tenant_id, route_id, redirect_uri, challenge, challenge_method, expires_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		c.Code, c.ClientID, c.Tenant, c.Route, c.RedirectURI, c.Challenge, c.ChallengeMethod,
		c.ExpiresAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("authz: create code: %w", err)
	}
	return nil
}

// ConsumeCode atomically marks a code consumed and returns it, scoped to
// the expected client + tenant + route. The scope check happens inside the
// SQL transaction BEFORE the consumed marker is written, so a foreign
// route's redemption attempt can neither mint tokens nor destroy another
// route's pending code. A code can only be consumed once; an expired code
// is rejected.
func (s *SQLStore) ConsumeCode(code, expectedClient, expectedTenant, expectedRoute string) (*Code, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: consume code: %w", err)
	}
	defer tx.Rollback()

	var (
		c         Code
		expiresAt string
		consumed  sql.NullString
	)
	err = tx.QueryRow(
		`SELECT code, client_id, tenant_id, route_id, redirect_uri, challenge, challenge_method, expires_at, consumed_at
		 FROM authz_codes WHERE code=?`, code).
		Scan(&c.Code, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI, &c.Challenge, &c.ChallengeMethod, &expiresAt, &consumed)
	if err != nil {
		return nil, fmt.Errorf("authz: unknown authorization code")
	}
	// Scope fence: the code's own tenant/route/client must match the
	// authorization server handling the redemption. A mismatch leaves
	// the row untouched (transaction rolls back), so route A's pending
	// code survives route B's attempt.
	if c.ClientID != expectedClient || c.Tenant != expectedTenant || c.Route != expectedRoute {
		return nil, fmt.Errorf("authz: authorization code is not bound to this client and route")
	}
	if consumed.Valid {
		return nil, fmt.Errorf("authz: authorization code already used")
	}
	exp, _ := time.Parse(time.RFC3339Nano, expiresAt)
	if time.Now().After(exp) {
		return nil, fmt.Errorf("authz: authorization code expired")
	}
	if _, err := tx.Exec(`UPDATE authz_codes SET consumed_at=? WHERE code=?`, time.Now().UTC().Format(time.RFC3339Nano), code); err != nil {
		return nil, fmt.Errorf("authz: consume code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: consume code commit: %w", err)
	}
	now := time.Now()
	c.ConsumedAt = &now
	c.ExpiresAt = exp
	return &c, nil
}

// ListGrants returns every grant, newest first.
func (s *SQLStore) ListGrants() ([]Grant, error) {
	rows, err := s.db.Query(
		`SELECT client_id, tenant_id, route_id, status, created_at, updated_at FROM authz_grants ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("authz: list grants: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		var status, createdAt, updatedAt string
		if err := rows.Scan(&g.ClientID, &g.Tenant, &g.Route, &status, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("authz: scan grant: %w", err)
		}
		g.Status = GrantStatus(status)
		if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
			g.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339Nano, updatedAt); err == nil {
			g.UpdatedAt = t
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// LoadIssuer loads the relay's issuer key, creating it on first use.
func (s *SQLStore) LoadIssuer() (*Issuer, error) {
	var (
		kid  string
		priv []byte
	)
	err := s.db.QueryRow(`SELECT kid, priv FROM authz_issuer_key WHERE id=1`).Scan(&kid, &priv)
	if err == sql.ErrNoRows {
		issuer, err := NewIssuer()
		if err != nil {
			return nil, err
		}
		if _, err := s.db.Exec(
			`INSERT INTO authz_issuer_key(id, kid, priv, created_at) VALUES(1,?,?,?)`,
			issuer.KID(), issuer.PrivateKeyBytes(), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, fmt.Errorf("authz: store issuer key: %w", err)
		}
		return issuer, nil
	}
	if err != nil {
		return nil, fmt.Errorf("authz: load issuer key: %w", err)
	}
	return IssuerFromKey(kid, priv)
}

// RotateIssuer generates a new issuer key, replacing the old one. Tokens
// signed by the retired key fail closed at admission. It works whether or
// not an issuer row already exists (INSERT ... ON CONFLICT covers the empty
// table, e.g. after --reset-authority or on a fresh database), verifies that
// exactly one row was persisted, and returns the key actually stored.
func (s *SQLStore) RotateIssuer() (*Issuer, error) {
	issuer, err := NewIssuer()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: rotate issuer key: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO authz_issuer_key(id, kid, priv, created_at) VALUES(1,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET kid=excluded.kid, priv=excluded.priv, created_at=excluded.created_at`,
		issuer.KID(), issuer.PrivateKeyBytes(), now); err != nil {
		return nil, fmt.Errorf("authz: rotate issuer key: %w", err)
	}
	// Confirm persistence: exactly one row, and it is the key we generated.
	var kid string
	var priv []byte
	if err := tx.QueryRow(`SELECT kid, priv FROM authz_issuer_key WHERE id=1`).Scan(&kid, &priv); err != nil {
		return nil, fmt.Errorf("authz: rotate issuer key: persistence not verifiable: %w", err)
	}
	if kid != issuer.KID() || !bytes.Equal(priv, issuer.PrivateKeyBytes()) {
		return nil, fmt.Errorf("authz: rotate issuer key: persisted key does not match generated key")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: rotate issuer key: %w", err)
	}
	return issuer, nil
}
