package authz

import (
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

// RegisterClient inserts a client. A duplicate id is rejected.
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
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at) VALUES(?,?,?,?)`,
		c.ID, c.Name, string(uris), now)
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
		`SELECT id, name, redirect_uris, created_at, revoked_at FROM authz_clients WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &uris, &createdAt, &revoked)
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
		g             Grant
		status        string
		createdAt     string
		updatedAt     string
		pairingHash   string
		pairingIssued string
	)
	err := s.db.QueryRow(
		`SELECT client_id, tenant_id, route_id, status, created_at, updated_at,
		        pairing_hash, pairing_issued_at
		 FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).
		Scan(&g.ClientID, &g.Tenant, &g.Route, &status, &createdAt, &updatedAt,
			&pairingHash, &pairingIssued)
	if err != nil {
		return nil, fmt.Errorf("authz: get grant: %w", err)
	}
	g.Status = GrantStatus(status)
	g.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	g.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	g.PairingHash = pairingHash
	g.PairingIssuedAt, _ = time.Parse(time.RFC3339Nano, pairingIssued)
	return &g, nil
}

// SetPairingSecret stores only the hash of the pairing secret.
func (s *SQLStore) SetPairingSecret(clientID, tenant, route, secret string) error {
	if secret == "" {
		return fmt.Errorf("authz: pairing secret is required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`UPDATE authz_grants SET pairing_hash=?, pairing_issued_at=?, updated_at=?
		 WHERE client_id=? AND tenant_id=? AND route_id=?`,
		HashSecret(secret), now, now, clientID, tenant, route); err != nil {
		return fmt.Errorf("authz: set pairing secret: %w", err)
	}
	return nil
}

// CheckPairingSecret compares the presented secret against the stored hash
// in constant time.
func (s *SQLStore) CheckPairingSecret(clientID, tenant, route, secret string) (bool, error) {
	var stored string
	err := s.db.QueryRow(
		`SELECT pairing_hash FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).Scan(&stored)
	if err != nil {
		return false, fmt.Errorf("authz: check pairing secret: %w", err)
	}
	if stored == "" {
		return false, nil
	}
	return hmac.Equal([]byte(stored), []byte(HashSecret(secret))), nil
}

// RevokeToken durably revokes one token by its jti.
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

// IsTokenRevoked reports whether a jti is revoked.
func (s *SQLStore) IsTokenRevoked(jti string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM authz_revocations WHERE jti=?`, jti).Scan(&n); err != nil {
		return false, fmt.Errorf("authz: token revocation check: %w", err)
	}
	return n > 0, nil
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
// initiated an authorize request. The operator approval is the security
// boundary; a token still requires a code exchange.
func (s *SQLStore) ApproveGrant(clientID, tenant, route string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(client_id, tenant_id, route_id)
		 DO UPDATE SET status=?, updated_at=?`,
		clientID, tenant, route, string(GrantActive), now, now, string(GrantActive), now)
	if err != nil {
		return fmt.Errorf("authz: approve grant: %w", err)
	}
	return nil
}

// RevokeGrant sets a grant revoked. It is immediate and permanent.
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

// ConsumeCode atomically marks a code consumed and returns it. A code can only
// be consumed once; an expired code is rejected.
func (s *SQLStore) ConsumeCode(code string) (*Code, error) {
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

// ListClients returns every registered client, newest first.
func (s *SQLStore) ListClients() ([]Client, error) {
	rows, err := s.db.Query(
		`SELECT id, name, redirect_uris, created_at, revoked_at FROM authz_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("authz: list clients: %w", err)
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var uris, createdAt string
		if err := rows.Scan(&c.ID, &c.Name, &uris, &createdAt, &c.RevokedAt); err != nil {
			return nil, fmt.Errorf("authz: scan client: %w", err)
		}
		c.RedirectURIs = splitList(uris)
		if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
			c.CreatedAt = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
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

// ListCodes returns unconsumed authorization codes pending operator action.
func (s *SQLStore) ListCodes() ([]Code, error) {
	rows, err := s.db.Query(
		`SELECT code, client_id, tenant, route, redirect_uri, challenge, challenge_method, expires_at, consumed_at
		 FROM authz_codes WHERE consumed_at IS NULL ORDER BY expires_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("authz: list codes: %w", err)
	}
	defer rows.Close()
	var out []Code
	for rows.Next() {
		var c Code
		var expiresAt string
		if err := rows.Scan(&c.Code, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI,
			&c.Challenge, &c.ChallengeMethod, &expiresAt, &c.ConsumedAt); err != nil {
			return nil, fmt.Errorf("authz: scan code: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, expiresAt); err == nil {
			c.ExpiresAt = t
		}
		out = append(out, c)
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
// signed by the retired key fail closed at admission.
func (s *SQLStore) RotateIssuer() (*Issuer, error) {
	issuer, err := NewIssuer()
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`UPDATE authz_issuer_key SET kid=?, priv=?, created_at=? WHERE id=1`,
		issuer.KID(), issuer.PrivateKeyBytes(), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("authz: rotate issuer key: %w", err)
	}
	return issuer, nil
}
