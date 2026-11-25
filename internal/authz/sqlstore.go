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
	db        *sql.DB
	secretKey []byte // optional 32-byte AES-256-GCM key for sealing authz_visitor_policies.client_secret
}

// NewSQLStore wraps a database handle. The schemaV8 tables must exist.
func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// SetSecretKey configures the 32-byte key used to encrypt and decrypt
// authz_visitor_policies.client_secret at rest in SQLite.
func (s *SQLStore) SetSecretKey(key []byte) {
	if len(key) == 0 {
		s.secretKey = nil
		return
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	s.secretKey = cp
}

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
	mode := c.ClientMode
	if mode == "" {
		mode = "public"
	}
	_, err = s.db.Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id, client_secret_hash, client_mode, refresh_policy) VALUES(?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Name, string(uris), now, c.Tenant, c.Route, c.ClientSecretHash, mode, c.RefreshPolicy)
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
		`SELECT id, name, redirect_uris, created_at, revoked_at, tenant_id, route_id, client_secret_hash, client_mode, refresh_policy
		 FROM authz_clients WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &uris, &createdAt, &revoked, &c.Tenant, &c.Route, &c.ClientSecretHash, &c.ClientMode, &c.RefreshPolicy)
	if err != nil {
		return nil, fmt.Errorf("authz: get client: %w", err)
	}
	if c.ClientMode == "" {
		c.ClientMode = "public"
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

// TryRegisterClient atomically enforces the per-route bound and inserts a
// client. If full, it reclaims the oldest unrevoked registration that has
// never received a grant. Granted identities and revoked ID reservations
// are never evicted. The selection, deletion, quota check, and insert share
// one transaction so concurrent DCR requests cannot cross the bound.
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
		var victimID string
		err := tx.QueryRow(
			`SELECT c.id FROM authz_clients c
			 WHERE c.tenant_id=? AND c.route_id=? AND c.revoked_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1 FROM authz_grants g
			     WHERE g.client_id=c.id AND g.tenant_id=c.tenant_id AND g.route_id=c.route_id
			       AND g.status IN ('active', 'revoked')
			   )
			 ORDER BY c.created_at ASC, c.id ASC LIMIT 1`,
			c.Tenant, c.Route).Scan(&victimID)
		if err == sql.ErrNoRows {
			return ErrClientQuota
		}
		if err != nil {
			return fmt.Errorf("authz: select oldest unused client: %w", err)
		}
		if _, err := tx.Exec(
			`DELETE FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=? AND status='pending'`,
			victimID, c.Tenant, c.Route); err != nil {
			return fmt.Errorf("authz: delete pending grant for evicted client: %w", err)
		}
		res, err := tx.Exec(
			`DELETE FROM authz_clients
			 WHERE id=? AND tenant_id=? AND route_id=? AND revoked_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1 FROM authz_grants g
			     WHERE g.client_id=authz_clients.id
			       AND g.tenant_id=authz_clients.tenant_id
			       AND g.route_id=authz_clients.route_id
			       AND g.status IN ('active', 'revoked')
			   )`,
			victimID, c.Tenant, c.Route)
		if err != nil {
			return fmt.Errorf("authz: evict oldest unused client: %w", err)
		}
		deleted, _ := res.RowsAffected()
		if deleted != 1 {
			return ErrClientQuota
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id, client_secret_hash, client_mode, refresh_policy) VALUES(?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Name, string(uris), createdAt.UTC().Format(time.RFC3339Nano), c.Tenant, c.Route, c.ClientSecretHash, defaultClientMode(c.ClientMode), c.RefreshPolicy); err != nil {
		return fmt.Errorf("authz: register client: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: register commit: %w", err)
	}
	return nil
}

func defaultClientMode(m string) string {
	if m == "" {
		return "public"
	}
	return m
}

// TryRegisterClientWithPendingGrant atomically enforces the per-route quota,
// inserts the client, AND seeds its initial GrantPending row in one transaction.
func (s *SQLStore) TryRegisterClientWithPendingGrant(c Client, tenant, route string) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	if tenant == "" || route == "" {
		return fmt.Errorf("authz: tenant and route are required for pending grant")
	}
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("authz: redirect uris: %w", err)
	}
	createdAt := c.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	nowStr := createdAt.UTC().Format(time.RFC3339Nano)
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
		var victimID string
		err := tx.QueryRow(
			`SELECT c.id FROM authz_clients c
			 WHERE c.tenant_id=? AND c.route_id=? AND c.revoked_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1 FROM authz_grants g
			     WHERE g.client_id=c.id AND g.tenant_id=c.tenant_id AND g.route_id=c.route_id
			       AND g.status IN ('active', 'revoked')
			   )
			 ORDER BY c.created_at ASC, c.id ASC LIMIT 1`,
			c.Tenant, c.Route).Scan(&victimID)
		if err == sql.ErrNoRows {
			return ErrClientQuota
		}
		if err != nil {
			return fmt.Errorf("authz: select oldest unused client: %w", err)
		}
		if _, err := tx.Exec(
			`DELETE FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=? AND status='pending'`,
			victimID, c.Tenant, c.Route); err != nil {
			return fmt.Errorf("authz: delete pending grant for evicted client: %w", err)
		}
		res, err := tx.Exec(
			`DELETE FROM authz_clients
			 WHERE id=? AND tenant_id=? AND route_id=? AND revoked_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1 FROM authz_grants g
			     WHERE g.client_id=authz_clients.id
			       AND g.tenant_id=authz_clients.tenant_id
			       AND g.route_id=authz_clients.route_id
			       AND g.status IN ('active', 'revoked')
			   )`,
			victimID, c.Tenant, c.Route)
		if err != nil {
			return fmt.Errorf("authz: evict oldest unused client: %w", err)
		}
		deleted, _ := res.RowsAffected()
		if deleted != 1 {
			return ErrClientQuota
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id, client_secret_hash, client_mode, refresh_policy) VALUES(?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Name, string(uris), nowStr, c.Tenant, c.Route, c.ClientSecretHash, defaultClientMode(c.ClientMode), c.RefreshPolicy); err != nil {
		return fmt.Errorf("authz: register client: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
		c.ID, tenant, route, string(GrantPending), nowStr, nowStr); err != nil {
		return fmt.Errorf("authz: seed pending grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: register commit: %w", err)
	}
	return nil
}

// TryRegisterClientWithTrustPolicy atomically re-verifies that policyID is
// still active, unrevoked, scoped to (tenant, route), and exact-matching
// c.RedirectURIs inside the SAME SQL transaction that enforces the per-route
// quota, inserts the client, and seeds the ACTIVE direct grant (skip_pairing=1).
// If the policy was revoked concurrently, it rolls back and returns
// ErrTrustPolicyInactive so ServeRegister can fall back to pending registration.
func (s *SQLStore) TryRegisterClientWithTrustPolicy(c Client, tenant, route, policyID string) error {
	if c.ID == "" {
		return fmt.Errorf("authz: client id is required")
	}
	if tenant == "" || route == "" || policyID == "" {
		return ErrTrustPolicyInactive
	}
	if c.Tenant != tenant || c.Route != route {
		return ErrTrustPolicyInactive
	}
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("authz: redirect uris: %w", err)
	}
	createdAt := c.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	nowStr := createdAt.UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("authz: register tx: %w", err)
	}
	defer tx.Rollback()

	var (
		polTenant   string
		polRoute    string
		polURIsJSON string
		polEnabled  int
		polRevoked  sql.NullString
	)
	err = tx.QueryRow(
		`SELECT tenant_id, route_id, redirect_uris_json, enabled, revoked_at
		 FROM authz_trust_policies WHERE id=?`,
		policyID,
	).Scan(&polTenant, &polRoute, &polURIsJSON, &polEnabled, &polRevoked)
	if err == sql.ErrNoRows {
		return ErrTrustPolicyInactive
	}
	if err != nil {
		return fmt.Errorf("authz: verify trust policy: %w", err)
	}
	if polTenant != tenant || polRoute != route || polEnabled != 1 || polRevoked.Valid {
		return ErrTrustPolicyInactive
	}
	var polURIs []string
	if uerr := json.Unmarshal([]byte(polURIsJSON), &polURIs); uerr != nil || !ExactRedirectURISetEqual(polURIs, c.RedirectURIs) {
		return ErrTrustPolicyInactive
	}
	var n int
	if err := tx.QueryRow(
		`SELECT COUNT(1) FROM authz_clients WHERE tenant_id=? AND route_id=?`,
		c.Tenant, c.Route).Scan(&n); err != nil {
		return fmt.Errorf("authz: count clients: %w", err)
	}
	if n >= MaxClientsPerRoute {
		var victimID string
		err := tx.QueryRow(
			`SELECT c.id FROM authz_clients c
			 WHERE c.tenant_id=? AND c.route_id=? AND c.revoked_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1 FROM authz_grants g
			     WHERE g.client_id=c.id AND g.tenant_id=c.tenant_id AND g.route_id=c.route_id
			       AND g.status IN ('active', 'revoked')
			   )
			 ORDER BY c.created_at ASC, c.id ASC LIMIT 1`,
			c.Tenant, c.Route).Scan(&victimID)
		if err == sql.ErrNoRows {
			return ErrClientQuota
		}
		if err != nil {
			return fmt.Errorf("authz: select oldest unused client: %w", err)
		}
		if _, err := tx.Exec(
			`DELETE FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=? AND status='pending'`,
			victimID, c.Tenant, c.Route); err != nil {
			return fmt.Errorf("authz: delete pending grant for evicted client: %w", err)
		}
		res, err := tx.Exec(
			`DELETE FROM authz_clients
			 WHERE id=? AND tenant_id=? AND route_id=? AND revoked_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1 FROM authz_grants g
			     WHERE g.client_id=authz_clients.id
			       AND g.tenant_id=authz_clients.tenant_id
			       AND g.route_id=authz_clients.route_id
			       AND g.status IN ('active', 'revoked')
			   )`,
			victimID, c.Tenant, c.Route)
		if err != nil {
			return fmt.Errorf("authz: evict oldest unused client: %w", err)
		}
		deleted, _ := res.RowsAffected()
		if deleted != 1 {
			return ErrClientQuota
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id, client_secret_hash, client_mode, refresh_policy) VALUES(?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Name, string(uris), nowStr, c.Tenant, c.Route, c.ClientSecretHash, defaultClientMode(c.ClientMode), c.RefreshPolicy); err != nil {
		return fmt.Errorf("authz: register client: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, skip_pairing, auth_method, trust_policy_id, created_at, updated_at) VALUES(?,?,?,?,1,?,?,?,?)`,
		c.ID, tenant, route, string(GrantActive), GrantMethodTrustPolicy, policyID, nowStr, nowStr); err != nil {
		return fmt.Errorf("authz: seed direct grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: register commit: %w", err)
	}
	return nil
}

// CreateTrustPolicy inserts a durable route-scoped exact-redirect trust policy.
func (s *SQLStore) CreateTrustPolicy(p ClientTrustPolicy) error {
	if p.ID == "" || p.TenantID == "" || p.RouteID == "" {
		return fmt.Errorf("authz: trust policy requires id, tenant_id, and route_id")
	}
	uris, err := ValidateTrustRedirectURIs(p.RedirectURIs)
	if err != nil {
		return err
	}
	urisJSON, err := json.Marshal(uris)
	if err != nil {
		return fmt.Errorf("authz: marshal trust policy redirect_uris: %w", err)
	}
	createdAt := p.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	_, err = s.db.Exec(
		`INSERT INTO authz_trust_policies(id, tenant_id, route_id, owner_key_id, kind, redirect_uris_json, enabled, created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		p.ID, p.TenantID, p.RouteID, p.OwnerKeyID, p.Kind, string(urisJSON), enabled, createdAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("authz: create trust policy: %w", err)
	}
	return nil
}

// ListTrustPolicies returns all active, unrevoked trust policies for (tenant, route).
func (s *SQLStore) ListTrustPolicies(tenant, route string) ([]ClientTrustPolicy, error) {
	rows, err := s.db.Query(
		`SELECT id, tenant_id, route_id, owner_key_id, kind, redirect_uris_json, enabled, created_at
		 FROM authz_trust_policies
		 WHERE tenant_id=? AND route_id=? AND enabled=1 AND revoked_at IS NULL
		 ORDER BY created_at ASC, id ASC`,
		tenant, route,
	)
	if err != nil {
		return nil, fmt.Errorf("authz: list trust policies: %w", err)
	}
	defer rows.Close()
	out := make([]ClientTrustPolicy, 0)
	for rows.Next() {
		var (
			p         ClientTrustPolicy
			urisJSON  string
			enabled   int
			createdAt string
		)
		if err := rows.Scan(&p.ID, &p.TenantID, &p.RouteID, &p.OwnerKeyID, &p.Kind, &urisJSON, &enabled, &createdAt); err != nil {
			return nil, fmt.Errorf("authz: scan trust policy: %w", err)
		}
		p.Enabled = enabled != 0
		_ = json.Unmarshal([]byte(urisJSON), &p.RedirectURIs)
		if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
			p.CreatedAt = t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokeTrustPolicy revokes active trust policies on (tenant, route) matching
// either exact policy ID or policy kind (e.g. "chatgpt"), and atomically
// revokes every grant and opaque refresh lineage derived from those policies
// while leaving separately authorized grants intact (OCL-006).
func (s *SQLStore) RevokeTrustPolicy(tenant, route, idOrKind string) (int, error) {
	if idOrKind == "" {
		return 0, fmt.Errorf("authz: policy id or kind is required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("authz: revoke trust policy tx: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id FROM authz_trust_policies
		 WHERE tenant_id=? AND route_id=? AND revoked_at IS NULL AND (id=? OR kind=?)`,
		tenant, route, idOrKind, idOrKind,
	)
	if err != nil {
		return 0, fmt.Errorf("authz: find trust policies: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("authz: scan trust policy id: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("authz: read trust policies: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	res, err := tx.Exec(
		`UPDATE authz_trust_policies
		 SET enabled=0, revoked_at=?
		 WHERE tenant_id=? AND route_id=? AND revoked_at IS NULL AND (id=? OR kind=?)`,
		now, tenant, route, idOrKind, idOrKind,
	)
	if err != nil {
		return 0, fmt.Errorf("authz: revoke trust policy: %w", err)
	}
	n, _ := res.RowsAffected()

	for _, polID := range ids {
		if _, err := tx.Exec(
			`UPDATE authz_opaque_refresh
			 SET revoked_at=?
			 WHERE tenant_id=? AND route_id=? AND revoked_at IS NULL
			   AND client_id IN (
			     SELECT client_id FROM authz_grants
			     WHERE tenant_id=? AND route_id=? AND trust_policy_id=? AND status<>'revoked'
			   )`,
			now, tenant, route, tenant, route, polID,
		); err != nil {
			return 0, fmt.Errorf("authz: revoke dependent opaque refresh tokens: %w", err)
		}
		if _, err := tx.Exec(
			`UPDATE authz_grants
			 SET status='revoked', updated_at=?
			 WHERE tenant_id=? AND route_id=? AND trust_policy_id=? AND status<>'revoked'`,
			now, tenant, route, polID,
		); err != nil {
			return 0, fmt.Errorf("authz: revoke dependent grants: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("authz: commit revoke trust policy: %w", err)
	}
	return int(n), nil
}

// SetVisitorAuthPolicy persists or updates a route's visitor auth policy (OCL-005).
// Every write atomically increments revision so in-flight OIDC transactions
// bound to a superseded policy revision fail closed, and seals client_secret
// with AES-256-GCM when a secret key is configured.
func (s *SQLStore) SetVisitorAuthPolicy(p VisitorAuthPolicy) error {
	clean, err := ValidateVisitorAuthPolicy(p)
	if err != nil {
		return err
	}
	subsJSON, err := json.Marshal(clean.AllowedSubjects)
	if err != nil {
		return fmt.Errorf("authz: marshal allowed_subjects: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	enabled := 0
	if clean.Enabled {
		enabled = 1
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("authz: set visitor policy tx: %w", err)
	}
	defer tx.Rollback()

	var (
		prevRev      int64
		prevIssuer   string
		prevClientID string
		prevSecret   string
	)
	err = tx.QueryRow(
		`SELECT revision, issuer, client_id, client_secret
		 FROM authz_visitor_policies WHERE tenant_id=? AND route_id=?`,
		clean.TenantID, clean.RouteID,
	).Scan(&prevRev, &prevIssuer, &prevClientID, &prevSecret)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("authz: read existing visitor auth policy: %w", err)
	}
	nextRev := prevRev + 1
	if nextRev < 1 {
		nextRev = 1
	}
	storedSecret := ""
	if clean.Mode == VisitorAuthModeFederated {
		if clean.ClientSecret != "" {
			sealed, serr := SealVisitorSecret(s.secretKey, clean.TenantID, clean.RouteID, clean.Issuer, clean.ClientID, clean.ClientSecret)
			if serr != nil {
				return serr
			}
			storedSecret = sealed
		} else if err == nil && prevIssuer == clean.Issuer && prevClientID == clean.ClientID {
			// Preserve existing secret across subject/policy updates for the same IdP app.
			storedSecret = prevSecret
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_visitor_policies(
		   tenant_id, route_id, mode, issuer, client_id, client_secret,
		   allowed_subjects_json, client_policy, enabled, revision, created_at, updated_at, revoked_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)
		 ON CONFLICT(tenant_id, route_id)
		 DO UPDATE SET mode=excluded.mode, issuer=excluded.issuer, client_id=excluded.client_id,
		   client_secret=excluded.client_secret, allowed_subjects_json=excluded.allowed_subjects_json,
		   client_policy=excluded.client_policy, enabled=excluded.enabled, revision=excluded.revision,
		   updated_at=excluded.updated_at, revoked_at=NULL`,
		clean.TenantID, clean.RouteID, clean.Mode, clean.Issuer, clean.ClientID, storedSecret,
		string(subsJSON), clean.ClientPolicy, enabled, nextRev, now, now,
	); err != nil {
		return fmt.Errorf("authz: set visitor auth policy: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: commit visitor auth policy: %w", err)
	}
	return nil
}

// GetVisitorAuthPolicy loads the active, unrevoked visitor auth policy for (tenant, route).
func (s *SQLStore) GetVisitorAuthPolicy(tenant, route string) (*VisitorAuthPolicy, error) {
	var (
		p            VisitorAuthPolicy
		subsJSON     string
		enabled      int
		storedSecret string
		createdAt    string
		updatedAt    string
	)
	err := s.db.QueryRow(
		`SELECT tenant_id, route_id, mode, issuer, client_id, client_secret,
		        allowed_subjects_json, client_policy, enabled, revision, created_at, updated_at
		 FROM authz_visitor_policies
		 WHERE tenant_id=? AND route_id=? AND enabled=1 AND revoked_at IS NULL`,
		tenant, route,
	).Scan(&p.TenantID, &p.RouteID, &p.Mode, &p.Issuer, &p.ClientID, &storedSecret,
		&subsJSON, &p.ClientPolicy, &enabled, &p.Revision, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("authz: get visitor auth policy: %w", err)
	}
	secret, serr := OpenVisitorSecret(s.secretKey, p.TenantID, p.RouteID, p.Issuer, p.ClientID, storedSecret)
	if serr != nil {
		return nil, serr
	}
	p.ClientSecret = secret
	p.Enabled = enabled != 0
	_ = json.Unmarshal([]byte(subsJSON), &p.AllowedSubjects)
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &p, nil
}

// RevokeVisitorAuthPolicy disables the route's visitor auth policy and
// atomically revokes dependent federated grants and opaque refresh tokens.
func (s *SQLStore) RevokeVisitorAuthPolicy(tenant, route string) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("authz: revoke visitor policy tx: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(
		`UPDATE authz_visitor_policies SET enabled=0, revoked_at=?, updated_at=?
		 WHERE tenant_id=? AND route_id=? AND revoked_at IS NULL`,
		now, now, tenant, route,
	)
	if err != nil {
		return 0, fmt.Errorf("authz: revoke visitor policy: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if _, err := tx.Exec(
			`UPDATE authz_opaque_refresh
			 SET revoked_at=?
			 WHERE tenant_id=? AND route_id=? AND revoked_at IS NULL
			   AND client_id IN (
			     SELECT client_id FROM authz_grants
			     WHERE tenant_id=? AND route_id=? AND auth_method=? AND status<>'revoked'
			   )`,
			now, tenant, route, tenant, route, GrantMethodFederatedOIDC,
		); err != nil {
			return 0, fmt.Errorf("authz: revoke federated opaque refresh: %w", err)
		}
		if _, err := tx.Exec(
			`UPDATE authz_grants SET status='revoked', updated_at=?
			 WHERE tenant_id=? AND route_id=? AND auth_method=? AND status<>'revoked'`,
			now, tenant, route, GrantMethodFederatedOIDC,
		); err != nil {
			return 0, fmt.Errorf("authz: revoke federated grants: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("authz: commit revoke visitor policy: %w", err)
	}
	return int(n), nil
}

func (s *SQLStore) CreateOIDCTransaction(t OIDCTransaction) error {
	if t.State == "" || t.Nonce == "" {
		return fmt.Errorf("authz: oidc transaction requires state and nonce")
	}
	if _, err := s.db.Exec(
		`INSERT INTO authz_oidc_tx(
		   state, nonce, pkce_verifier, client_id, tenant_id, route_id,
		   redirect_uri, code_challenge, client_state, resource, scope,
		   trust_policy_id, visitor_policy_revision, expires_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.State, t.Nonce, t.PKCEVerifier, t.ClientID, t.Tenant, t.Route,
		t.RedirectURI, t.CodeChallenge, t.ClientState, t.Resource, t.Scope,
		t.TrustPolicyID, t.PolicyRevision, t.ExpiresAt.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("authz: create oidc tx: %w", err)
	}
	return nil
}

func (s *SQLStore) ConsumeOIDCTransaction(state, expectedTenant, expectedRoute string) (*OIDCTransaction, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: consume oidc tx: %w", err)
	}
	defer tx.Rollback()
	var (
		t        OIDCTransaction
		expires  string
		consumed sql.NullString
	)
	err = tx.QueryRow(
		`SELECT state, nonce, pkce_verifier, client_id, tenant_id, route_id,
		        redirect_uri, code_challenge, client_state, resource, scope,
		        trust_policy_id, visitor_policy_revision, expires_at, consumed_at
		 FROM authz_oidc_tx WHERE state=?`,
		state,
	).Scan(&t.State, &t.Nonce, &t.PKCEVerifier, &t.ClientID, &t.Tenant, &t.Route,
		&t.RedirectURI, &t.CodeChallenge, &t.ClientState, &t.Resource, &t.Scope,
		&t.TrustPolicyID, &t.PolicyRevision, &expires, &consumed)
	if err != nil {
		return nil, fmt.Errorf("authz: unknown oidc transaction state")
	}
	if t.Tenant != expectedTenant || t.Route != expectedRoute {
		return nil, fmt.Errorf("authz: oidc transaction is not bound to this route")
	}
	if consumed.Valid {
		return nil, fmt.Errorf("authz: oidc transaction already consumed")
	}
	t.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if t.ExpiresAt.IsZero() || time.Now().After(t.ExpiresAt) {
		return nil, fmt.Errorf("authz: oidc transaction expired")
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(`UPDATE authz_oidc_tx SET consumed_at=? WHERE state=?`, now.Format(time.RFC3339Nano), state); err != nil {
		return nil, fmt.Errorf("authz: consume oidc tx: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: commit consume oidc tx: %w", err)
	}
	t.ConsumedAt = &now
	return &t, nil
}

func (s *SQLStore) CountPendingOIDCTransactions(tenant, route string) (int, error) {
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(1) FROM authz_oidc_tx
		 WHERE tenant_id=? AND route_id=? AND consumed_at IS NULL AND expires_at > ?`,
		tenant, route, time.Now().UTC().Format(time.RFC3339Nano),
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("authz: count oidc tx: %w", err)
	}
	return n, nil
}

// MatchTrustPolicy returns the first active trust policy on (tenant, route)
// whose RedirectURIs set exactly equals redirectURIs.
func (s *SQLStore) MatchTrustPolicy(tenant, route string, redirectURIs []string) (*ClientTrustPolicy, error) {
	policies, err := s.ListTrustPolicies(tenant, route)
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

// CreateOpaqueRefresh persists a hashed opaque refresh token for a confidential client.
func (s *SQLStore) CreateOpaqueRefresh(r OpaqueRefresh) error {
	_, err := s.db.Exec(
		`INSERT INTO authz_opaque_refresh(token_hash, client_id, tenant_id, route_id, scope, expires_at, absolute_expires_at, last_used_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		r.TokenHash, r.ClientID, r.Tenant, r.Route, r.Scope,
		r.ExpiresAt.UTC().Format(time.RFC3339Nano),
		r.AbsoluteExpiresAt.UTC().Format(time.RFC3339Nano),
		r.LastUsedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("authz: create opaque refresh: %w", err)
	}
	return nil
}

// RotateOpaqueRefresh atomically burns oldHash and inserts newHash for a
// confidential client. If oldHash was already revoked/rotated, it treats that
// as a replay and revokes the client's active opaque refresh lineage.
func (s *SQLStore) RotateOpaqueRefresh(oldHash, newHash, clientID, tenant, route string, now time.Time, extendBy time.Duration) (*OpaqueRefresh, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: opaque refresh tx: %w", err)
	}
	defer tx.Rollback()
	var (
		r          OpaqueRefresh
		expStr     string
		absExpStr  string
		lastUsed   string
		revokedStr sql.NullString
	)
	err = tx.QueryRow(
		`SELECT token_hash, client_id, tenant_id, route_id, scope, expires_at, absolute_expires_at, last_used_at, revoked_at
		 FROM authz_opaque_refresh WHERE token_hash=?`, oldHash).
		Scan(&r.TokenHash, &r.ClientID, &r.Tenant, &r.Route, &r.Scope, &expStr, &absExpStr, &lastUsed, &revokedStr)
	if err != nil {
		return nil, fmt.Errorf("authz: opaque refresh not found: %w", err)
	}
	if r.ClientID != clientID || r.Tenant != tenant || r.Route != route {
		return nil, fmt.Errorf("authz: opaque refresh binding mismatch")
	}
	nowStr := now.UTC().Format(time.RFC3339Nano)
	if revokedStr.Valid {
		// Replay detected: revoke the entire opaque refresh lineage for this client+route.
		_, _ = tx.Exec(
			`UPDATE authz_opaque_refresh SET revoked_at=? WHERE client_id=? AND tenant_id=? AND route_id=? AND revoked_at IS NULL`,
			nowStr, clientID, tenant, route)
		_ = tx.Commit()
		return nil, fmt.Errorf("authz: opaque refresh replay detected")
	}
	r.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expStr)
	r.AbsoluteExpiresAt, _ = time.Parse(time.RFC3339Nano, absExpStr)
	if now.After(r.ExpiresAt) || now.After(r.AbsoluteExpiresAt) {
		return nil, fmt.Errorf("authz: opaque refresh expired")
	}
	res, err := tx.Exec(
		`UPDATE authz_opaque_refresh SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL`,
		nowStr, oldHash)
	if err != nil {
		return nil, fmt.Errorf("authz: burn opaque refresh: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		_, _ = tx.Exec(
			`UPDATE authz_opaque_refresh SET revoked_at=? WHERE client_id=? AND tenant_id=? AND route_id=? AND revoked_at IS NULL`,
			nowStr, clientID, tenant, route)
		_ = tx.Commit()
		return nil, fmt.Errorf("authz: opaque refresh already rotated")
	}
	nextExp := now.Add(extendBy)
	if nextExp.After(r.AbsoluteExpiresAt) {
		nextExp = r.AbsoluteExpiresAt
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_opaque_refresh(token_hash, client_id, tenant_id, route_id, scope, expires_at, absolute_expires_at, last_used_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		newHash, clientID, tenant, route, r.Scope,
		nextExp.UTC().Format(time.RFC3339Nano),
		r.AbsoluteExpiresAt.UTC().Format(time.RFC3339Nano),
		nowStr); err != nil {
		return nil, fmt.Errorf("authz: insert rotated opaque refresh: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: commit opaque refresh: %w", err)
	}
	return &OpaqueRefresh{
		TokenHash:         newHash,
		ClientID:          clientID,
		Tenant:            tenant,
		Route:             route,
		Scope:             r.Scope,
		ExpiresAt:         nextExp,
		AbsoluteExpiresAt: r.AbsoluteExpiresAt,
		LastUsedAt:        now,
	}, nil
}

// ExtendOpaqueRefresh atomically validates an opaque refresh token for an
// explicitly configured google_confidential client and extends its sliding
// expiration bounded by absolute_expires_at without rotating the token.
func (s *SQLStore) ExtendOpaqueRefresh(tokenHash, clientID, tenant, route string, now time.Time, extendBy time.Duration) (*OpaqueRefresh, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: extend opaque refresh tx: %w", err)
	}
	defer tx.Rollback()
	var (
		r          OpaqueRefresh
		expStr     string
		absExpStr  string
		lastUsed   string
		revokedStr sql.NullString
	)
	err = tx.QueryRow(
		`SELECT token_hash, client_id, tenant_id, route_id, scope, expires_at, absolute_expires_at, last_used_at, revoked_at
		 FROM authz_opaque_refresh WHERE token_hash=?`, tokenHash).
		Scan(&r.TokenHash, &r.ClientID, &r.Tenant, &r.Route, &r.Scope, &expStr, &absExpStr, &lastUsed, &revokedStr)
	if err != nil {
		return nil, fmt.Errorf("authz: opaque refresh not found: %w", err)
	}
	if revokedStr.Valid {
		return nil, fmt.Errorf("authz: opaque refresh revoked")
	}
	if r.ClientID != clientID || r.Tenant != tenant || r.Route != route {
		return nil, fmt.Errorf("authz: opaque refresh binding mismatch")
	}
	r.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expStr)
	r.AbsoluteExpiresAt, _ = time.Parse(time.RFC3339Nano, absExpStr)
	if now.After(r.ExpiresAt) || now.After(r.AbsoluteExpiresAt) {
		return nil, fmt.Errorf("authz: opaque refresh expired")
	}
	nextExp := now.Add(extendBy)
	if nextExp.After(r.AbsoluteExpiresAt) {
		nextExp = r.AbsoluteExpiresAt
	}
	nowStr := now.UTC().Format(time.RFC3339Nano)
	res, err := tx.Exec(
		`UPDATE authz_opaque_refresh SET expires_at=?, last_used_at=? WHERE token_hash=? AND revoked_at IS NULL`,
		nextExp.UTC().Format(time.RFC3339Nano), nowStr, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("authz: extend opaque refresh: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("authz: opaque refresh revoked concurrently")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: commit extend opaque refresh: %w", err)
	}
	r.ExpiresAt = nextExp
	r.LastUsedAt = now
	return &r, nil
}

// RevokeOpaqueRefresh revokes a single opaque refresh token scoped to tenant+route.
func (s *SQLStore) RevokeOpaqueRefresh(tokenHash, tenant, route string, now time.Time) error {
	if _, err := s.db.Exec(
		`UPDATE authz_opaque_refresh SET revoked_at=? WHERE token_hash=? AND tenant_id=? AND route_id=? AND revoked_at IS NULL`,
		now.UTC().Format(time.RFC3339Nano), tokenHash, tenant, route); err != nil {
		return fmt.Errorf("authz: revoke opaque refresh: %w", err)
	}
	return nil
}

// RevokeOpaqueRefreshForClient revokes all opaque refresh tokens for a client.
func (s *SQLStore) RevokeOpaqueRefreshForClient(clientID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`UPDATE authz_opaque_refresh SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL`,
		now, clientID); err != nil {
		return fmt.Errorf("authz: revoke opaque refresh: %w", err)
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
	if _, err := s.db.Exec(
		`DELETE FROM authz_grants
		 WHERE status='pending'
		   AND client_id IN (
		     SELECT id FROM authz_clients WHERE created_at < ? AND revoked_at IS NULL
		   )`,
		cutoff); err != nil {
		return 0, fmt.Errorf("authz: prune pending grants: %w", err)
	}
	res, err := s.db.Exec(
		`DELETE FROM authz_clients
		 WHERE created_at < ? AND revoked_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM authz_grants g
		                    WHERE g.client_id=authz_clients.id
		                      AND g.tenant_id=authz_clients.tenant_id
		                      AND g.route_id=authz_clients.route_id
		                      AND g.status IN ('active', 'revoked'))`,
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
	_ = s.RevokeOpaqueRefreshForClient(id)
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
		skipPairing    int
	)
	err := s.db.QueryRow(
		`SELECT client_id, tenant_id, route_id, status, created_at, updated_at,
		        pairing_hash, pairing_issued_at, pairing_expires_at, pairing_consumed_at,
		        skip_pairing, auth_method, trust_policy_id, owner_issuer, owner_subject
		 FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).
		Scan(&g.ClientID, &g.Tenant, &g.Route, &status, &createdAt, &updatedAt,
			&pairingHash, &pairingIssued, &pairingExpires, &pairingUsed, &skipPairing,
			&g.Provenance.Method, &g.Provenance.TrustPolicyID, &g.Provenance.OwnerIssuer, &g.Provenance.OwnerSubject)
	if err != nil {
		return nil, fmt.Errorf("authz: get grant: %w", err)
	}
	g.Status = GrantStatus(status)
	g.SkipPairing = skipPairing != 0
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
	scope := c.Scope
	if scope == "" {
		scope = "mcp:tools offline_access"
	}
	if _, err := s.db.Exec(
		`INSERT INTO authz_consent(challenge, client_id, tenant_id, route_id, redirect_uri,
		   code_challenge, state, resource, scope, expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		c.Challenge, c.ClientID, c.Tenant, c.Route, c.RedirectURI,
		c.CodeChallenge, c.State, c.Resource, scope, c.ExpiresAt.UTC().Format(time.RFC3339Nano)); err != nil {
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
		`DELETE FROM authz_oidc_tx WHERE consumed_at IS NOT NULL OR expires_at < ?`, nowStr); err != nil {
		return fmt.Errorf("authz: prune oidc tx: %w", err)
	}
	if _, err := s.db.Exec(
		`DELETE FROM authz_revocations WHERE revoked_at < ?`, revCutoff); err != nil {
		return fmt.Errorf("authz: prune revocations: %w", err)
	}
	obsCutoff := now.UTC().Add(-HostObservationRetention).Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`DELETE FROM mcp_host_observations WHERE observed_at < ?`, obsCutoff); err != nil {
		return fmt.Errorf("authz: prune host observations: %w", err)
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
		        state, resource, scope, expires_at, consumed_at FROM authz_consent WHERE challenge=?`,
		challenge).
		Scan(&c.Challenge, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI,
			&c.CodeChallenge, &c.State, &c.Resource, &c.Scope, &expires, &consumed)
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

// ListPendingConsents returns unconsumed, unexpired, pending consent
// transactions for (tenant, route), newest first.
func (s *SQLStore) ListPendingConsents(tenant, route string) ([]Consent, error) {
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.Query(
		`SELECT co.challenge, co.client_id, COALESCE(cl.name, ''), co.tenant_id, co.route_id,
		        co.redirect_uri, co.code_challenge, co.state, co.resource, co.scope,
		        co.decision, co.expires_at
		 FROM authz_consent co
		 LEFT JOIN authz_clients cl ON cl.id = co.client_id
		 WHERE co.tenant_id=? AND co.route_id=? AND co.consumed_at IS NULL
		   AND co.decision='pending' AND co.expires_at > ?
		 ORDER BY co.expires_at DESC`,
		tenant, route, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("authz: list pending consents: %w", err)
	}
	defer rows.Close()
	out := make([]Consent, 0)
	for rows.Next() {
		var c Consent
		var expires string
		if err := rows.Scan(&c.Challenge, &c.ClientID, &c.ClientName, &c.Tenant, &c.Route,
			&c.RedirectURI, &c.CodeChallenge, &c.State, &c.Resource, &c.Scope,
			&c.Decision, &expires); err != nil {
			return nil, fmt.Errorf("authz: scan pending consent: %w", err)
		}
		c.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetConsentStatus returns the current state of a consent challenge scoped to
// (tenant, route) without consuming it.
func (s *SQLStore) GetConsentStatus(challenge, tenant, route string) (*Consent, error) {
	var (
		c        Consent
		expires  string
		consumed sql.NullString
		decided  sql.NullString
	)
	err := s.db.QueryRow(
		`SELECT challenge, client_id, tenant_id, route_id, redirect_uri, code_challenge,
		        state, resource, scope, decision, decided_at, decided_by_key_id, expires_at, consumed_at
		 FROM authz_consent WHERE challenge=? AND tenant_id=? AND route_id=?`,
		challenge, tenant, route,
	).Scan(&c.Challenge, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI, &c.CodeChallenge,
		&c.State, &c.Resource, &c.Scope, &c.Decision, &decided, &c.DecidedByKeyID, &expires, &consumed)
	if err != nil {
		return nil, fmt.Errorf("authz: unknown consent challenge")
	}
	c.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if consumed.Valid {
		t, _ := time.Parse(time.RFC3339Nano, consumed.String)
		c.ConsumedAt = &t
	}
	if decided.Valid {
		t, _ := time.Parse(time.RFC3339Nano, decided.String)
		c.DecidedAt = &t
	}
	if c.Decision == "" {
		c.Decision = "pending"
	}
	return &c, nil
}

// DecideConsentTransaction atomically approves or denies one pending consent
// transaction on behalf of the authenticated publisher operator (Ed25519 keyID).
// Approval activates the durable grant (auth_method='operator_tx', skip_pairing=0)
// in the same SQLite transaction without issuing or copying pairing secrets.
func (s *SQLStore) DecideConsentTransaction(challenge, tenant, route, operatorKeyID string, approve bool) (*Consent, error) {
	if challenge == "" || tenant == "" || route == "" {
		return nil, fmt.Errorf("authz: challenge, tenant, and route are required")
	}
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: decide consent tx: %w", err)
	}
	defer tx.Rollback()

	var fedCount int
	if err := tx.QueryRow(
		`SELECT COUNT(1) FROM authz_visitor_policies
		 WHERE tenant_id=? AND route_id=? AND mode='federated' AND enabled=1 AND revoked_at IS NULL`,
		tenant, route,
	).Scan(&fedCount); err != nil {
		return nil, fmt.Errorf("authz: check visitor auth policy: %w", err)
	}
	if fedCount > 0 {
		return nil, fmt.Errorf("%w: native consent decision prohibited on federated route", ErrFederatedPolicyRequired)
	}

	var (
		c        Consent
		expires  string
		consumed sql.NullString
	)
	err = tx.QueryRow(
		`SELECT challenge, client_id, tenant_id, route_id, redirect_uri, code_challenge,
		        state, resource, scope, decision, expires_at, consumed_at
		 FROM authz_consent WHERE challenge=? AND tenant_id=? AND route_id=?`,
		challenge, tenant, route,
	).Scan(&c.Challenge, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI, &c.CodeChallenge,
		&c.State, &c.Resource, &c.Scope, &c.Decision, &expires, &consumed)
	if err != nil {
		return nil, fmt.Errorf("authz: unknown consent challenge")
	}
	if consumed.Valid {
		return nil, fmt.Errorf("authz: consent challenge already consumed")
	}
	c.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if c.ExpiresAt.IsZero() || now.After(c.ExpiresAt) {
		return nil, fmt.Errorf("authz: consent challenge expired")
	}
	if c.Decision != "" && c.Decision != "pending" {
		return nil, fmt.Errorf("authz: consent challenge already %s", c.Decision)
	}

	var (
		cName    string
		cTenant  string
		cRoute   string
		cRevoked sql.NullString
	)
	if err := tx.QueryRow(
		`SELECT name, tenant_id, route_id, revoked_at FROM authz_clients WHERE id=?`,
		c.ClientID,
	).Scan(&cName, &cTenant, &cRoute, &cRevoked); err != nil || cRevoked.Valid || cTenant != tenant || (cRoute != "" && cRoute != route) {
		return nil, fmt.Errorf("authz: client %q is unknown or revoked", c.ClientID)
	}

	decision := "denied"
	if approve {
		decision = "approved"
		var status string
		gerr := tx.QueryRow(
			`SELECT status FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
			c.ClientID, tenant, route,
		).Scan(&status)
		if gerr != nil && gerr != sql.ErrNoRows {
			return nil, fmt.Errorf("authz: check grant status: %w", gerr)
		}
		if gerr == nil && status == string(GrantRevoked) {
			return nil, fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", c.ClientID, route)
		}
		res, err := tx.Exec(
			`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at, skip_pairing, auth_method)
			 VALUES(?,?,?,?,?,?,0,?)
			 ON CONFLICT(client_id, tenant_id, route_id)
			 DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at,
			   skip_pairing=0, auth_method=excluded.auth_method
			 WHERE authz_grants.status <> 'revoked'`,
			c.ClientID, tenant, route, string(GrantActive), nowStr, nowStr, GrantMethodOperatorTx,
		)
		if err != nil {
			return nil, fmt.Errorf("authz: activate operator_tx grant: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil, fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", c.ClientID, route)
		}
	}

	res, err := tx.Exec(
		`UPDATE authz_consent SET decision=?, decided_at=?, decided_by_key_id=?
		 WHERE challenge=? AND tenant_id=? AND route_id=? AND consumed_at IS NULL AND decision='pending'`,
		decision, nowStr, operatorKeyID, challenge, tenant, route,
	)
	if err != nil {
		return nil, fmt.Errorf("authz: record consent decision: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("authz: consent challenge already decided or consumed")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: commit consent decision: %w", err)
	}
	c.ClientName = cName
	c.Decision = decision
	c.DecidedAt = &now
	c.DecidedByKeyID = operatorKeyID
	return &c, nil
}

// ConsumeDecidedConsent atomically consumes an approved or denied consent
// transaction scoped to (tenant, route) so it can complete at most once.
func (s *SQLStore) ConsumeDecidedConsent(challenge, expectedTenant, expectedRoute string) (*Consent, error) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("authz: consume decided consent tx: %w", err)
	}
	defer tx.Rollback()
	var (
		c        Consent
		expires  string
		consumed sql.NullString
		decided  sql.NullString
	)
	err = tx.QueryRow(
		`SELECT challenge, client_id, tenant_id, route_id, redirect_uri, code_challenge,
		        state, resource, scope, decision, decided_at, decided_by_key_id, expires_at, consumed_at
		 FROM authz_consent WHERE challenge=? AND tenant_id=? AND route_id=?`,
		challenge, expectedTenant, expectedRoute,
	).Scan(&c.Challenge, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI, &c.CodeChallenge,
		&c.State, &c.Resource, &c.Scope, &c.Decision, &decided, &c.DecidedByKeyID, &expires, &consumed)
	if err != nil {
		return nil, fmt.Errorf("authz: unknown consent challenge")
	}
	if consumed.Valid {
		return nil, fmt.Errorf("authz: consent challenge already consumed")
	}
	c.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if c.ExpiresAt.IsZero() || now.After(c.ExpiresAt) {
		return nil, fmt.Errorf("authz: consent challenge expired")
	}
	if c.Decision != "approved" && c.Decision != "denied" {
		return nil, fmt.Errorf("authz: consent challenge is still pending operator decision")
	}
	res, err := tx.Exec(
		`UPDATE authz_consent SET consumed_at=? WHERE challenge=? AND consumed_at IS NULL`,
		nowStr, challenge,
	)
	if err != nil {
		return nil, fmt.Errorf("authz: consume decided consent: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("authz: consent challenge already consumed")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("authz: commit consume decided consent: %w", err)
	}
	c.ConsumedAt = &now
	if decided.Valid {
		t, _ := time.Parse(time.RFC3339Nano, decided.String)
		c.DecidedAt = &t
	}
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

// RecordHostObservation persists a privacy-safe host observation (OCL-009)
// and enforces per-route bounded retention (MaxHostObservationsPerRoute).
func (s *SQLStore) RecordHostObservation(obs HostObservation) error {
	if obs.TenantID == "" || obs.RouteID == "" || obs.Stage == "" {
		return nil
	}
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	if obs.ResultCategory == "" {
		obs.ResultCategory = "ok"
	}
	if obs.ClientKind == "" {
		obs.ClientKind = "generic"
	}
	transportOK := 1
	if obs.TransportStatus == "error" {
		transportOK = 0
	}
	synth := 0
	if obs.IsSynthetic {
		synth = 1
	}
	if _, err := s.db.Exec(
		`INSERT INTO mcp_host_observations(
		   tenant_id, route_id, canonical_url, client_id, client_kind,
		   protocol_version, publication_generation, stage, transport_ok, result_category,
		   is_synthetic, observed_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		obs.TenantID, obs.RouteID, obs.CanonicalURL, obs.ClientID, obs.ClientKind,
		obs.ProtocolVersion, obs.PublicationGeneration, obs.Stage, transportOK, obs.ResultCategory,
		synth, obs.ObservedAt.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("authz: record host observation: %w", err)
	}
	// Bound per-route observation history so long-running relays cannot grow unbounded.
	_, _ = s.db.Exec(
		`DELETE FROM mcp_host_observations
		 WHERE tenant_id=? AND route_id=?
		   AND id NOT IN (
		     SELECT id FROM mcp_host_observations
		     WHERE tenant_id=? AND route_id=?
		     ORDER BY id DESC LIMIT ?
		   )`,
		obs.TenantID, obs.RouteID, obs.TenantID, obs.RouteID, MaxHostObservationsPerRoute,
	)
	return nil
}

// ListHostObservations returns recent host observations for (tenant, route), newest first.
func (s *SQLStore) ListHostObservations(tenant, route string, limit int) ([]HostObservation, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT tenant_id, route_id, canonical_url, client_id, client_kind,
		        protocol_version, publication_generation, stage, transport_ok, result_category,
		        is_synthetic, observed_at
		 FROM mcp_host_observations
		 WHERE tenant_id=? AND route_id=?
		 ORDER BY id DESC LIMIT ?`,
		tenant, route, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("authz: list host observations: %w", err)
	}
	defer rows.Close()
	out := make([]HostObservation, 0)
	for rows.Next() {
		var o HostObservation
		var transportOK int
		var synth int
		var ts string
		if err := rows.Scan(&o.TenantID, &o.RouteID, &o.CanonicalURL, &o.ClientID, &o.ClientKind,
			&o.ProtocolVersion, &o.PublicationGeneration, &o.Stage, &transportOK, &o.ResultCategory, &synth, &ts); err != nil {
			return nil, fmt.Errorf("authz: scan host observation: %w", err)
		}
		if transportOK != 0 {
			o.TransportStatus = "ok"
		} else {
			o.TransportStatus = "error"
		}
		o.IsSynthetic = synth != 0
		o.ObservedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, o)
	}
	return out, rows.Err()
}

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
	var fedCount int
	if err := tx.QueryRow(
		`SELECT COUNT(1) FROM authz_visitor_policies
		 WHERE tenant_id=? AND route_id=? AND mode='federated' AND enabled=1 AND revoked_at IS NULL`,
		tenant, route,
	).Scan(&fedCount); err != nil {
		return fmt.Errorf("authz: check visitor auth policy: %w", err)
	}
	if fedCount > 0 {
		return fmt.Errorf("%w: pairing approval is prohibited on federated route", ErrFederatedPolicyRequired)
	}
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
		   pairing_hash, pairing_issued_at, pairing_expires_at, pairing_consumed_at, auth_method)
		 VALUES(?,?,?,?,?,?,?,?,?,NULL,?)
		 ON CONFLICT(client_id, tenant_id, route_id)
		 DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at,
		   pairing_hash=excluded.pairing_hash, pairing_issued_at=excluded.pairing_issued_at,
		   pairing_expires_at=excluded.pairing_expires_at, pairing_consumed_at=NULL,
		   auth_method=excluded.auth_method
		 WHERE authz_grants.status <> 'revoked'`,
		clientID, tenant, route, string(GrantActive), nowStr, nowStr,
		HashSecret(secret), nowStr, expires, GrantMethodPairing); err != nil {
		return fmt.Errorf("authz: approve grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: approve commit: %w", err)
	}
	return nil
}

// ApproveGrantDirect activates a grant with skip_pairing=1 for a client
// registered in the same tenant (including cross-route grants).
func (s *SQLStore) ApproveGrantDirect(clientID, tenant, route string) error {
	client, cerr := s.GetClient(clientID)
	if cerr != nil {
		return fmt.Errorf("authz: approve grant for unknown client %q: %w", clientID, cerr)
	}
	if client.Tenant == "" {
		return fmt.Errorf("authz: client %q has no tenant registration scope; refusing approval", clientID)
	}
	if client.Tenant != tenant {
		return fmt.Errorf("authz: client %q is registered for tenant %q, not tenant %q",
			clientID, client.Tenant, tenant)
	}
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("authz: approve direct tx: %w", err)
	}
	defer tx.Rollback()
	var fedCount int
	if err := tx.QueryRow(
		`SELECT COUNT(1) FROM authz_visitor_policies
		 WHERE tenant_id=? AND route_id=? AND mode='federated' AND enabled=1 AND revoked_at IS NULL`,
		tenant, route,
	).Scan(&fedCount); err != nil {
		return fmt.Errorf("authz: check visitor auth policy: %w", err)
	}
	if fedCount > 0 {
		return fmt.Errorf("%w: direct approval is prohibited on federated route", ErrFederatedPolicyRequired)
	}
	var status string
	err = tx.QueryRow(
		`SELECT status FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).Scan(&status)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("authz: approve direct grant: %w", err)
	}
	if err == nil && status == string(GrantRevoked) {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", clientID, route)
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at, skip_pairing, auth_method)
		 VALUES(?,?,?,?,?,?,1,?)
		 ON CONFLICT(client_id, tenant_id, route_id)
		 DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, skip_pairing=1, auth_method=excluded.auth_method
		 WHERE authz_grants.status <> 'revoked'`,
		clientID, tenant, route, string(GrantActive), nowStr, nowStr, GrantMethodDirectOperator); err != nil {
		return fmt.Errorf("authz: approve direct grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: approve direct commit: %w", err)
	}
	return nil
}

// ApproveGrantWithProvenance atomically activates a grant with explicit
// authorization provenance (e.g. federated_oidc + trust_policy_id + issuer +
// subject). It refuses revoked grants and cross-tenant clients (OCL-005, OCL-006).
func (s *SQLStore) ApproveGrantWithProvenance(clientID, tenant, route string, skipPairing bool, prov GrantProvenance) error {
	client, cerr := s.GetClient(clientID)
	if cerr != nil {
		return fmt.Errorf("authz: approve grant for unknown client %q: %w", clientID, cerr)
	}
	if client.Tenant == "" || client.Tenant != tenant {
		return fmt.Errorf("authz: client %q is not registered for tenant %q", clientID, tenant)
	}
	if prov.Method == "" {
		prov.Method = GrantMethodLegacy
	}
	skipInt := 0
	if skipPairing {
		skipInt = 1
	}
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("authz: approve provenance tx: %w", err)
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRow(
		`SELECT status FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		clientID, tenant, route).Scan(&status)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("authz: check grant status: %w", err)
	}
	if err == nil && status == string(GrantRevoked) {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", clientID, route)
	}
	if _, err := tx.Exec(
		`INSERT INTO authz_grants(
		   client_id, tenant_id, route_id, status, created_at, updated_at,
		   skip_pairing, auth_method, trust_policy_id, owner_issuer, owner_subject)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(client_id, tenant_id, route_id)
		 DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at,
		   skip_pairing=excluded.skip_pairing, auth_method=excluded.auth_method,
		   trust_policy_id=excluded.trust_policy_id, owner_issuer=excluded.owner_issuer,
		   owner_subject=excluded.owner_subject
		 WHERE authz_grants.status <> 'revoked'`,
		clientID, tenant, route, string(GrantActive), nowStr, nowStr,
		skipInt, prov.Method, prov.TrustPolicyID, prov.OwnerIssuer, prov.OwnerSubject); err != nil {
		return fmt.Errorf("authz: approve grant with provenance: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: approve provenance commit: %w", err)
	}
	return nil
}

// ApproveFederatedGrantAtomic transactionally validates client identity &
// revocation, publication existence & non-revocation (when mcp_publications
// exists), current visitor policy state & revision, allowed issuer & subject,
// current trust policy state & exact redirect match, and grant non-revocation
// inside a SINGLE SQLite transaction before activating the federated grant
// (OCL-005). Any concurrent revocation or policy replacement during IdP token
// exchange rolls back cleanly without activating a grant.
func (s *SQLStore) ApproveFederatedGrantAtomic(req FederatedGrantActivation) error {
	if req.ClientID == "" || req.Tenant == "" || req.Route == "" {
		return fmt.Errorf("authz: federated grant activation requires client, tenant, and route")
	}
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("authz: federated grant tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Verify client identity, revocation, route scope, and redirect URI binding.
	var (
		cTenant   string
		cRoute    string
		cURIsJSON string
		cRevoked  sql.NullString
	)
	if err := tx.QueryRow(
		`SELECT tenant_id, route_id, redirect_uris, revoked_at FROM authz_clients WHERE id=?`,
		req.ClientID,
	).Scan(&cTenant, &cRoute, &cURIsJSON, &cRevoked); err != nil {
		return fmt.Errorf("authz: client %q unknown: %w", req.ClientID, err)
	}
	if cRevoked.Valid {
		return fmt.Errorf("authz: client %q is revoked", req.ClientID)
	}
	if cTenant == "" || cTenant != req.Tenant || (cRoute != "" && cRoute != req.Route) {
		return fmt.Errorf("authz: client %q is not bound to tenant %q route %q", req.ClientID, req.Tenant, req.Route)
	}
	var clientURIs []string
	if err := json.Unmarshal([]byte(cURIsJSON), &clientURIs); err != nil {
		return fmt.Errorf("authz: decode client redirect_uris: %w", err)
	}
	if req.RedirectURI != "" {
		if err := ValidateRedirectURI(req.RedirectURI, clientURIs); err != nil {
			return fmt.Errorf("authz: redirect_uri not bound to client: %w", err)
		}
	}

	// 2. Verify publication identity & non-revocation when mcp_publications exists.
	var pubTable string
	if err := tx.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_publications'`).Scan(&pubTable); err == nil && pubTable != "" {
		var pubRevoked sql.NullString
		if err := tx.QueryRow(
			`SELECT revoked_at FROM mcp_publications WHERE route_id=? AND tenant_id=?`,
			req.Route, req.Tenant,
		).Scan(&pubRevoked); err != nil {
			return fmt.Errorf("authz: publication %q not found for tenant %q", req.Route, req.Tenant)
		}
		if pubRevoked.Valid {
			return fmt.Errorf("authz: publication %q is revoked", req.Route)
		}
	}

	// 3. Verify current visitor policy state, revision, issuer, and allowed subject.
	var (
		vp        VisitorAuthPolicy
		subsJSON  string
		vpEnabled int
		vpRevoked sql.NullString
	)
	err = tx.QueryRow(
		`SELECT tenant_id, route_id, mode, issuer, client_id, allowed_subjects_json,
		        client_policy, enabled, revision, revoked_at
		 FROM authz_visitor_policies WHERE tenant_id=? AND route_id=?`,
		req.Tenant, req.Route,
	).Scan(&vp.TenantID, &vp.RouteID, &vp.Mode, &vp.Issuer, &vp.ClientID, &subsJSON,
		&vp.ClientPolicy, &vpEnabled, &vp.Revision, &vpRevoked)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: visitor auth policy absent", ErrPolicyRevisionMismatch)
	}
	if err != nil {
		return fmt.Errorf("authz: verify visitor auth policy: %w", err)
	}
	vp.Enabled = vpEnabled != 0
	if vpRevoked.Valid {
		t, _ := time.Parse(time.RFC3339Nano, vpRevoked.String)
		vp.RevokedAt = &t
	}
	_ = json.Unmarshal([]byte(subsJSON), &vp.AllowedSubjects)
	if !vp.IsActiveFederated() {
		return fmt.Errorf("%w: visitor auth policy inactive or revoked", ErrPolicyRevisionMismatch)
	}
	if req.ExpectedPolicyRevision > 0 && vp.Revision != req.ExpectedPolicyRevision {
		return fmt.Errorf("%w: expected revision %d, current %d", ErrPolicyRevisionMismatch, req.ExpectedPolicyRevision, vp.Revision)
	}
	if !vp.AllowsSubject(req.OwnerIssuer, req.OwnerSubject) {
		return fmt.Errorf("authz: subject is not allowed by active visitor auth policy")
	}

	// 4. Verify current trust policy state (when required by client_policy or bound by tx).
	if vp.ClientPolicy != "" || req.TrustPolicyID != "" {
		if req.TrustPolicyID == "" {
			return fmt.Errorf("%w: missing required trust policy binding", ErrTrustPolicyInactive)
		}
		var (
			tpTenant   string
			tpRoute    string
			tpKind     string
			tpURIsJSON string
			tpEnabled  int
			tpRevoked  sql.NullString
		)
		err = tx.QueryRow(
			`SELECT tenant_id, route_id, kind, redirect_uris_json, enabled, revoked_at
			 FROM authz_trust_policies WHERE id=?`,
			req.TrustPolicyID,
		).Scan(&tpTenant, &tpRoute, &tpKind, &tpURIsJSON, &tpEnabled, &tpRevoked)
		if err != nil || tpTenant != req.Tenant || tpRoute != req.Route || tpEnabled != 1 || tpRevoked.Valid {
			return ErrTrustPolicyInactive
		}
		var tpURIs []string
		if uerr := json.Unmarshal([]byte(tpURIsJSON), &tpURIs); uerr != nil || !ExactRedirectURISetEqual(tpURIs, clientURIs) {
			return ErrTrustPolicyInactive
		}
		if vp.ClientPolicy != "" && vp.ClientPolicy != "custom" && tpKind != vp.ClientPolicy {
			return ErrTrustPolicyInactive
		}
	}

	// 5. Verify existing grant is not revoked (revocation is terminal).
	var status string
	err = tx.QueryRow(
		`SELECT status FROM authz_grants WHERE client_id=? AND tenant_id=? AND route_id=?`,
		req.ClientID, req.Tenant, req.Route,
	).Scan(&status)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("authz: check grant status: %w", err)
	}
	if err == nil && status == string(GrantRevoked) {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", req.ClientID, req.Route)
	}

	// 6. Atomically activate the federated grant.
	res, err := tx.Exec(
		`INSERT INTO authz_grants(
		   client_id, tenant_id, route_id, status, created_at, updated_at,
		   skip_pairing, auth_method, trust_policy_id, owner_issuer, owner_subject)
		 VALUES(?,?,?,?,?,?,0,?,?,?,?)
		 ON CONFLICT(client_id, tenant_id, route_id)
		 DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at,
		   skip_pairing=0, auth_method=excluded.auth_method,
		   trust_policy_id=excluded.trust_policy_id, owner_issuer=excluded.owner_issuer,
		   owner_subject=excluded.owner_subject
		 WHERE authz_grants.status <> 'revoked'`,
		req.ClientID, req.Tenant, req.Route, string(GrantActive), nowStr, nowStr,
		GrantMethodFederatedOIDC, req.TrustPolicyID, req.OwnerIssuer, req.OwnerSubject,
	)
	if err != nil {
		return fmt.Errorf("authz: activate federated grant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("authz: grant for client %q route %q is revoked; revocation is terminal", req.ClientID, req.Route)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authz: commit federated grant: %w", err)
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
	scope := c.Scope
	if scope == "" {
		scope = "mcp:tools offline_access"
	}
	_, err := s.db.Exec(
		`INSERT INTO authz_codes(code, client_id, tenant_id, route_id, redirect_uri, challenge, challenge_method, scope, expires_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		c.Code, c.ClientID, c.Tenant, c.Route, c.RedirectURI, c.Challenge, c.ChallengeMethod, scope,
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
		`SELECT code, client_id, tenant_id, route_id, redirect_uri, challenge, challenge_method, scope, expires_at, consumed_at
		 FROM authz_codes WHERE code=?`, code).
		Scan(&c.Code, &c.ClientID, &c.Tenant, &c.Route, &c.RedirectURI, &c.Challenge, &c.ChallengeMethod, &c.Scope, &expiresAt, &consumed)
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

// ListGrants returns every grant, newest first, joined with client metadata.
func (s *SQLStore) ListGrants() ([]Grant, error) {
	rows, err := s.db.Query(
		`SELECT g.client_id, COALESCE(c.name, ''), COALESCE(c.redirect_uris, '[]'),
		        g.tenant_id, g.route_id, g.status, g.created_at, g.updated_at, g.skip_pairing,
		        g.auth_method, g.trust_policy_id, g.owner_issuer, g.owner_subject
		 FROM authz_grants g
		 LEFT JOIN authz_clients c ON c.id = g.client_id
		 ORDER BY g.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("authz: list grants: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		var status, createdAt, updatedAt, redirectsJSON string
		var skipPairing int
		if err := rows.Scan(&g.ClientID, &g.ClientName, &redirectsJSON,
			&g.Tenant, &g.Route, &status, &createdAt, &updatedAt, &skipPairing,
			&g.Provenance.Method, &g.Provenance.TrustPolicyID, &g.Provenance.OwnerIssuer, &g.Provenance.OwnerSubject); err != nil {
			return nil, fmt.Errorf("authz: scan grant: %w", err)
		}
		g.Status = GrantStatus(status)
		g.SkipPairing = skipPairing != 0
		_ = json.Unmarshal([]byte(redirectsJSON), &g.RedirectURIs)
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
