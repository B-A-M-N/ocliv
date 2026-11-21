// Package store owns durable relay metadata in SQLite (WAL): tenants, agent
// keys, leases, access token verifiers, visitor sessions, enrollment grants,
// and audit events (spec section 5). It stores only verifiers, never raw
// secrets. In-memory sockets are never persisted (F11).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"ocliv/internal/apperr"
)

// Schema versions; migrations are explicit and rollback-aware (H07).
const schemaV1 = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS schema_version (v INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT NOT NULL, quotas_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS agent_keys (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
  ed25519_public BLOB NOT NULL, status TEXT NOT NULL,
  created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS leases (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_key_id TEXT NOT NULL,
  hostname TEXT NOT NULL UNIQUE, label TEXT NOT NULL, port INTEGER NOT NULL,
  access_mode TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
  token_generation INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL, expires_at TEXT, reconnect_until TEXT,
  created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_leases_host ON leases(hostname);
CREATE TABLE IF NOT EXISTS access_tokens (
  id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES leases(id),
  verifier TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'visitor',
  created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT,
  max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_tokens_verifier ON access_tokens(verifier);
CREATE TABLE IF NOT EXISTS visitor_sessions (
  id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES leases(id),
  token_generation INTEGER NOT NULL DEFAULT 0, session_verifier TEXT NOT NULL,
  created_at TEXT NOT NULL, idle_expires_at TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS enrollment_codes (
  id TEXT PRIMARY KEY, verifier TEXT NOT NULL, tenant_id TEXT NOT NULL,
  expires_at TEXT NOT NULL, used_at TEXT, issued_by TEXT NOT NULL DEFAULT 'operator');
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, actor TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT '', lease_id TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS mgmt_replay (
  id TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
-- Path-route mappings for single-host MCP ingress (P0-A). A row is only
-- a routing hint: admission always re-checks the bound lease's status,
-- TTL, live session, and generation, plus the lease's access_mode
-- binding (P0-B). Rows carry no secrets; a route can never create a
-- tunnel, select an executable, or bypass ownership.
CREATE TABLE IF NOT EXISTS mcp_routes (
  route_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES leases(id),
  external_host TEXT NOT NULL, profile TEXT NOT NULL,
  target_path TEXT NOT NULL DEFAULT '/mcp', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_mcp_routes_lease ON mcp_routes(lease_id);
`

// schemaV2 revokes legacy visitor_sessions rows. Before P0-4 the session
// bearer was stored as the row id; any database written by the old code
// may still hold usable browser credentials, so migration invalidates
// those sessions — cookie re-authentication is required after upgrade.
const schemaV2 = `
DELETE FROM visitor_sessions;
`

// schemaV3 makes concurrent route publication idempotent (P1-4): one
// logical publication — one (lease, host, profile) — owns exactly one
// route row. Pre-existing duplicates collapse to the earliest mapping
// before the uniqueness constraint lands.
const schemaV3 = `
DELETE FROM mcp_routes WHERE rowid NOT IN
  (SELECT MIN(rowid) FROM mcp_routes GROUP BY lease_id, external_host, profile);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_routes_logical
  ON mcp_routes(lease_id, external_host, profile);
`

// schemaV4 replaces lease-bound mcp_routes with durable publications
// (P1-A): one stable route per (tenant, owner key, external host,
// profile, publication label), rebound across leases. Legacy rows
// migrate with their route_id preserved (stable URL); duplicate
// natural keys keep the earliest route; rows whose lease is gone could
// never admit and are dropped. mcp_routes is retired afterwards.
const schemaV4 = `
CREATE TABLE IF NOT EXISTS mcp_publications (
  route_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL, owner_key_id TEXT NOT NULL,
  external_host TEXT NOT NULL, profile TEXT NOT NULL,
  pub_name TEXT NOT NULL, target_path TEXT NOT NULL DEFAULT '/mcp',
  -- Deferred: named-lease reclaim deletes the old lease and rebinds
  -- its publications to the replacement within one transaction; the
  -- commit state is always consistent (P1-A).
  lease_id TEXT REFERENCES leases(id) DEFERRABLE INITIALLY DEFERRED, revoked_at TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, target_path, lease_id, created_at, updated_at)
  SELECT r.route_id, l.tenant_id, l.agent_key_id, r.external_host, r.profile, l.label, r.target_path, r.lease_id, r.created_at, r.created_at
  FROM mcp_routes r JOIN leases l ON l.id = r.lease_id;
DELETE FROM mcp_publications WHERE rowid NOT IN
  (SELECT MIN(rowid) FROM mcp_publications GROUP BY tenant_id, owner_key_id, external_host, profile, pub_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_publications_logical
  ON mcp_publications(tenant_id, owner_key_id, external_host, profile, pub_name);
DROP TABLE mcp_routes;
`

// schemaV5 adds pending-verification publication state (P0-A): new
// rows register unverified (verified_at NULL) and deny tool traffic
// until the publisher completes discovery verification and
// activation. Existing rows grandfather as verified — they are live,
// operator-established bindings, not new unverified supply. The
// lease_id index serves the wildcard pending check without
// re-scanning the logical-key index.
const schemaV5 = `
ALTER TABLE mcp_publications ADD COLUMN verified_at TEXT;
UPDATE mcp_publications SET verified_at = created_at WHERE verified_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_publications_lease ON mcp_publications(lease_id);
`

// schemaV6 indexes audit event time for the retention sweep (Stage 6,
// chaos finding A2). No rows are deleted by the migration itself; the
// relay prunes rows older than AuditRetention at boot.
const schemaV6 = `
CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(time);
`

// schemaV7 attributes audit events to the authenticated key that caused
// them (post-qualification hardening). Existing rows keep the empty
// default; management-plane denials are queryable by key without parsing
// free text. No rows are deleted.
const schemaV7 = `
ALTER TABLE audit_events ADD COLUMN key_id TEXT NOT NULL DEFAULT '';
`

// schemaV8 adds the managed-authorization state (Phase 2): dynamically
// registered clients, per-tenant/per-route grants, single-use authorization
// codes, and the relay's issuer key. Forward-only; the issuer key makes this
// database a secret (it already holds enrollment verifiers).
const schemaV8 = `
CREATE TABLE IF NOT EXISTS authz_clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS authz_grants (
  client_id TEXT NOT NULL, tenant_id TEXT NOT NULL, route_id TEXT NOT NULL,
  status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (client_id, tenant_id, route_id));
CREATE INDEX IF NOT EXISTS idx_authz_grants_route ON authz_grants(tenant_id, route_id);
CREATE TABLE IF NOT EXISTS authz_codes (
  code TEXT PRIMARY KEY, client_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
  route_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  challenge TEXT NOT NULL, challenge_method TEXT NOT NULL,
  expires_at TEXT NOT NULL, consumed_at TEXT);
CREATE INDEX IF NOT EXISTS idx_authz_codes_expires ON authz_codes(expires_at);
CREATE TABLE IF NOT EXISTS authz_issuer_key (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  kid TEXT NOT NULL, priv BLOB NOT NULL, created_at TEXT NOT NULL);
`

// schemaV9 closes the public-client impersonation and fake-revocation
// findings: each grant carries a pairing secret hash (the operator's
// out-of-band approval credential), tokens carry a revocation key, and
// authorization-plane decisions are audited. Forward-only.
const schemaV9 = `
ALTER TABLE authz_grants ADD COLUMN pairing_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE authz_grants ADD COLUMN pairing_issued_at TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS authz_revocations (
  jti TEXT PRIMARY KEY, client_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
  route_id TEXT NOT NULL, revoked_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_authz_revocations_client ON authz_revocations(client_id);
CREATE TABLE IF NOT EXISTS authz_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL,
  actor TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',
  route_id TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_authz_audit_time ON authz_audit(time);
`

// schemaV10 replaces the URL-borne pairing credential with a one-time,
// expiring, transaction-bound consent challenge.
const schemaV10 = `
CREATE TABLE IF NOT EXISTS authz_consent (
  challenge TEXT PRIMARY KEY, client_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
  route_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL, state TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL, consumed_at TEXT);
CREATE INDEX IF NOT EXISTS idx_authz_consent_expires ON authz_consent(expires_at);
`

// schemaV11 completes the managed-authorization pairing lifecycle: the
// pairing credential gains an enforced expiry and single-use consumption,
// the consent challenge records the canonical resource so every field of
// the transaction can be rebound on completion, and public dynamic client
// registration is route-scoped so registration can be bounded per route.
// Forward-only; legacy rows keep fail-closed defaults.
const schemaV11 = `
ALTER TABLE authz_grants ADD COLUMN pairing_expires_at TEXT NOT NULL DEFAULT '';
ALTER TABLE authz_grants ADD COLUMN pairing_consumed_at TEXT;
ALTER TABLE authz_consent ADD COLUMN resource TEXT NOT NULL DEFAULT '';
ALTER TABLE authz_clients ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE authz_clients ADD COLUMN route_id TEXT NOT NULL DEFAULT '';
`

// schemaV12 adds durable administrative desired_enabled state and a
// monotonic state_generation CAS counter to mcp_publications so
// operator disablement is distinct from unexpected outage, survives
// restarts, and cannot be overridden by a stale publisher reconnect.
// Forward-only; existing rows default to desired_enabled=1 and keep
// all authorization grants and route identities intact.
const schemaV12 = `
ALTER TABLE mcp_publications ADD COLUMN desired_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE mcp_publications ADD COLUMN state_generation INTEGER NOT NULL DEFAULT 1;
`

// schemaV13 adds skip_pairing to authz_grants so an operator-approved
// direct grant (--direct) can bypass the interactive browser pairing_secret
// consent form while keeping pairing_secret mandatory for standard grants.
const schemaV13 = `
ALTER TABLE authz_grants ADD COLUMN skip_pairing INTEGER NOT NULL DEFAULT 0;
`

// schemaV14 adds confidential-client support (client_mode, client_secret_hash)
// and opaque persistent refresh tokens (authz_opaque_refresh) for pre-registered
// confidential clients (e.g. Google Connected Apps persistent linking).
const schemaV14 = `
ALTER TABLE authz_clients ADD COLUMN client_secret_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE authz_clients ADD COLUMN client_mode TEXT NOT NULL DEFAULT 'public';
CREATE TABLE IF NOT EXISTS authz_opaque_refresh (
	token_hash TEXT PRIMARY KEY,
	client_id TEXT NOT NULL,
	tenant_id TEXT NOT NULL,
	route_id TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	absolute_expires_at TEXT NOT NULL,
	last_used_at TEXT NOT NULL,
	revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_authz_opaque_refresh_client ON authz_opaque_refresh(client_id, tenant_id, route_id);
`

// schemaV15 persists granted OAuth scopes on authorization challenges and codes.
const schemaV15 = `
ALTER TABLE authz_codes ADD COLUMN scope TEXT NOT NULL DEFAULT 'mcp:tools offline_access';
ALTER TABLE authz_consent ADD COLUMN scope TEXT NOT NULL DEFAULT 'mcp:tools offline_access';
`

// schemaV16 adds explicit refresh_policy to authz_clients so pre-registered
// confidential Google Connected App clients can opt into stable-token refresh
// without weakening public-client rotation.
const schemaV16 = `
ALTER TABLE authz_clients ADD COLUMN refresh_policy TEXT NOT NULL DEFAULT '';
`

// schemaV17 persists granted scope on authz_opaque_refresh so confidential
// refresh tokens cannot escalate scope beyond what was originally authorized.
const schemaV17 = `
ALTER TABLE authz_opaque_refresh ADD COLUMN scope TEXT NOT NULL DEFAULT '';
`

// schemaV18 marks persistent hosted leases so ordinary daemon restarts,
// reboots, and >90-second network outages retain the lease identity and
// protected visitor sessions rather than expiring after ephemeral grace.
const schemaV18 = `
ALTER TABLE leases ADD COLUMN persistent INTEGER NOT NULL DEFAULT 0;
`

// schemaV19 adds publisher-initiated pairing requests. A publisher can
// submit its public key to get a short display code; the relay operator
// then approves the code to complete enrollment without exchanging secrets
// out-of-band. Rate-limited per source IP, single-use, 10-minute TTL.
const schemaV19 = `
CREATE TABLE IF NOT EXISTS pairing_requests (
  id TEXT PRIMARY KEY,
  display_code TEXT NOT NULL,
  public_key BLOB NOT NULL,
  key_id TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  resolved_at TEXT,
  enrollment_code_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_pairing_requests_code ON pairing_requests(display_code);
CREATE INDEX IF NOT EXISTS idx_pairing_requests_status ON pairing_requests(status, expires_at);
`

// schemaV20 splits the pairing display code from the polling credential.
// Polling now requires a high-entropy poll_id + poll_verifier that is never
// equal to the human-readable display code. The display_code column gains a
// UNIQUE constraint; display-code-only polling is refused at the handler layer.
// Pre-V20 pending requests have no poll_verifier and cannot be polled under the
// new protocol, so migration explicitly expires them (pairing requests are
// intentionally non-surviving across this incompatible protocol upgrade).
const schemaV20 = `
ALTER TABLE pairing_requests ADD COLUMN poll_id TEXT;
ALTER TABLE pairing_requests ADD COLUMN poll_verifier BLOB;
UPDATE pairing_requests
  SET status = 'expired',
      resolved_at = COALESCE(resolved_at, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  WHERE status = 'pending' AND poll_verifier IS NULL;
UPDATE pairing_requests SET poll_id = id WHERE poll_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pairing_requests_poll_id
  ON pairing_requests(poll_id) WHERE poll_id IS NOT NULL;
DELETE FROM pairing_requests WHERE rowid NOT IN (
  SELECT MIN(rowid) FROM pairing_requests GROUP BY display_code);
DROP INDEX IF EXISTS idx_pairing_requests_code;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pairing_requests_display_code
  ON pairing_requests(display_code);
`

// schemaV21 adds a dedicated resolved_tenant_id column to pairing_requests so
// approved tenant IDs are no longer overloaded into enrollment_code_id. It also
// expires any legacy pending rows lacking poll_verifier left by earlier V20 DBs.
const schemaV21 = `
ALTER TABLE pairing_requests ADD COLUMN resolved_tenant_id TEXT NOT NULL DEFAULT '';
UPDATE pairing_requests
  SET resolved_tenant_id = COALESCE(enrollment_code_id, '')
  WHERE status = 'approved' AND resolved_tenant_id = '';
UPDATE pairing_requests
  SET status = 'expired',
      resolved_at = COALESCE(resolved_at, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  WHERE status = 'pending' AND poll_verifier IS NULL;
`

// schemaV22 enforces at most one live pending pairing request per key_id via
// a partial unique index, after expiring any older duplicate pending rows.
const schemaV22 = `
UPDATE pairing_requests
  SET status = 'expired',
      resolved_at = COALESCE(resolved_at, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  WHERE status = 'pending'
    AND rowid NOT IN (
      SELECT MAX(rowid) FROM pairing_requests WHERE status = 'pending' GROUP BY key_id
    );
CREATE UNIQUE INDEX IF NOT EXISTS idx_pairing_requests_one_pending_per_key
  ON pairing_requests(key_id) WHERE status = 'pending';
`

// applyMigration runs one versioned migration body and its version
// stamp in a single transaction: a failure anywhere rolls back the
// body, so a version is never recorded for half-applied work (P1-2).
// SQLite DDL is transactional, so index creation participates too.
func applyMigration(sqldb *sql.DB, version int, body string) error {
	tx, err := sqldb.Begin()
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "beginning migration", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(body); err != nil {
		return apperr.E(apperr.CodeStoreFault, "migrating state database", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO schema_version(v, applied_at) VALUES(?, ?)`,
		version, utcNow()); err != nil {
		return apperr.E(apperr.CodeStoreFault, "recording schema version", err)
	}
	if err := tx.Commit(); err != nil {
		return apperr.E(apperr.CodeStoreFault, "committing migration", err)
	}
	return nil
}

// currentSchema is the newest version Open must reach.
const currentSchema = 22

// SchemaVersion is the exported current schema version for tools that must
// refuse unknown/newer databases without opening (and thereby migrating)
// them, such as the restore-time read-only preflight.
const SchemaVersion = currentSchema

// PairingRequest is one pending publisher-initiated pairing request.
type PairingRequest struct {
	ID               string
	DisplayCode      string
	PollID           string
	PollVerifier     []byte
	PublicKey        []byte
	KeyID            string
	SourceIP         string
	Status           string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ResolvedAt       *time.Time
	ResolvedTenantID string
	// EnrollmentCodeID is retained only for schema backward compatibility;
	// new code uses ResolvedTenantID exclusively.
	EnrollmentCodeID string
}

// DB wraps the SQLite handle.
type DB struct {
	sql *sql.DB
}

// Open opens (creating with 0600 when new) and migrates the database.
// Unknown schema versions fail closed (F12).
//
// The pool is a single connection: the relay control plane is low-rate but
// lock-sensitive (auth checks race audit writes), and a single serialized
// connection eliminates SQLITE_BUSY between concurrent control operations.
// The data plane (yamux streams) never touches SQLite per-byte.
// ensurePrivateDir guarantees the database directory exists and is
// owner-only. MkdirAll does not repair a pre-existing permissive
// directory, so an explicit chmod plus verification closes that gap
// (P1-3). A directory that cannot be made private fails the open.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating state directory", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return apperr.E(apperr.CodeStoreFault, "securing state directory", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "stating state directory", err)
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return apperr.E(apperr.CodeStoreFault, "state directory not private", nil)
	}
	return nil
}

// lockDownFiles enforces owner-only permissions on the database and any
// SQLite sidecars (-wal, -shm, -journal) left by earlier runs under a
// permissive umask, then verifies (P1-3).
func lockDownFiles(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return apperr.E(apperr.CodeStoreFault, "stating state database", err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			return apperr.E(apperr.CodeStoreFault, "securing state database", err)
		}
	}
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || fi.Mode().Perm()&0o077 != 0 {
			return apperr.E(apperr.CodeStoreFault, "state database not private", err)
		}
	}
	return nil
}

// preflightSchema opens an existing database read-only before any migration
// statements run. A newer binary must refuse a future schema without even
// creating missing V1 tables or inserting the V1 marker into that database.
func preflightSchema(path string) error {
	if path == ":memory:" {
		return nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect state database before migration: %w", err)
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	uri := (&url.URL{Scheme: "file", Path: absolute}).String() + "?mode=ro"
	ro, err := sql.Open("sqlite", uri)
	if err != nil {
		return fmt.Errorf("open state database for schema preflight: %w", err)
	}
	defer ro.Close()
	ro.SetMaxOpenConns(1)

	var tableCount int
	if err := ro.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&tableCount); err != nil {
		return fmt.Errorf("inspect state database schema: %w", err)
	}
	if tableCount == 0 {
		return nil // existing but empty SQLite file
	}
	var versionTable int
	if err := ro.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'`).Scan(&versionTable); err != nil {
		return fmt.Errorf("inspect state database version table: %w", err)
	}
	if versionTable != 1 {
		return fmt.Errorf("state database has tables but no schema version; refusing migration")
	}
	var version sql.NullInt64
	if err := ro.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&version); err != nil {
		return fmt.Errorf("read state database schema version: %w", err)
	}
	if !version.Valid || version.Int64 < 1 {
		return fmt.Errorf("invalid state database schema version")
	}
	if version.Int64 > currentSchema {
		return fmt.Errorf("unknown state schema version %d", version.Int64)
	}
	return nil
}

func Open(path string) (*DB, error) {
	if err := preflightSchema(path); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "preflighting state database schema", err)
	}
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	sqldb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "opening state database", err)
	}
	sqldb.SetMaxOpenConns(1)
	if _, err := sqldb.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		sqldb.Close()
		return nil, apperr.E(apperr.CodeStoreFault, "setting busy timeout", err)
	}
	// The schema declares REFERENCES edges; they only constrain writes
	// when enforcement is on (SQLite default is off). Fail closed when
	// the pragma cannot be enabled or verified.
	if _, err := sqldb.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		sqldb.Close()
		return nil, apperr.E(apperr.CodeStoreFault, "enabling foreign keys", err)
	}
	var fk int
	if err := sqldb.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		sqldb.Close()
		return nil, apperr.E(apperr.CodeStoreFault, "foreign key enforcement not active", err)
	}
	if _, err := sqldb.Exec(schemaV1); err != nil {
		sqldb.Close()
		return nil, apperr.E(apperr.CodeStoreFault, "migrating state database", err)
	}
	if _, err := sqldb.Exec(`INSERT OR IGNORE INTO schema_version(v, applied_at) VALUES(1, ?)`, utcNow()); err != nil {
		sqldb.Close()
		return nil, apperr.E(apperr.CodeStoreFault, "recording schema version", err)
	}
	// Numbered forward migrations. Each step runs once, guarded by the
	// recorded version; downgrade or unknown-newer databases fail closed.
	migrations := []struct {
		version int
		sql     string
	}{
		{2, schemaV2},
		{3, schemaV3},
		{4, schemaV4},
		{5, schemaV5},
		{6, schemaV6},
		{7, schemaV7},
		{8, schemaV8},
		{9, schemaV9},
		{10, schemaV10},
		{11, schemaV11},
		{12, schemaV12},
		{13, schemaV13},
		{14, schemaV14},
		{15, schemaV15},
		{16, schemaV16},
		{17, schemaV17},
		{18, schemaV18},
		{19, schemaV19},
		{20, schemaV20},
		{21, schemaV21},
		{22, schemaV22},
	}
	for _, m := range migrations {
		var v int
		if err := sqldb.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil {
			sqldb.Close()
			return nil, apperr.E(apperr.CodeStoreFault, "reading schema version", err)
		}
		switch {
		case v > currentSchema:
			// Newer-than-known database (downgrade): fail closed
			// before any migration write.
			sqldb.Close()
			return nil, apperr.E(apperr.CodeStoreFault, "unknown state schema version", nil)
		case v < m.version:
			if err := applyMigration(sqldb, m.version, m.sql); err != nil {
				sqldb.Close()
				return nil, err
			}
		default:
			// Already applied (e.g. re-open); nothing to do.
		}
	}
	var v int
	if err := sqldb.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != currentSchema {
		sqldb.Close()
		return nil, apperr.E(apperr.CodeStoreFault, "unknown state schema version", err)
	}
	// Files created under a permissive umask (including -wal/-shm from
	// this open) must not stay group/world-readable (P1-3).
	if err := lockDownFiles(path); err != nil {
		sqldb.Close()
		return nil, err
	}
	return &DB{sql: sqldb}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// SQL exposes the handle for transactional owners (relay only).
func (d *DB) SQL() *sql.DB { return d.sql }

func utcNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// Audit records a redacted operational event (H04). detail must already be
// redacted by the caller; never pass secrets, paths, or query strings.
func (d *DB) Audit(actor, tenantID, leaseID, category, result, detail string) {
	_, _ = d.sql.Exec(
		`INSERT INTO audit_events(time, actor, tenant_id, lease_id, category, result, detail) VALUES(?,?,?,?,?,?,?)`,
		utcNow(), actor, tenantID, leaseID, category, result, detail)
}

// AuditKey is Audit with the authenticated key identifier recorded in its
// own column (schemaV7). Use it for key-scoped management-plane events so
// a denied attempt can be attributed without parsing the detail string.
// keyID must be the already-authenticated key identifier, never a secret.
func (d *DB) AuditKey(actor, tenantID, keyID, leaseID, category, result, detail string) {
	_, _ = d.sql.Exec(
		`INSERT INTO audit_events(time, actor, tenant_id, key_id, lease_id, category, result, detail) VALUES(?,?,?,?,?,?,?,?)`,
		utcNow(), actor, tenantID, keyID, leaseID, category, result, detail)
}

// AuditRetention is the operator-visible audit evidence window (Stage 6,
// chaos finding A2): every denied request writes an audit row and no
// code path reclaimed them, so months of probing filled the disk and
// bloated backups. Rows older than this are pruned at relay boot
// (reconcileBoot). 90 days preserves recent incident evidence while
// bounding growth; revocation state itself lives in leases/agent_keys
// (revoked_at), so pruning audit rows can never resurrect authority.
const AuditRetention = 90 * 24 * time.Hour

// TenantPolicy governs what a tenant's publishers may expose.
// Stored as JSON in tenants.quotas_json. Zero value is the safe default
// (no public exposure, unlimited leases).
type TenantPolicy struct {
	AllowPublic         bool `json:"allow_public"`          // default false: public exposure denied
	MaxActiveLeases     int  `json:"max_active_leases"`     // 0 = unlimited
	MaxPersistentLeases int  `json:"max_persistent_leases"` // 0 = unlimited
}

// GetTenantPolicy reads the quota_json policy for tenantID.
// Returns an error on missing tenant, corrupt JSON, or database failure —
// never silently returns zero-value (which would mean unlimited quotas).
func (d *DB) GetTenantPolicy(tenantID string) (TenantPolicy, error) {
	var raw string
	if err := d.sql.QueryRow(`SELECT quotas_json FROM tenants WHERE id=?`, tenantID).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return TenantPolicy{}, apperr.E(apperr.CodeStoreFault, "tenant not found", err)
		}
		return TenantPolicy{}, apperr.E(apperr.CodeStoreFault, "reading tenant policy", err)
	}
	var p TenantPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return TenantPolicy{}, apperr.E(apperr.CodeStoreFault, "corrupt tenant policy JSON", err)
	}
	return p, nil
}

// SetTenantPolicy writes policy to quotas_json for tenantID.
func (d *DB) SetTenantPolicy(tenantID string, p TenantPolicy) error {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encoding policy: %w", err)
	}
	res, err := d.sql.Exec(`UPDATE tenants SET quotas_json=? WHERE id=?`, string(b), tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tenant %q not found", tenantID)
	}
	return nil
}

// PruneAuditEvents deletes audit rows older than AuditRetention relative
// to now and returns the deleted count. Times are RFC3339Nano UTC, so
// lexicographic comparison orders them. The DELETE is idempotent and
// single-statement: safe to repeat, and a failure only skips pruning,
// never blocks serving.
func (d *DB) PruneAuditEvents(now time.Time) (int64, error) {
	cutoff := now.UTC().Add(-AuditRetention).Format(time.RFC3339Nano)
	res, err := d.sql.Exec(`DELETE FROM audit_events WHERE time < ?`, cutoff)
	if err != nil {
		return 0, apperr.E(apperr.CodeStoreFault, "pruning audit events", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, apperr.E(apperr.CodeStoreFault, "pruning audit events", err)
	}
	return n, nil
}

// CreatePairingRequestSuperseding atomically expires any existing pending
// pairing request for keyID and inserts the new pending request in a single
// transaction, preserving the one-pending-request-per-key invariant.
func (d *DB) CreatePairingRequestSuperseding(id, displayCode, pollID string, pollVerifier, pubKey []byte, keyID, sourceIP string, expiresAt time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := d.sql.Begin()
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "beginning pairing transaction", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE pairing_requests SET status='expired', resolved_at=?
		 WHERE key_id=? AND status='pending'`,
		now, keyID); err != nil {
		return apperr.E(apperr.CodeStoreFault, "superseding prior pairing request", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO pairing_requests(id, display_code, poll_id, poll_verifier, public_key, key_id, source_ip, status, created_at, expires_at)
		 VALUES(?,?,?,?,?,?,?,'pending',?,?)`,
		id, displayCode, pollID, pollVerifier, pubKey, keyID, sourceIP, now, expiresAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return apperr.E(apperr.CodeStoreFault, "storing pairing request", err)
	}
	if err := tx.Commit(); err != nil {
		return apperr.E(apperr.CodeStoreFault, "committing pairing request", err)
	}
	return nil
}

// CreatePairingRequest stores a new pending publisher-initiated pairing request.
// pollID is the opaque lookup key; pollVerifier is the SHA-256 hash of the
// poll secret — the raw secret is never stored.
func (d *DB) CreatePairingRequest(id, displayCode, pollID string, pollVerifier, pubKey []byte, keyID, sourceIP string, expiresAt time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.sql.Exec(
		`INSERT INTO pairing_requests(id, display_code, poll_id, poll_verifier, public_key, key_id, source_ip, status, created_at, expires_at)
		 VALUES(?,?,?,?,?,?,?,'pending',?,?)`,
		id, displayCode, pollID, pollVerifier, pubKey, keyID, sourceIP, now, expiresAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "storing pairing request", err)
	}
	return nil
}

// GetPairingRequest looks up a pairing request by its display code.
// Used by operator-side approval (ApprovePairingRequest) — the display
// code is typed by the human operator, not held by the publisher.
func (d *DB) GetPairingRequest(displayCode string) (PairingRequest, error) {
	row := d.sql.QueryRow(
		`SELECT id, display_code, COALESCE(poll_id,''), COALESCE(poll_verifier,X''),
		        public_key, key_id, source_ip, status, created_at, expires_at,
		        resolved_at, COALESCE(resolved_tenant_id,''), COALESCE(enrollment_code_id,'')
		 FROM pairing_requests WHERE display_code=?`, displayCode)
	return scanPairingRequest(row)
}

// GetPairingRequestByPollID looks up a pairing request by its high-entropy
// poll_id. The caller must verify the poll secret against PollVerifier using
// constant-time comparison — this function does not perform secret verification.
func (d *DB) GetPairingRequestByPollID(pollID string) (PairingRequest, error) {
	row := d.sql.QueryRow(
		`SELECT id, display_code, COALESCE(poll_id,''), COALESCE(poll_verifier,X''),
		        public_key, key_id, source_ip, status, created_at, expires_at,
		        resolved_at, COALESCE(resolved_tenant_id,''), COALESCE(enrollment_code_id,'')
		 FROM pairing_requests WHERE poll_id=?`, pollID)
	return scanPairingRequest(row)
}

// ListPendingPairingRequests returns all pending, non-expired pairing requests, newest first.
func (d *DB) ListPendingPairingRequests() ([]PairingRequest, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := d.sql.Query(
		`SELECT id, display_code, COALESCE(poll_id,''), COALESCE(poll_verifier,X''),
		        public_key, key_id, source_ip, status, created_at, expires_at,
		        resolved_at, COALESCE(resolved_tenant_id,''), COALESCE(enrollment_code_id,'')
		 FROM pairing_requests
		 WHERE status='pending' AND expires_at > ?
		 ORDER BY created_at DESC`, now)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "listing pairing requests", err)
	}
	defer rows.Close()
	var out []PairingRequest
	for rows.Next() {
		pr, err := scanPairingRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

// CountRecentPairingRequestsByIP returns how many pending requests were submitted
// from sourceIP in the last window duration (rate-limit helper).
func (d *DB) CountRecentPairingRequestsByIP(sourceIP string, since time.Time) (int, error) {
	var n int
	err := d.sql.QueryRow(
		`SELECT COUNT(*) FROM pairing_requests WHERE source_ip=? AND created_at > ? AND status='pending'`,
		sourceIP, since.UTC().Format(time.RFC3339Nano)).Scan(&n)
	if err != nil {
		return 0, apperr.E(apperr.CodeStoreFault, "counting pairing requests", err)
	}
	return n, nil
}

type pairingScanner interface {
	Scan(dest ...any) error
}

func scanPairingRequest(row pairingScanner) (PairingRequest, error) {
	var pr PairingRequest
	var createdStr, expiresStr string
	var resolvedStr sql.NullString
	if err := row.Scan(&pr.ID, &pr.DisplayCode, &pr.PollID, &pr.PollVerifier,
		&pr.PublicKey, &pr.KeyID, &pr.SourceIP,
		&pr.Status, &createdStr, &expiresStr, &resolvedStr, &pr.ResolvedTenantID, &pr.EnrollmentCodeID); err != nil {
		if err == sql.ErrNoRows {
			return PairingRequest{}, apperr.E(apperr.CodeEnrollAuth, "pairing request not found", nil)
		}
		return PairingRequest{}, apperr.E(apperr.CodeStoreFault, "scanning pairing request", err)
	}
	var err error
	pr.CreatedAt, err = time.Parse(time.RFC3339Nano, createdStr)
	if err != nil {
		return PairingRequest{}, apperr.E(apperr.CodeStoreFault, "corrupt pairing request created_at timestamp", err)
	}
	pr.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresStr)
	if err != nil {
		return PairingRequest{}, apperr.E(apperr.CodeStoreFault, "corrupt pairing request expires_at timestamp", err)
	}
	if resolvedStr.Valid && resolvedStr.String != "" {
		t, rerr := time.Parse(time.RFC3339Nano, resolvedStr.String)
		if rerr != nil {
			return PairingRequest{}, apperr.E(apperr.CodeStoreFault, "corrupt pairing request resolved_at timestamp", rerr)
		}
		pr.ResolvedAt = &t
	}
	return pr, nil
}

// CountPendingPairingRequests returns the number of non-expired pending pairing
// requests relay-wide for global cap enforcement. Expired-but-not-yet-pruned
// rows are excluded so they cannot block new requests.
func (d *DB) CountPendingPairingRequests() (int, error) {
	var n int
	if err := d.sql.QueryRow(
		`SELECT COUNT(*) FROM pairing_requests WHERE status='pending' AND expires_at > ?`,
		time.Now().UTC().Format(time.RFC3339Nano)).Scan(&n); err != nil {
		return 0, apperr.E(apperr.CodeStoreFault, "counting pending pairing requests", err)
	}
	return n, nil
}

// SupersedePendingPairingRequest marks any existing pending pairing request
// from keyID as expired, so a publisher never holds two valid display codes
// simultaneously. Called before creating a new request.
func (d *DB) SupersedePendingPairingRequest(keyID string, now time.Time) error {
	_, err := d.sql.Exec(
		`UPDATE pairing_requests SET status='expired', resolved_at=?
		 WHERE key_id=? AND status='pending'`,
		now.UTC().Format(time.RFC3339Nano), keyID)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "superseding prior pairing request", err)
	}
	return nil
}

// PrunePairingRequests durably expires pending requests past their TTL and
// deletes old resolved requests. It returns (marked, deleted, error).
// resolvedRetention is how long to keep resolved rows before pruning (e.g. 24h).
func (d *DB) PrunePairingRequests(now time.Time, resolvedRetention time.Duration) (int64, int64, error) {
	nowStr := now.UTC().Format(time.RFC3339Nano)
	cutoff := now.UTC().Add(-resolvedRetention).Format(time.RFC3339Nano)
	res, err := d.sql.Exec(
		`UPDATE pairing_requests SET status='expired', resolved_at=?
		 WHERE status='pending' AND expires_at <= ?`,
		nowStr, nowStr)
	if err != nil {
		return 0, 0, apperr.E(apperr.CodeStoreFault, "expiring pairing requests", err)
	}
	marked, _ := res.RowsAffected()
	res2, err := d.sql.Exec(
		`DELETE FROM pairing_requests
		 WHERE status IN ('approved','denied','expired') AND resolved_at < ?`,
		cutoff)
	if err != nil {
		return marked, 0, apperr.E(apperr.CodeStoreFault, "pruning pairing requests", err)
	}
	deleted, _ := res2.RowsAffected()
	return marked, deleted, nil
}

// TerminalLeaseEphemeraRetention is the retention window before expired or
// revoked visitor_sessions and access_tokens attached to terminal leases
// (CLOSED, EXPIRED, REVOKED) are pruned.
//
// Security invariant (indefinite lease tombstones): terminal rows in the
// `leases` table itself are NEVER deleted. Each lease tombstone is ~200 bytes
// (~20 MB per 100,000 terminal leases) and is required indefinitely by the
// backup/restore rollback guard (status, generation, token_generation) and
// ownership fences to prevent authority resurrection. Only bulky ephemeral
// visitor_sessions and access_tokens referencing terminal leases are pruned.
const TerminalLeaseEphemeraRetention = 30 * 24 * time.Hour

// PruneTerminalLeaseEphemera deletes expired/revoked visitor_sessions and
// access_tokens belonging to terminal leases older than retention, without ever
// deleting the terminal lease tombstone rows themselves.
func (d *DB) PruneTerminalLeaseEphemera(now time.Time, retention time.Duration) (int64, error) {
	cutoff := now.UTC().Add(-retention).Format(time.RFC3339Nano)
	res1, err := d.sql.Exec(
		`DELETE FROM visitor_sessions
		 WHERE lease_id IN (SELECT id FROM leases WHERE status IN ('CLOSED','EXPIRED','REVOKED'))
		   AND (absolute_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?))`,
		cutoff, cutoff)
	if err != nil {
		return 0, apperr.E(apperr.CodeStoreFault, "pruning terminal lease visitor sessions", err)
	}
	n1, _ := res1.RowsAffected()
	res2, err := d.sql.Exec(
		`DELETE FROM access_tokens
		 WHERE lease_id IN (SELECT id FROM leases WHERE status IN ('CLOSED','EXPIRED','REVOKED'))
		   AND ((expires_at IS NOT NULL AND expires_at < ?) OR (revoked_at IS NOT NULL AND revoked_at < ?))`,
		cutoff, cutoff)
	if err != nil {
		return n1, apperr.E(apperr.CodeStoreFault, "pruning terminal lease access tokens", err)
	}
	n2, _ := res2.RowsAffected()
	return n1 + n2, nil
}
