// Package store owns durable relay metadata in SQLite (WAL): tenants, agent
// keys, leases, access token verifiers, visitor sessions, enrollment grants,
// and audit events (spec section 5). It stores only verifiers, never raw
// secrets. In-memory sockets are never persisted (F11).
package store

import (
	"database/sql"
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
const currentSchema = 3

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

func Open(path string) (*DB, error) {
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
