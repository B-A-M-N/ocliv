package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// The relay database holds credential verifiers, so Open must leave the
// data directory owner-only and the database (plus SQLite sidecars)
// owner-read/write even when created under a permissive umask or
// pre-existing permissive paths (P1-3). MkdirAll alone repairs neither.
func TestOpenEnforcesPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	// Simulate a pre-existing permissive layout (umask 022 world).
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ocliv.db")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open with permissive layout: %v", err)
	}
	defer db.Close()
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("data dir perm = %v err = %v, want owner-only", fi.Mode(), err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("db file %s perm = %v err = %v, want owner-only", p, fi.Mode(), err)
		}
	}
}

// A migration that fails partway must leave prior rows and the recorded
// schema version untouched: body and version stamp commit atomically,
// so a crash between statements can never half-apply a version (P1-2).
func TestApplyMigrationRollsBackPartialFailure(t *testing.T) {
	path := t.TempDir() + "/mig.db"
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, stmt := range []string{
		`CREATE TABLE schema_version (v INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE mcp_routes (
		   route_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL,
		   external_host TEXT NOT NULL, profile TEXT NOT NULL,
		   target_path TEXT NOT NULL DEFAULT '/mcp', created_at TEXT NOT NULL)`,
		`INSERT INTO schema_version(v, applied_at) VALUES(2, 't')`,
		`INSERT INTO mcp_routes(route_id, lease_id, external_host, profile, created_at) VALUES('r-a','lse','h','p','t')`,
		`INSERT INTO mcp_routes(route_id, lease_id, external_host, profile, created_at) VALUES('r-b','lse','h','p','t')`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	// First statement valid, second invalid: nothing may persist.
	err = applyMigration(raw, 3, "DELETE FROM mcp_routes WHERE route_id='r-a'; NOT VALID SQL AT ALL;")
	if err == nil {
		t.Fatal("partial-failure migration accepted")
	}
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM mcp_routes`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows after rollback: n=%d err=%v, want 2", n, err)
	}
	var v int
	if err := raw.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != 2 {
		t.Fatalf("version after rollback: v=%d err=%v, want 2", v, err)
	}
}

// One logical publication — one (tenant, owner, host, profile, name)
// mapping — must have exactly one row (P1-4, P1-A). The unique
// constraint makes concurrent check-then-act inserts converge instead
// of duplicating, including across replacement leases.
func TestMCPRouteMappingUnique(t *testing.T) {
	db, err := Open(t.TempDir() + "/ocliv.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mklease := func(id, label, hostname string) {
		t.Helper()
		if _, err := db.SQL().Exec(
			`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?)`,
			id, "t1", "k1", hostname, label, 3000, "mcp_upstream_oauth", 1, "ACTIVE", utcNow()); err != nil {
			t.Fatal(err)
		}
	}
	mklease("lse-mcp", "mcp", "mcp.t")
	mklease("lse-mcp2", "mcp", "mcp2.t")
	ins := `INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, target_path, lease_id, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`
	if _, err := db.SQL().Exec(ins, "r1", "t1", "k1", "public.example.org", "upstream-oauth", "mcp", "/mcp", "lse-mcp", utcNow(), utcNow()); err != nil {
		t.Fatalf("first mapping rejected: %v", err)
	}
	// Same logical publication on a replacement lease: still one row.
	if _, err := db.SQL().Exec(ins, "r2", "t1", "k1", "public.example.org", "upstream-oauth", "mcp", "/mcp", "lse-mcp2", utcNow(), utcNow()); err == nil {
		t.Fatal("duplicate (tenant, owner, host, profile, name) mapping accepted")
	}
	var n int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM mcp_publications WHERE pub_name='mcp'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("mapping rows=%d err=%v, want exactly 1", n, err)
	}
}

// Re-opening a migrated database must be a no-op (restart path), and a
// newer-than-known schema version must fail closed (downgrade refusal).
func TestOpenIdempotentAndDowngradeRefused(t *testing.T) {
	path := t.TempDir() + "/ocliv.db"
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open migrated db: %v", err)
	}
	var v int
	if err := db2.SQL().QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != currentSchema {
		db2.Close()
		t.Fatalf("version after re-open: v=%d err=%v", v, err)
	}
	db2.Close()

	// Downgrade refusal: stamp a newer-than-known version into an
	// already-migrated database; the next Open must fail closed.
	db3, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db3.SQL().Exec(`INSERT INTO schema_version(v, applied_at) VALUES(99, ?)`, utcNow()); err != nil {
		t.Fatal(err)
	}
	db3.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("newer-than-known schema accepted")
	}
}

// A database written before P1-4 may hold duplicate route rows for one
// logical publication (no uniqueness constraint existed). Migration must
// collapse them to the earliest mapping and land the constraint, so a
// later duplicate insert is rejected.
func TestOpenDedupesLegacyRouteDuplicates(t *testing.T) {
	path := t.TempDir() + "/legacy-routes.db"
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE schema_version (v INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE leases (
		   id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_key_id TEXT NOT NULL,
		   hostname TEXT NOT NULL UNIQUE, label TEXT NOT NULL, port INTEGER NOT NULL,
		   access_mode TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
		   token_generation INTEGER NOT NULL DEFAULT 0,
		   status TEXT NOT NULL, expires_at TEXT, reconnect_until TEXT,
		   created_at TEXT NOT NULL)`,
		`CREATE TABLE mcp_routes (
		   route_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES leases(id),
		   external_host TEXT NOT NULL, profile TEXT NOT NULL,
		   target_path TEXT NOT NULL DEFAULT '/mcp', created_at TEXT NOT NULL)`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			raw.Close()
			t.Fatalf("fixture schema: %v", err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO schema_version(v, applied_at) VALUES(1, ?)`, utcNow()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"lse-dup", "t1", "k1", "dup.t", "dup", 3000, "mcp_upstream_oauth", 1, "ACTIVE", utcNow()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	for _, rid := range []string{"r-old", "r-new"} {
		if _, err := raw.Exec(
			`INSERT INTO mcp_routes(route_id, lease_id, external_host, profile, target_path, created_at)
			 VALUES(?,?,?,?,?,?)`,
			rid, "lse-dup", "public.example.org", "upstream-oauth", "/mcp", utcNow()); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy db: %v", err)
	}
	defer db.Close()
	// v4 retires mcp_routes: duplicates collapse to one durable
	// publication keeping the earliest route.
	var kept string
	var n int
	if err := db.SQL().QueryRow(
		`SELECT route_id FROM mcp_publications WHERE lease_id='lse-dup'`).Scan(&kept); err != nil {
		t.Fatalf("no publication survived: %v", err)
	}
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM mcp_publications WHERE lease_id='lse-dup'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("duplicate publications survived: n=%d err=%v", n, err)
	}
	if kept != "r-old" {
		t.Fatalf("kept %q, want earliest r-old", kept)
	}
	var v int
	if err := db.SQL().QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != currentSchema {
		t.Fatalf("schema version after migration: v=%d err=%v", v, err)
	}
}

// A pre-P1-A database holds lease-bound mcp_routes rows. Opening it
// must migrate each live row to a durable publication preserving its
// route_id (stable URL), keyed by (tenant, owner, host, profile,
// label); duplicate natural keys keep the earliest route, orphan rows
// whose lease is gone are dropped, and mcp_routes is retired (P1-A).
func TestOpenMigratesLegacyMCPRoutes(t *testing.T) {
	path := t.TempDir() + "/legacy-routes.db"
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE schema_version (v INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE leases (
		   id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_key_id TEXT NOT NULL,
		   hostname TEXT NOT NULL UNIQUE, label TEXT NOT NULL, port INTEGER NOT NULL,
		   access_mode TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
		   token_generation INTEGER NOT NULL DEFAULT 0,
		   status TEXT NOT NULL, expires_at TEXT, reconnect_until TEXT,
		   created_at TEXT NOT NULL)`,
		`CREATE TABLE mcp_routes (
		   route_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES leases(id),
		   external_host TEXT NOT NULL, profile TEXT NOT NULL,
		   target_path TEXT NOT NULL DEFAULT '/mcp', created_at TEXT NOT NULL)`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			raw.Close()
			t.Fatalf("fixture schema: %v", err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO schema_version(v, applied_at) VALUES(1, ?)`, utcNow()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	mklease := func(id, label, hostname string) {
		t.Helper()
		if _, err := raw.Exec(
			`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?)`,
			id, "t1", "k1", hostname, label, 3000, "mcp_upstream_oauth", 1, "ACTIVE", utcNow()); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	mklease("lse-a", "alpha", "alpha.t")
	// Two live leases share one publication label: the v4 natural key
	// (not the v3 lease key) must collapse them to the earliest route.
	mklease("lse-b1", "beta", "beta1.t")
	mklease("lse-b2", "beta", "beta2.t")
	for _, rr := range [][2]string{
		{"r-keep", "lse-a"}, {"r-dup1", "lse-b1"}, {"r-dup2", "lse-b2"}, {"r-orphan", "lse-gone"},
	} {
		// The orphan row's FK would fail: legacy DBs predate strict
		// enforcement here, so insert it with keys off like old code.
		if _, err := raw.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
			raw.Close()
			t.Fatal(err)
		}
		if _, err := raw.Exec(
			`INSERT INTO mcp_routes(route_id, lease_id, external_host, profile, target_path, created_at)
			 VALUES(?,?,?,?,?,?)`,
			rr[0], rr[1], "public.example.org", "upstream-oauth", "/mcp", utcNow()); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy routes db: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("publications=%d err=%v, want 2 (keep + earliest dup)", n, err)
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id='r-keep'`).Scan(&bound); err != nil || bound != "lse-a" {
		t.Fatalf("r-keep bound to %q err=%v, want lse-a", bound, err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications WHERE route_id IN ('r-dup1','r-dup2')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("dup natural key rows=%d err=%v, want exactly 1", n, err)
	}
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id='r-dup1'`).Scan(&bound); err != nil || bound != "lse-b1" {
		t.Fatalf("dup natural key kept bound to %q err=%v, want earliest lse-b1", bound, err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications WHERE route_id='r-orphan'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("orphan route migrated: n=%d err=%v", n, err)
	}
	var tbl string
	if err := db.SQL().QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_routes'`).Scan(&tbl); err == nil {
		t.Fatalf("legacy mcp_routes table survived migration")
	}
	var v int
	if err := db.SQL().QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != currentSchema {
		t.Fatalf("schema version after migration: v=%d err=%v", v, err)
	}
}

// A pre-P0-4 database may hold usable browser credentials as
// visitor_sessions row ids. Opening it must revoke those sessions
// (table emptied) and record schema version 2, while preserving all
// other rows (P0-4, P2-3).
func TestOpenMigratesLegacySessionBearers(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE schema_version (v INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE leases (
		   id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_key_id TEXT NOT NULL,
		   hostname TEXT NOT NULL UNIQUE, label TEXT NOT NULL, port INTEGER NOT NULL,
		   access_mode TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
		   token_generation INTEGER NOT NULL DEFAULT 0,
		   status TEXT NOT NULL, expires_at TEXT, reconnect_until TEXT,
		   created_at TEXT NOT NULL)`,
		`CREATE TABLE visitor_sessions (
		   id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES leases(id),
		   token_generation INTEGER NOT NULL DEFAULT 0, session_verifier TEXT NOT NULL,
		   created_at TEXT NOT NULL, idle_expires_at TEXT NOT NULL,
		   absolute_expires_at TEXT NOT NULL, revoked_at TEXT)`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			raw.Close()
			t.Fatalf("fixture schema: %v", err)
		}
	}
	if _, err := raw.Exec(
		`INSERT INTO schema_version(v, applied_at) VALUES(1, ?)`, utcNow()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"lse-legacy", "t1", "k1", "demo.t", "demo", 3000, "protected", 1, "ACTIVE", utcNow()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	// Legacy row: id IS a live bearer ("sess-live-bearer").
	if _, err := raw.Exec(
		`INSERT INTO visitor_sessions(id, lease_id, token_generation, session_verifier, created_at, idle_expires_at, absolute_expires_at)
		 VALUES(?,?,?,?,?,?,?)`,
		"sess-live-bearer", "lse-legacy", 0, "verifier-x", utcNow(), utcNow(), utcNow()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy db: %v", err)
	}
	defer db.Close()
	var v int
	if err := db.SQL().QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != currentSchema {
		t.Fatalf("schema version after migration: v=%d err=%v", v, err)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM visitor_sessions`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("legacy sessions not revoked: n=%d err=%v", n, err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM leases WHERE id='lse-legacy'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("migration dropped non-session rows: n=%d err=%v", n, err)
	}
}

// Open applies the schema idempotently, including the management replay
// table that backs one-time mutation nonces (P1-07).
func TestOpenAppliesSchema(t *testing.T) {
	db, err := Open(t.TempDir() + "/ocliv.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{"leases", "audit_events", "mgmt_replay", "access_tokens"} {
		var n int
		if err := db.SQL().QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing: n=%d err=%v", table, n, err)
		}
	}
	db.Audit("agent", "t1", "l1", "mgmt_replay", "denied", "mutation replayed")
	var got int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE category='mgmt_replay'`).Scan(&got); err != nil || got != 1 {
		t.Fatalf("audit row not recorded: n=%d err=%v", got, err)
	}
}

// Orphan credentials must be rejected: a token or session referencing a
// nonexistent lease fails the foreign key instead of lingering as an
// unroutable authorization (qualification P1).
func TestForeignKeysEnforced(t *testing.T) {
	db, err := Open(t.TempDir() + "/ocliv.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.SQL().Exec(
		`INSERT INTO access_tokens(id, lease_id, verifier, scope, created_at, max_uses, uses)
		 VALUES(?,?,?,?,?,?,0)`,
		"tok-orphan", "lse-no-such", "v", "visitor", utcNow(), 1); err == nil {
		t.Fatal("orphan access token accepted")
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO visitor_sessions(id, lease_id, token_generation, session_verifier, created_at, idle_expires_at, absolute_expires_at)
		 VALUES(?,?,?,?,?,?,?)`,
		"sess-orphan", "lse-no-such", 0, "v", utcNow(), utcNow(), utcNow()); err == nil {
		t.Fatal("orphan visitor session accepted")
	}
	// A token with a real parent still inserts.
	if _, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"lse-1", "t1", "k1", "h.t", "h", 3000, "protected", 1, "ACTIVE", utcNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO access_tokens(id, lease_id, verifier, scope, created_at, max_uses, uses)
		 VALUES(?,?,?,?,?,?,0)`,
		"tok-ok", "lse-1", "v", "visitor", utcNow(), 1); err != nil {
		t.Fatalf("token with parent lease rejected: %v", err)
	}
}
