package authz

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authz.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// applySchema creates the schemaV8 tables for the test. It mirrors the
// migration bodies without running the whole relay schema.
func applySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, stmt := range []string{
		`CREATE TABLE authz_clients (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
		   redirect_uris TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, revoked_at TEXT,
		   tenant_id TEXT NOT NULL DEFAULT '', route_id TEXT NOT NULL DEFAULT '',
		   client_secret_hash TEXT NOT NULL DEFAULT '', client_mode TEXT NOT NULL DEFAULT 'public',
		   refresh_policy TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE authz_grants (client_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
		   route_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
		   updated_at TEXT NOT NULL, pairing_hash TEXT NOT NULL DEFAULT '',
		   pairing_issued_at TEXT NOT NULL DEFAULT '',
		   pairing_expires_at TEXT NOT NULL DEFAULT '',
		   pairing_consumed_at TEXT, consented_at TEXT,
		   skip_pairing INTEGER NOT NULL DEFAULT 0,
		   auth_method TEXT NOT NULL DEFAULT 'legacy',
		   trust_policy_id TEXT NOT NULL DEFAULT '',
		   owner_issuer TEXT NOT NULL DEFAULT '',
		   owner_subject TEXT NOT NULL DEFAULT '',
		   PRIMARY KEY (client_id, tenant_id, route_id))`,
		`CREATE TABLE authz_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL,
		   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
		   challenge TEXT NOT NULL, challenge_method TEXT NOT NULL,
		   scope TEXT NOT NULL DEFAULT 'mcp:tools offline_access',
		   expires_at TEXT NOT NULL, consumed_at TEXT)`,
		`CREATE TABLE authz_consent (challenge TEXT PRIMARY KEY, client_id TEXT NOT NULL,
		   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
		   code_challenge TEXT NOT NULL, state TEXT NOT NULL DEFAULT '',
		   resource TEXT NOT NULL DEFAULT '',
		   scope TEXT NOT NULL DEFAULT 'mcp:tools offline_access',
		   expires_at TEXT NOT NULL, consumed_at TEXT)`,
		`CREATE TABLE authz_issuer_key (id INTEGER PRIMARY KEY CHECK (id = 1),
			   kid TEXT NOT NULL, priv BLOB NOT NULL, created_at TEXT NOT NULL)`,
		`CREATE TABLE authz_revocations (jti TEXT PRIMARY KEY, client_id TEXT NOT NULL,
			   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, revoked_at TEXT NOT NULL)`,
		`CREATE TABLE authz_audit (id INTEGER PRIMARY KEY AUTOINCREMENT,
			   time TEXT NOT NULL, actor TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',
			   route_id TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL DEFAULT '',
			   action TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE authz_trust_policies (id TEXT PRIMARY KEY,
			   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, owner_key_id TEXT NOT NULL,
			   kind TEXT NOT NULL, redirect_uris_json TEXT NOT NULL,
			   enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, revoked_at TEXT)`,
		`CREATE TABLE authz_opaque_refresh (token_hash TEXT PRIMARY KEY,
			   client_id TEXT NOT NULL, tenant_id TEXT NOT NULL, route_id TEXT NOT NULL,
			   scope TEXT NOT NULL DEFAULT '',
			   expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
			   last_used_at TEXT NOT NULL, revoked_at TEXT)`,
		`CREATE TABLE authz_visitor_policies (
			   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, mode TEXT NOT NULL,
			   issuer TEXT NOT NULL, client_id TEXT NOT NULL, client_secret TEXT NOT NULL DEFAULT '',
			   allowed_subjects_json TEXT NOT NULL DEFAULT '[]', client_policy TEXT NOT NULL DEFAULT '',
			   enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
			   revoked_at TEXT, PRIMARY KEY (tenant_id, route_id))`,
		`CREATE TABLE authz_oidc_tx (
			   state TEXT PRIMARY KEY, nonce TEXT NOT NULL, pkce_verifier TEXT NOT NULL,
			   client_id TEXT NOT NULL, tenant_id TEXT NOT NULL, route_id TEXT NOT NULL,
			   redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, client_state TEXT NOT NULL DEFAULT '',
			   resource TEXT NOT NULL, scope TEXT NOT NULL, trust_policy_id TEXT NOT NULL DEFAULT '',
			   expires_at TEXT NOT NULL, consumed_at TEXT)`,
		`CREATE TABLE mcp_host_observations (
			   id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, route_id TEXT NOT NULL,
			   canonical_url TEXT NOT NULL, client_id TEXT NOT NULL DEFAULT '',
			   client_kind TEXT NOT NULL DEFAULT 'generic', protocol_version TEXT NOT NULL DEFAULT '',
			   publication_generation INTEGER NOT NULL DEFAULT 0, stage TEXT NOT NULL,
			   result_category TEXT NOT NULL DEFAULT 'ok', is_synthetic INTEGER NOT NULL DEFAULT 0,
			   observed_at TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
}

func TestSQLStoreGrantLifecycle(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)

	if err := s.RegisterClient(Client{ID: "cli_1", Name: "c", RedirectURIs: []string{"https://x/cb"}, Tenant: "t", Route: "r"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.RegisterClient(Client{Tenant: "t", Route: "r", ID: "cli_1"}); err == nil {
		t.Fatal("duplicate client accepted")
	}
	got, err := s.GetClient("cli_1")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://x/cb" {
		t.Fatalf("redirect uris not persisted: %+v", got.RedirectURIs)
	}

	if err := s.CreateGrant(Grant{ClientID: "cli_1", Tenant: "t", Route: "r", Status: GrantPending}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := s.CreateGrant(Grant{ClientID: "cli_1", Tenant: "t", Route: "r", Status: GrantPending}); err == nil {
		t.Fatal("duplicate grant accepted")
	}
	if err := s.ApproveGrant("cli_1", "t", "r"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	g, err := s.GetGrant("cli_1", "t", "r")
	if err != nil || g.Status != GrantActive {
		t.Fatalf("grant status: %+v err=%v", g, err)
	}
	if err := s.RevokeGrant("cli_1", "t", "r"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	g, _ = s.GetGrant("cli_1", "t", "r")
	if g.Status != GrantRevoked {
		t.Fatalf("status=%q", g.Status)
	}
}

func TestSQLStoreApproveCreatesMissingGrant(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	if err := s.ApproveGrant("cli_x", "t", "r"); err != nil {
		t.Fatalf("approve without prior grant: %v", err)
	}
	g, err := s.GetGrant("cli_x", "t", "r")
	if err != nil || g.Status != GrantActive {
		t.Fatalf("grant: %+v err=%v", g, err)
	}
}

func TestSQLStoreCodeSingleUse(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	if err := s.CreateCode(Code{
		Code: "c1", ClientID: "cli_1", Tenant: "t", Route: "r",
		RedirectURI: "https://x/cb", Challenge: "ch", ChallengeMethod: "S256",
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.ConsumeCode("c1", "cli_1", "t", "r"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.ConsumeCode("c1", "cli_1", "t", "r"); err == nil {
		t.Fatal("code replayed")
	}
	if err := s.CreateCode(Code{
		Code: "c2", ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("create2: %v", err)
	}
	if _, err := s.ConsumeCode("c2", "", "", ""); err == nil {
		t.Fatal("expired code accepted")
	}
}

func TestSQLStoreIssuerPersistence(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)

	issuer, err := s.LoadIssuer()
	if err != nil {
		t.Fatalf("first load creates: %v", err)
	}
	tok, err := issuer.Mint(TokenClaims{
		Issuer: "iss", Subject: "sub", Audience: "aud", Tenant: "t", Route: "r",
		Expiry: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// A fresh store over the same DB must verify the token with the same key.
	again, err := NewSQLStore(db).LoadIssuer()
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if _, err := again.Verify(tok); err != nil {
		t.Fatalf("issuer key not durable: %v", err)
	}

	rotated, err := s.RotateIssuer()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.KID() == issuer.KID() {
		t.Fatal("rotation did not change the key id")
	}
	if _, err := rotated.Verify(tok); err == nil {
		t.Fatal("old-key token accepted after rotation")
	}
}

func TestSQLStoreClientRevocation(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	if err := s.RegisterClient(Client{ID: "cli_1", RedirectURIs: []string{"https://x/cb"}, Tenant: "t", Route: "r"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.RevokeClient("cli_1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	c, err := s.GetClient("cli_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.RevokedAt == nil {
		t.Fatal("revoked_at not persisted")
	}
	// The id stays reserved.
	if err := s.RegisterClient(Client{Tenant: "t", Route: "r", ID: "cli_1"}); err == nil {
		t.Fatal("revoked client id re-registered")
	}
}

// TestRotateIssuerCreatesMissingIssuer: rotation on an EMPTY issuer table
// must persist the new key (INSERT path), not silently update zero rows and
// report success while leaving nothing stored. Pre-fix RotateIssuer only ran
// UPDATE ... WHERE id=1, which affects 0 rows without error when the row is
// absent — the CLI then reports success for a key that was never saved.
func TestRotateIssuerCreatesMissingIssuer(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)

	rotated, err := s.RotateIssuer() // empty table
	if err != nil {
		t.Fatalf("rotate on empty table: %v", err)
	}
	// Reopen a fresh store over the same DB; the returned kid must match
	// what was actually persisted, and a token from the returned issuer
	// must verify against the reopened issuer.
	reopened, err := NewSQLStore(db).LoadIssuer()
	if err != nil {
		t.Fatalf("load after rotate: %v", err)
	}
	if reopened.KID() != rotated.KID() {
		t.Fatalf("persisted kid %q != returned kid %q — rotation not saved", reopened.KID(), rotated.KID())
	}
	tok, err := rotated.Mint(TokenClaims{Issuer: "iss", Subject: "sub", Audience: "aud",
		Tenant: "t", Route: "r", Expiry: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := reopened.Verify(tok); err != nil {
		t.Fatalf("reopened issuer cannot verify token from returned issuer: %v", err)
	}
}

func TestSQLTryRegisterEvictsOldestUnusedAndPreservesAuthority(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	now := time.Now().UTC()
	for i := 0; i < MaxClientsPerRoute; i++ {
		id := fmt.Sprintf("client-%03d", i)
		if err := s.RegisterClient(Client{ID: id, CreatedAt: now.Add(time.Duration(i) * time.Second),
			Tenant: "tenant", Route: "route"}); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			if _, err := db.Exec(`UPDATE authz_clients SET revoked_at=? WHERE id=?`, now.Format(time.RFC3339Nano), id); err != nil {
				t.Fatal(err)
			}
		}
		if i == 0 || i == 2 {
			status := GrantActive
			if i == 2 {
				status = GrantRevoked
			}
			if err := s.CreateGrant(Grant{ClientID: id, Tenant: "tenant", Route: "route",
				Status: status, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.TryRegisterClient(Client{ID: "replacement", CreatedAt: now, Tenant: "tenant", Route: "route"}); err != nil {
		t.Fatalf("registration at full route quota: %v", err)
	}
	for _, id := range []string{"client-000", "client-001", "client-002", "replacement"} {
		if _, err := s.GetClient(id); err != nil {
			t.Fatalf("protected/new identity %s missing: %v", id, err)
		}
	}
	if _, err := s.GetClient("client-003"); err == nil {
		t.Fatal("oldest unapproved client was not evicted")
	}
	if n, err := s.CountClients("tenant", "route"); err != nil || n != MaxClientsPerRoute {
		t.Fatalf("client count=%d err=%v, want bound %d", n, err, MaxClientsPerRoute)
	}
}

func TestSQLTryRegisterQuotaFailsWhenAllIdentitiesCarryAuthority(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	now := time.Now().UTC()
	for i := 0; i < MaxClientsPerRoute; i++ {
		id := fmt.Sprintf("client-%03d", i)
		if err := s.RegisterClient(Client{ID: id, CreatedAt: now.Add(time.Duration(i) * time.Second),
			Tenant: "tenant", Route: "route"}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateGrant(Grant{ClientID: id, Tenant: "tenant", Route: "route",
			Status: GrantActive, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.TryRegisterClient(Client{ID: "replacement", CreatedAt: now, Tenant: "tenant", Route: "route"}); err != ErrClientQuota {
		t.Fatalf("full route without an evictable client err=%v, want ErrClientQuota", err)
	}
	if n, err := s.CountClients("tenant", "route"); err != nil || n != MaxClientsPerRoute {
		t.Fatalf("client count=%d err=%v after denied registration, want unchanged bound %d", n, err, MaxClientsPerRoute)
	}
}

func TestSQLTryRegisterConcurrentEvictionKeepsRouteBound(t *testing.T) {
	db := openTestDB(t)
	db.SetMaxOpenConns(1) // matches the relay store's serialized SQLite writer
	applySchema(t, db)
	s := NewSQLStore(db)
	const attempts = MaxClientsPerRoute + 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []error
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := s.TryRegisterClient(Client{ID: fmt.Sprintf("concurrent-%03d", i),
				CreatedAt: time.Now(), Tenant: "tenant", Route: "route"})
			if err != nil {
				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(failures) != 0 {
		t.Fatalf("safe LRU registration failures: %v", failures)
	}
	if n, err := s.CountClients("tenant", "route"); err != nil || n != MaxClientsPerRoute {
		t.Fatalf("concurrent client count=%d err=%v, want bound %d", n, err, MaxClientsPerRoute)
	}
}
