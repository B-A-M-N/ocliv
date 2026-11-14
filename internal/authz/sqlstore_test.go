package authz

import (
	"database/sql"
	"path/filepath"
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
		   tenant_id TEXT NOT NULL DEFAULT '', route_id TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE authz_grants (client_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
		   route_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
		   updated_at TEXT NOT NULL, pairing_hash TEXT NOT NULL DEFAULT '',
		   pairing_issued_at TEXT NOT NULL DEFAULT '',
		   pairing_expires_at TEXT NOT NULL DEFAULT '',
		   pairing_consumed_at TEXT, consented_at TEXT,
		   PRIMARY KEY (client_id, tenant_id, route_id))`,
		`CREATE TABLE authz_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL,
		   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
		   challenge TEXT NOT NULL, challenge_method TEXT NOT NULL,
		   expires_at TEXT NOT NULL, consumed_at TEXT)`,
		`CREATE TABLE authz_consent (challenge TEXT PRIMARY KEY, client_id TEXT NOT NULL,
		   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
		   code_challenge TEXT NOT NULL, state TEXT NOT NULL DEFAULT '',
		   resource TEXT NOT NULL DEFAULT '',
		   expires_at TEXT NOT NULL, consumed_at TEXT)`,
		`CREATE TABLE authz_issuer_key (id INTEGER PRIMARY KEY CHECK (id = 1),
			   kid TEXT NOT NULL, priv BLOB NOT NULL, created_at TEXT NOT NULL)`,
		`CREATE TABLE authz_revocations (jti TEXT PRIMARY KEY, client_id TEXT NOT NULL,
			   tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, revoked_at TEXT NOT NULL)`,
		`CREATE TABLE authz_audit (id INTEGER PRIMARY KEY AUTOINCREMENT,
			   time TEXT NOT NULL, actor TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',
			   route_id TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL DEFAULT '',
			   action TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')`,
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
