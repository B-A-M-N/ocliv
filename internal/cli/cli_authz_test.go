package cli

import (
	"bytes"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/store"
)

// The managed authorization mode must map to a real relay access mode and a
// real ingress profile; a typo here would publish an unenforceable route.
func TestMCPManagedAccessMode(t *testing.T) {
	if got := mcpAccessMode("ocliv-managed"); got != "mcp_managed_oauth" {
		t.Fatalf("mcpAccessMode(ocliv-managed) = %q, want mcp_managed_oauth", got)
	}
	if got := mcpAuthProfiles["ocliv-managed"]; got != "managed-oauth" {
		t.Fatalf("mcpAuthProfiles[ocliv-managed] = %q, want managed-oauth", got)
	}
	// The existing modes must be unchanged.
	if got := mcpAccessMode("upstream-oauth"); got != "mcp_upstream_oauth" {
		t.Fatalf("mcpAccessMode(upstream-oauth) = %q, want mcp_upstream_oauth", got)
	}
	if got := mcpAccessMode("fixture-anonymous"); got != "mcp_anonymous_fixture" {
		t.Fatalf("mcpAccessMode(fixture-anonymous) = %q, want mcp_anonymous_fixture", got)
	}
}

// A managed publication is a first-class publish: it must parse, and it must
// never require an upstream OAuth discovery file.
func TestParseMCPPublishManagedAccepted(t *testing.T) {
	cfg, code := parseMCPPublish([]string{
		"--local=http://127.0.0.1:8765/mcp", "--auth=ocliv-managed",
	}, false)
	if code != 0 {
		t.Fatalf("managed publish rejected: code %d", code)
	}
	if cfg.auth != "ocliv-managed" {
		t.Fatalf("cfg.auth = %q, want ocliv-managed", cfg.auth)
	}
}

// Managed mode must not inherit the upstream-only flags; they are rejected
// rather than silently ignored so the operator learns the mode boundary.
func TestParseMCPPublishManagedRejectsUpstreamFlags(t *testing.T) {
	for _, argv := range [][]string{
		{"--local=http://127.0.0.1:1/mcp", "--auth=ocliv-managed", "--strict-discovery"},
		{"--local=http://127.0.0.1:1/mcp", "--auth=ocliv-managed", "--dev-allow-unverified-discovery"},
		{"--local=http://127.0.0.1:1/mcp", "--auth=ocliv-managed", "--resource-file=/tmp/x"},
	} {
		if _, code := parseMCPPublish(argv, false); code == 0 {
			t.Errorf("argv %q accepted, want rejection", argv)
		}
	}
}

// The operator authz command set is closed: unknown subcommands fail closed.
// Inventory commands are READ-ONLY: on an empty data dir (no database) they
// must fail with a clear "not a relay database" message rather than create
// one (rereview P2). Mutating commands still create/verify their store:
// rotate-key on an empty dir is a legitimate success (it creates the
// issuer). A mutating command with a missing client and an unknown
// subcommand must fail.
func TestAuthzCommandSetClosed(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"pending", "list"} {
		var stderr bytes.Buffer
		r, w, _ := os.Pipe()
		old := os.Stderr
		os.Stderr = w
		code := cmdAuthz([]string{sub, "--data", dir})
		w.Close()
		os.Stderr = old
		_, _ = io.Copy(&stderr, r)
		if code == 0 {
			t.Errorf("authz %s on a nonexistent database returned 0, want a read-only refusal", sub)
		}
		if !strings.Contains(stderr.String(), "not an ocliv relay database") {
			t.Errorf("authz %s refusal should name the cause, got: %s", sub, stderr.String())
		}
	}
	if code := cmdAuthz([]string{"rotate-key", "--data", dir}); code != 0 {
		t.Errorf("authz rotate-key on an empty data dir returned %d, want 0", code)
	}
	if code := cmdAuthz([]string{"exec", "--data", dir}); code == 0 {
		t.Error("authz exec accepted, want rejection")
	}
	if code := cmdAuthz(nil); code == 0 {
		t.Error("authz with no subcommand returned 0, want failure")
	}
}

// The ingress profile sent to the relay is the relay-facing name. For the
// managed mode these differ, and sending the CLI name made route creation
// fail closed with 400 "unknown ingress profile" on a live publish.
func TestMCPIngressProfileMapping(t *testing.T) {
	cases := map[string]string{
		"upstream-oauth":    "upstream-oauth",
		"fixture-anonymous": "fixture-anonymous",
		"ocliv-managed":     "managed-oauth",
	}
	for auth, want := range cases {
		if got := mcpIngressProfile(auth); got != want {
			t.Errorf("mcpIngressProfile(%q) = %q, want %q", auth, got, want)
		}
	}
}

// approve/revoke require --client AND explicit --tenant/--route. An
// ambiguous approval must never silently cover several grants.
func TestAuthzClientRequired(t *testing.T) {
	dir := t.TempDir()
	if code := cmdAuthzApprove([]string{"--data", dir}); code == 0 {
		t.Error("approve without --client returned 0, want failure")
	}
	if code := cmdAuthzRevoke([]string{"--data", dir}); code == 0 {
		t.Error("revoke without --client returned 0, want failure")
	}
	if code := cmdAuthzApprove([]string{"--data", dir, "--client", "c1"}); code == 0 {
		t.Error("approve without --tenant/--route returned 0, want failure")
	}
	if code := cmdAuthzRevoke([]string{"--data", dir, "--client", "c1"}); code == 0 {
		t.Error("revoke without --tenant/--route returned 0, want failure")
	}
}

func TestAuthzRejectsUnknownFlags(t *testing.T) {
	dir := t.TempDir()
	for _, argv := range [][]string{
		{"rotate-key", "--dat", dir},              // misspelled
		{"list", "--data", dir, "--tenantx", "t"}, // misspelled filter
		{"list", "--data", dir, "positional"},     // positional not allowed
	} {
		if code := cmdAuthz(argv); code != apperr.ExitCLIValidation {
			t.Errorf("authz %v: got %d, want CLI-validation rejection", argv, code)
		}
	}
}

func TestAuthzRejectsMissingFlagValues(t *testing.T) {
	dir := t.TempDir()
	// --data with no following value
	if code := cmdAuthz([]string{"list", "--data"}); code != apperr.ExitCLIValidation {
		t.Errorf("authz list --data (missing value): got %d, want validation", code)
	}
	// --client with no value on approve
	if code := cmdAuthz([]string{"approve", "--data", dir, "--client"}); code != apperr.ExitCLIValidation {
		t.Errorf("authz approve --client (missing value): got %d, want validation", code)
	}
	// --tenant with no value on revoke
	if code := cmdAuthz([]string{"revoke", "--data", dir, "--client", "c", "--tenant"}); code != apperr.ExitCLIValidation {
		t.Errorf("authz revoke --tenant (missing value): got %d, want validation", code)
	}
}

func TestAuthzRejectsConflictingFlags(t *testing.T) {
	dir := t.TempDir()
	if code := cmdAuthz([]string{"list", "--data", dir, "--data", dir}); code != apperr.ExitCLIValidation {
		t.Errorf("duplicate --data accepted: got %d, want validation", code)
	}
	if code := cmdAuthz([]string{"list", "--data", dir, "--data=" + dir}); code != apperr.ExitCLIValidation {
		t.Errorf("duplicate --data (=/form) accepted: got %d, want validation", code)
	}
}

func TestAuthzInvalidFlagsNeverCreateDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ocliv.db")
	// Each invalid invocation must fail validation WITHOUT creating a DB.
	for _, argv := range [][]string{
		{"rotate-key", "--dat", dir},
		{"list", "--data", dir, "--bogus", "x"},
		{"approve", "--data", dir, "--client"},
	} {
		cmdAuthz(argv)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("invalid flags created/kept a database at %s", dbPath)
	}
}

func TestAuthzRotateKeyTargetsExplicitDatabase(t *testing.T) {
	// rotate-key with an explicit --data must target THAT db, not a default.
	a := t.TempDir()
	b := t.TempDir()
	if code := cmdAuthz([]string{"rotate-key", "--data", a}); code != 0 {
		t.Fatalf("rotate-key explicit --data: %d", code)
	}
	if _, err := os.Stat(filepath.Join(a, "ocliv.db")); err != nil {
		t.Fatalf("rotate-key did not create the explicit --data db: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b, "ocliv.db")); !os.IsNotExist(err) {
		t.Fatalf("rotate-key created an unintended db in %s", b)
	}
	// And a misspelled flag must NOT fall back to the default dir.
	c := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(c); err != nil {
		t.Fatal(err)
	}
	if code := cmdAuthz([]string{"rotate-key", "--dat", a}); code != apperr.ExitCLIValidation {
		t.Errorf("misspelled --dat: got %d, want validation", code)
	}
	if _, err := os.Stat(filepath.Join(c, "ocliv-relay-data", "ocliv.db")); !os.IsNotExist(err) {
		t.Fatalf("misspelled --dat fell back to the default database dir")
	}
}

// TestAuthzListDoesNotCreateDatabase: `authz list` on a data dir with NO
// database must fail (read-only open), and must NOT create ocliv.db as a
// side effect. Pre-fix, authzOpen->store.Open would create and migrate one.
func TestAuthzListDoesNotCreateDatabase(t *testing.T) {
	dir := t.TempDir()
	if code := cmdAuthz([]string{"list", "--data", dir}); code == 0 {
		t.Fatal("authz list on a nonexistent db unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); !os.IsNotExist(err) {
		t.Fatalf("authz list created a database in %s", dir)
	}
}

// TestAuthzPendingDoesNotMigrateDatabase: a pre-V8-shaped database read by
// `authz pending` must remain at its recorded schema version afterwards.
func TestAuthzPendingDoesNotMigrateDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ocliv.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`DELETE FROM schema_version WHERE v > 7`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if code := cmdAuthz([]string{"pending", "--data", dir}); code != 0 {
		t.Fatalf("pending on a v7 db should succeed read-only, got %d", code)
	}
	ro, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var v int
	if err := ro.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != 7 {
		t.Fatalf("pending migrated the database: v=%d err=%v", v, err)
	}
}

// TestAuthzReadOnlyDoesNotChangeDatabaseBytes: byte-for-byte comparison of
// the database file around an `authz list` call (mtime aside, content must
// not change).
func TestAuthzReadOnlyDoesNotChangeDatabaseBytes(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := "2026-01-01T00:00:00Z"
	if _, err := db.SQL().Exec(`INSERT INTO tenants(id,status,created_at) VALUES('t1','active',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO authz_grants(client_id,tenant_id,route_id,status,created_at,updated_at) VALUES('cli','t1','r','active',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	if code := cmdAuthz([]string{"list", "--data", dir}); code != 0 {
		t.Fatalf("authz list on a valid db: %d", code)
	}
	after, err := os.ReadFile(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("authz list changed the database bytes")
	}
}

func TestAuthzBareJSONFlagAndNoSwallow(t *testing.T) {
	spec := authzSpecFor("json")
	f, err := parseAuthzFlags([]string{"--data", "/tmp/d", "--json"}, spec)
	if err != nil {
		t.Fatalf("expected bare --json to parse, got error: %v", err)
	}
	if !f.asJSON || f.dataDir != "/tmp/d" {
		t.Fatalf("unexpected parsed flags: %+v", f)
	}
	if _, err := parseAuthzFlags([]string{"--data", "--json"}, spec); err == nil {
		t.Fatal("expected --data --json without value to fail rather than swallowing --json")
	}
	if _, err := parseAuthzFlags([]string{"--json=true"}, spec); err == nil {
		t.Fatal("expected --json=true to be rejected")
	}
}
