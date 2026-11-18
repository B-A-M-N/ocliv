package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ocliv/internal/apperr"
	"ocliv/internal/authz"
	"ocliv/internal/identity"
	"ocliv/internal/store"
)

func TestConnectGoogleWorkflowIdempotencyAndRevocationFence(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/r-goog/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/r/r-goog/mcp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/r-goog/mcp","authorization_servers":["` + srvURL + `/r/r-goog/oauth"]}`))
		case "/.well-known/oauth-authorization-server/r/r-goog/oauth":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + srvURL + `/r/r-goog/oauth","authorization_endpoint":"` + srvURL + `/r/r-goog/oauth/authorize","token_endpoint":"` + srvURL + `/r/r-goog/oauth/token","code_challenge_methods_supported":["S256"]}`))
		case "/.well-known/google-connected-apps":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"verification_tokens":["tok-test-123"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	seedEnrolledProfileForTest(t, srvURL)
	dataDir := t.TempDir()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[{"route_id":"r-goog","pub_name":"my-mcp","profile":"managed-oauth","url":"` + srvURL + `/r/r-goog/mcp","publication_state":"ACTIVE","desired_enabled":true}]}`), nil
		},
	}

	secretFile := filepath.Join(t.TempDir(), "google-secret.txt")
	cb := "https://oauth-redirect.googleusercontent.com/r/app1"
	args := []string{"google", "my-mcp", "--type", "connected-app", "--redirect", cb, "--data", dataDir, "--secret-out", secretFile, "--approve"}
	if code := cmdConnectWithOps(args, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("connect google exit=%d, want 0", code)
	}
	fi, err := os.Stat(secretFile)
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secret file permissions invalid: err=%v mode=%v", err, fi.Mode().Perm())
	}

	// Verify SQLite client has google_confidential policy.
	db2, err := authzOpen(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	st := authz.NewSQLStore(db2.SQL())
	grants, err := st.ListGrants()
	if err != nil || len(grants) != 1 {
		t.Fatalf("unexpected grants: %+v err=%v", grants, err)
	}
	cliRec, err := st.GetClient(grants[0].ClientID)
	if err != nil || cliRec.RefreshPolicy != "google_confidential" {
		t.Fatalf("unexpected client: %+v err=%v", cliRec, err)
	}

	// Repeat with same inputs is idempotent.
	if code := cmdConnectWithOps(args, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("idempotent connect google exit=%d, want 0", code)
	}

	// Changed callback without --update must be refused.
	badArgs := []string{"google", "my-mcp", "--type", "connected-app", "--redirect", "https://oauth-redirect.googleusercontent.com/r/other", "--data", dataDir}
	if code := cmdConnectWithOps(badArgs, ops, srv.Client()); code == apperr.ExitOK {
		t.Fatal("expected refusal when changing callback without --update")
	}

	// Status & revoke, then ensure reconnection cannot resurrect a revoked binding.
	if code := cmdConnectWithOps([]string{"status", "google", "my-mcp"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("connect status exit=%d, want 0", code)
	}
	if code := cmdConnectWithOps([]string{"revoke", "google", "my-mcp", "--data", dataDir}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("connect revoke exit=%d, want 0", code)
	}
	if code := cmdConnectWithOps(args, ops, srv.Client()); code != apperr.ExitAuth {
		t.Fatalf("expected ExitAuth when reconnecting revoked binding, got %d", code)
	}
}

func TestConnectGoogleUpdateRevokesOldClientAndRequiresExistingDB(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/r-upd/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/r/r-upd/mcp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/r-upd/mcp","authorization_servers":["` + srvURL + `/r/r-upd/oauth"]}`))
		case "/.well-known/oauth-authorization-server/r/r-upd/oauth":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + srvURL + `/r/r-upd/oauth","authorization_endpoint":"` + srvURL + `/r/r-upd/oauth/authorize","token_endpoint":"` + srvURL + `/r/r-upd/oauth/token","code_challenge_methods_supported":["S256"]}`))
		case "/.well-known/google-connected-apps":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"verification_tokens":["tok-upd-1"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	seedEnrolledProfileForTest(t, srvURL)
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[{"route_id":"r-upd","pub_name":"my-mcp","profile":"managed-oauth","url":"` + srvURL + `/r/r-upd/mcp","publication_state":"ACTIVE","desired_enabled":true}]}`), nil
		},
	}

	// Missing DB must fail closed without creating ocliv.db.
	missingDir := filepath.Join(t.TempDir(), "nonexistent-relay-data")
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--redirect", "https://oauth-redirect.googleusercontent.com/r/1", "--data", missingDir}, ops, srv.Client()); code != apperr.ExitCLIValidation {
		t.Fatalf("expected ExitCLIValidation on missing DB, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(missingDir, "ocliv.db")); err == nil {
		t.Fatal("missing DB was silently created")
	}

	// --json without --secret-out must fail validation.
	dataDir := t.TempDir()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--redirect", "https://oauth-redirect.googleusercontent.com/r/1", "--data", dataDir, "--json"}, ops, srv.Client()); code != apperr.ExitCLIValidation {
		t.Fatalf("expected ExitCLIValidation for --json without --secret-out, got %d", code)
	}

	// Initial connect + --update must revoke the old client.
	sec1 := filepath.Join(t.TempDir(), "sec1.txt")
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--redirect", "https://oauth-redirect.googleusercontent.com/r/1", "--data", dataDir, "--secret-out", sec1, "--approve"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("initial connect=%d", code)
	}
	sec2 := filepath.Join(t.TempDir(), "sec2.txt")
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--redirect", "https://oauth-redirect.googleusercontent.com/r/2", "--data", dataDir, "--secret-out", sec2, "--approve", "--update"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("update connect=%d", code)
	}

	db2, err := authzOpen(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	st := authz.NewSQLStore(db2.SQL())
	grants, err := st.ListGrants()
	if err != nil {
		t.Fatal(err)
	}
	activeCount, revokedCount := 0, 0
	for _, g := range grants {
		if g.Status == authz.GrantActive {
			activeCount++
		} else if g.Status == authz.GrantRevoked {
			revokedCount++
		}
	}
	if activeCount != 1 || revokedCount != 1 {
		t.Fatalf("expected 1 active + 1 revoked grant after --update, got active=%d revoked=%d", activeCount, revokedCount)
	}
}

func TestValidateGoogleVerificationDocumentStrict(t *testing.T) {
	if err := ValidateGoogleVerificationDocument([]byte(`{"verification_tokens":["abc"]}`), "abc"); err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}
	bad := [][]byte{
		[]byte(`{"connections":[{"app":"test"}]}`),
		[]byte(`{"verification_tokens":[]}`),
		[]byte(`{"verification_tokens":["a","a"]}`),
		[]byte(`{"verification_tokens":["  "]}`),
		[]byte(`not-json`),
	}
	for _, b := range bad {
		if err := ValidateGoogleVerificationDocument(b, ""); err == nil {
			t.Fatalf("expected rejection for %s", string(b))
		}
	}
	if err := ValidateGoogleVerificationDocument([]byte(`{"verification_tokens":["other"]}`), "expected"); err == nil {
		t.Fatal("expected mismatch rejection")
	}
}

func TestConnectGoogleIdempotenceChecksTenantAndAuthoritativeDB(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/r-idemp/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/r/r-idemp/mcp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/r-idemp/mcp","authorization_servers":["` + srvURL + `/r/r-idemp/oauth"]}`))
		case "/.well-known/oauth-authorization-server/r/r-idemp/oauth":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + srvURL + `/r/r-idemp/oauth","authorization_endpoint":"` + srvURL + `/r/r-idemp/oauth/authorize","token_endpoint":"` + srvURL + `/r/r-idemp/oauth/token","code_challenge_methods_supported":["S256"]}`))
		case "/.well-known/google-connected-apps":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"verification_tokens":["tok-idemp"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	seedEnrolledProfileForTest(t, srvURL)
	dataDir := t.TempDir()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[{"route_id":"r-idemp","pub_name":"my-mcp","profile":"managed-oauth","url":"` + srvURL + `/r/r-idemp/mcp","publication_state":"ACTIVE","desired_enabled":true}]}`), nil
		},
	}

	sec := filepath.Join(t.TempDir(), "sec.txt")
	cb := "https://oauth-redirect.googleusercontent.com/r/app1"
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--redirect", cb, "--data", dataDir, "--secret-out", sec, "--approve"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("initial connect=%d", code)
	}

	// 1. Different tenant without --update must NOT return idempotent success.
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--tenant", "other-tenant", "--redirect", cb, "--data", dataDir}, ops, srv.Client()); code != apperr.ExitCLIValidation {
		t.Fatalf("expected ExitCLIValidation for mismatched tenant, got %d", code)
	}

	// 2. Wrong/empty DB must NOT return idempotent success.
	otherDir := t.TempDir()
	dbOther, err := store.Open(filepath.Join(otherDir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = dbOther.Close()
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--redirect", cb, "--data", otherDir}, ops, srv.Client()); code != apperr.ExitCLIValidation {
		t.Fatalf("expected ExitCLIValidation when client missing from DB, got %d", code)
	}

	// 3. Client revoked directly in DB must refuse idempotent success.
	db2, err := authzOpen(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	st := authz.NewSQLStore(db2.SQL())
	grants, _ := st.ListGrants()
	_ = st.RevokeClient(grants[0].ClientID)
	_ = db2.Close()
	if code := cmdConnectWithOps([]string{"google", "my-mcp", "--redirect", cb, "--data", dataDir}, ops, srv.Client()); code != apperr.ExitAuth {
		t.Fatalf("expected ExitAuth when client revoked in DB, got %d", code)
	}
}

func TestConnectGoogleReconnectVerificationTokenAndCutoverRecovery(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/r-rec/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/r/r-rec/mcp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/r-rec/mcp","authorization_servers":["` + srvURL + `/r/r-rec/oauth"]}`))
		case "/.well-known/oauth-authorization-server/r/r-rec/oauth":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + srvURL + `/r/r-rec/oauth","authorization_endpoint":"` + srvURL + `/r/r-rec/oauth/authorize","token_endpoint":"` + srvURL + `/r/r-rec/oauth/token","code_challenge_methods_supported":["S256"]}`))
		case "/.well-known/google-connected-apps":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"verification_tokens":["tok-exact-99"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	seedEnrolledProfileForTest(t, srvURL)
	dataDir := t.TempDir()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[{"route_id":"r-rec","pub_name":"my-rec","profile":"managed-oauth","url":"` + srvURL + `/r/r-rec/mcp","publication_state":"ACTIVE","desired_enabled":true}]}`), nil
		},
	}

	// Trailing JSON must be rejected.
	if err := ValidateGoogleVerificationDocument([]byte(`{"verification_tokens":["a"]}{"extra":1}`), ""); err == nil {
		t.Fatal("expected trailing JSON rejection")
	}

	// Wrong --verification-token-file must fail.
	badTokFile := filepath.Join(t.TempDir(), "bad-tok.txt")
	_ = os.WriteFile(badTokFile, []byte("wrong-tok\n"), 0o600)
	cb := "https://oauth-redirect.googleusercontent.com/r/app1"
	if code := cmdConnectWithOps([]string{"google", "my-rec", "--redirect", cb, "--data", dataDir, "--verification-token-file", badTokFile}, ops, srv.Client()); code != apperr.ExitRelayTLS {
		t.Fatalf("expected ExitRelayTLS on mismatched verification token, got %d", code)
	}

	// Exact --verification-token-file succeeds and maps managed-oauth -> ocliv-managed.
	goodTokFile := filepath.Join(t.TempDir(), "good-tok.txt")
	_ = os.WriteFile(goodTokFile, []byte("tok-exact-99\n"), 0o600)
	sec1 := filepath.Join(t.TempDir(), "sec1.txt")
	if code := cmdConnectWithOps([]string{"google", "my-rec", "--redirect", cb, "--data", dataDir, "--verification-token-file", goodTokFile, "--secret-out", sec1, "--approve"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("connect google=%d, want 0", code)
	}
	svcStore, _ := openServicesForProfile("default")
	rec, ok, _ := svcStore.Get("my-rec")
	if !ok || rec.Auth != "ocliv-managed" {
		t.Fatalf("expected mapped Auth=ocliv-managed, got %q (ok=%v)", rec.Auth, ok)
	}

	// Revoke, then --reconnect creates a brand new client while old remains revoked.
	if code := cmdConnectWithOps([]string{"revoke", "google", "my-rec", "--data", dataDir}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("revoke=%d", code)
	}
	sec2 := filepath.Join(t.TempDir(), "sec2.txt")
	if code := cmdConnectWithOps([]string{"google", "my-rec", "--redirect", cb, "--data", dataDir, "--secret-out", sec2, "--approve", "--reconnect"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("reconnect=%d, want 0", code)
	}
	rec2, _, _ := svcStore.Get("my-rec")
	b2 := rec2.ProviderBindings["google"]
	if b2.ClientID == rec.ProviderBindings["google"].ClientID || len(b2.RevokedClientIDs) != 1 {
		t.Fatalf("expected new client ID + 1 revoked history, got %+v", b2)
	}
}
