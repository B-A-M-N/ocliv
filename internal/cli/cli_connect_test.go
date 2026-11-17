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
			_, _ = w.Write([]byte(`{"connections":[{"app":"test"}]}`))
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
