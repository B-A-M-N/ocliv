package cli

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestPairResumeRejectsKeyMismatchAndInvalidURL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))

	// Generate a local identity key.
	_, keyPath, _, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Save(keyPath); err != nil {
		t.Fatal(err)
	}

	// 1. Saved pending state with invalid remote HTTP relay URL must be rejected.
	if err := savePairPending("http://remote.example.net", "key-"+string(k.ID()), "pid", "psec", 600, ""); err != nil {
		t.Fatal(err)
	}
	if rc := cmdPairResume(nil); rc != apperr.ExitCLIValidation {
		t.Fatalf("expected ExitCLIValidation for invalid persisted relay URL, got %d", rc)
	}

	// 2. Saved pending state bound to a DIFFERENT key_id must be rejected.
	if err := savePairPending("https://relay.example.net", "key-0000000000000000", "pid", "psec", 600, ""); err != nil {
		t.Fatal(err)
	}
	if rc := cmdPairResume(nil); rc != apperr.ExitAuth {
		t.Fatalf("expected ExitAuth for mismatched key_id, got %d", rc)
	}
}

func TestPairAndResumeWithPrivateCACert(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)

	var lastKeyID string
	approved := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/pair-request":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pairing_code":       "aaaa-bbbb-cccc",
				"poll_id":            "poll-123",
				"poll_secret":        "secret-456",
				"expires_in_seconds": 600,
			})
		case "/v1/agent/pair-status":
			w.Header().Set("Content-Type", "application/json")
			if approved {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":    "approved",
					"tenant_id": "t-ca",
					"key_id":    lastKeyID,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without --cacert, private CA must fail TLS verification.
	if rc := cmdPair([]string{srv.URL, "--no-wait"}); rc == apperr.ExitOK {
		t.Fatalf("expected TLS failure without --cacert")
	}

	// With --cacert, pair --no-wait succeeds and saves pending state bound to local key.
	if rc := cmdPair([]string{srv.URL, "--no-wait", "--cacert", caPath}); rc != apperr.ExitOK {
		t.Fatalf("pair --no-wait with --cacert failed: rc=%d", rc)
	}
	_, keyPath, _, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	k, err := identity.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	lastKeyID = "key-" + string(k.ID())
	approved = true

	// Resume using --cacert (and saved CACertPath) completes within 10s.
	if rc := cmdPairResume([]string{"--cacert", caPath, "--timeout", (8 * time.Second).String()}); rc != apperr.ExitOK {
		t.Fatalf("pair resume with --cacert failed: rc=%d", rc)
	}
	// Pending file must be cleaned up after terminal approved outcome.
	if _, err := os.Stat(filepath.Join(cfgDir, "pair-pending.json")); !os.IsNotExist(err) {
		t.Fatalf("pair-pending.json should be removed after approval")
	}
}

func TestWritePrivateFileAtomicRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "pair-pending.json")
	if err := os.Symlink(victim, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFileAtomic(linkPath, []byte(`{"poll_secret":"x"}`)); err == nil {
		t.Fatal("writePrivateFileAtomic must refuse to overwrite a pre-existing symlink")
	}
	got, _ := os.ReadFile(victim)
	if string(got) != "untouched" {
		t.Fatalf("victim was modified through symlink: %q", got)
	}
}

func TestDefaultPairInterruptedResumesSameRequest(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ocliv")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("OCLIV_CONFIG_DIR", cfgDir)

	var lastKeyID string
	approved := false
	pairCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/pair-request":
			pairCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pairing_code":       "1234-5678-90ab",
				"poll_id":            "poll-int",
				"poll_secret":        "sec-int",
				"expires_in_seconds": 600,
			})
		case "/v1/agent/pair-status":
			w.Header().Set("Content-Type", "application/json")
			if approved {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":    "approved",
					"tenant_id": "t-resume",
					"key_id":    lastKeyID,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Default wait mode interrupted (short timeout) before approval: must leave
	// pair-pending.json persisted on disk so a second invocation can resume.
	if rc := cmdPair([]string{srv.URL, "--timeout", "100ms"}); rc != apperr.ExitAuth {
		t.Fatalf("expected timeout ExitAuth, got %d", rc)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "pair-pending.json")); err != nil {
		t.Fatalf("pair-pending.json not persisted during default wait: %v", err)
	}
	_, keyPath, _, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	k, err := identity.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	lastKeyID = "key-" + string(k.ID())
	approved = true

	// Second CLI invocation resumes against the SAME pairing request (pairCalls stays 1).
	if rc := cmdPairResume([]string{"--timeout", "8s"}); rc != apperr.ExitOK {
		t.Fatalf("pair resume after interrupted default wait failed: rc=%d", rc)
	}
	if pairCalls != 1 {
		t.Fatalf("expected 1 pair-request total, got %d", pairCalls)
	}
}
