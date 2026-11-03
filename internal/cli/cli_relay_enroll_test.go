package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A help request must never mint an enrollment code or create state:
// `issue-enroll --help` previously ignored the flag and issued a live
// code against the default store.
func TestIssueEnrollHelpTouchesNoStore(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "ocliv.db")
		if code := cmdRelay([]string{"issue-enroll", flag, "--data", dir}); code == 0 {
			t.Fatalf("issue-enroll %s exited 0, want usage error", flag)
		}
		if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
			t.Fatalf("issue-enroll %s created %s", flag, dbPath)
		}
	}
}
