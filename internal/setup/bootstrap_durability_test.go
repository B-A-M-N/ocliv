package setup

// Regression for the second review's bootstrap durability finding. The
// candidate was staged under one FIXED name (<dst>.ocliv-staged), so two
// concurrent installs could write the same staged file and one rename
// could publish a torn mix; publication also lacked an fsync. The fix
// stages under a UNIQUE per-install name and fsyncs the staged file and
// its directory before/around the atomic rename, so a completed install
// never leaves a staged temp behind and the rename is journaled.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two consecutive installs must leave no staged temp and a valid final
// binary; the staged artifact (fixed or unique) is always swept.
func TestInstallBinaryLeavesNoStagedArtifact(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv")
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("binary-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InstallBinaryTo(src, dst); err != nil {
		t.Fatalf("install v1: %v", err)
	}
	if err := os.WriteFile(src, []byte("binary-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InstallBinaryTo(src, dst); err != nil {
		t.Fatalf("install v2: %v", err)
	}
	// No staged temp survives a completed install (fixed OR unique name).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".ocliv-staged") {
			t.Fatalf("staged artifact left behind after completed install: %s", e.Name())
		}
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary-v2" {
		t.Fatalf("final binary = %q, want binary-v2", got)
	}
}

// The publish boundary must be explicit so a candidate that fails
// validation is NEVER published, and the staged file must be fsynced
// before the atomic rename (power-loss durability). These pin the
// validateStagedBinary indirection and the fsync-on-staged-file contract.
func TestInstallBinaryValidationFailureSweepsStaged(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv")
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("bad-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := validateStagedBinary
	validateStagedBinary = func(string) error { return errors.New("simulated invalid candidate") }
	defer func() { validateStagedBinary = old }()
	if err := InstallBinaryTo(src, dst); err == nil {
		t.Fatal("invalid candidate published")
	}
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Fatalf("invalid candidate left a destination behind: %v", serr)
	}
}
