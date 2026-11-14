package setup

// P2 bootstrap atomic replacement (source review 2026-11-14): the
// installer used os.WriteFile(dst, raw, 0755) directly, so a power
// failure or interrupted write could leave a partially installed
// binary at the final destination. The backup makes recovery
// possible, but recovery is not atomic publication. These tests pin
// the corrected contract: the candidate is staged on the destination
// filesystem, validated, and atomically renamed into place; an
// interruption before replacement leaves dst byte-identical to the
// previous binary and sweeps the staged candidate.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Interruption before replacement (injected as a validation failure at
// the publish boundary): dst must remain the previous binary
// byte-for-byte, the staged candidate must be swept, and the rollback
// point must still be the previous binary.
func TestInstallBinaryInterruptedBeforeReplacementKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv")
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(dst, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldValidate := validateStagedBinary
	validateStagedBinary = func(string) error { return errors.New("simulated interruption before replacement") }
	defer func() { validateStagedBinary = oldValidate }()

	if err := InstallBinaryTo(src, dst); err == nil {
		t.Fatal("interrupted install reported success")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("destination unreadable after interrupted install: %v", err)
	}
	if string(got) != "old-binary" {
		t.Fatalf("interrupted install published a partial/new binary: %q", got)
	}
	if _, serr := os.Stat(dst + ".ocliv-staged"); !os.IsNotExist(serr) {
		t.Fatalf("interrupted install left the staged candidate behind: %v", serr)
	}
	bak, err := os.ReadFile(dst + ".ocliv-bak")
	if err != nil {
		t.Fatalf("rollback point lost: %v", err)
	}
	if string(bak) != "old-binary" {
		t.Fatalf("rollback point = %q, want old-binary", bak)
	}
}

// Completed replacement followed by a later bootstrap failure: the
// atomic publish lands the whole candidate, the staged artifact is
// gone, and RollbackBinary restores the preserved previous binary.
func TestInstallBinaryCompletedReplacementThenFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv")
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(dst, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InstallBinaryTo(src, dst); err != nil {
		t.Fatalf("install: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-binary" {
		t.Fatalf("installed binary = %q, want new-binary", got)
	}
	if _, serr := os.Stat(dst + ".ocliv-staged"); !os.IsNotExist(serr) {
		t.Fatalf("completed install left the staged candidate behind: %v", serr)
	}
	fi, err := os.Stat(dst)
	if err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("installed binary is not executable: %v", err)
	}
	// Later bootstrap step fails; the operator rolls back.
	restored, err := RollbackBinary(dst)
	if err != nil {
		t.Fatalf("rollback after later failure: %v", err)
	}
	if !restored {
		t.Fatal("rollback reported nothing to restore")
	}
	got, _ = os.ReadFile(dst)
	if string(got) != "old-binary" {
		t.Fatalf("rollback restored %q, want old-binary", got)
	}
}
