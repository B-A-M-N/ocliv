package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallManagedFile_SymlinkDestRejected proves that a symlink at the
// destination path is refused, so a local unprivileged user cannot redirect
// a privileged write to an attacker-chosen target by substituting a symlink.
func TestInstallManagedFile_SymlinkDestRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-target")
	dst := filepath.Join(dir, "config.conf")

	// Write a file containing the managed marker at the target.
	targetContent := ManagedMarker + "\noriginal content\n"
	if err := os.WriteFile(target, []byte(targetContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Replace dst with a symlink pointing to target.
	if err := os.Symlink(target, dst); err != nil {
		t.Fatal(err)
	}

	candidate := []byte(ManagedMarker + "\nnew content\n")
	err := installManagedFile(dst, candidate, nil)
	if err == nil {
		t.Fatal("expected error when destination is a symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected error to mention symlink, got: %v", err)
	}

	// Verify the symlink target was NOT overwritten.
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("reading target after refused write: %v", readErr)
	}
	if string(got) != targetContent {
		t.Errorf("symlink target was modified despite rejection; want %q got %q", targetContent, string(got))
	}
}

// TestInstallManagedFile_SymlinkBakRejected proves that a symlink at the
// backup path is refused before any backup write occurs.
func TestInstallManagedFile_SymlinkBakRejected(t *testing.T) {
	dir := t.TempDir()
	bakTarget := filepath.Join(dir, "bak-real-target")
	dst := filepath.Join(dir, "config.conf")
	bakPath := dst + ".ocliv-bak"

	// Write an existing managed file at dst.
	existing := []byte(ManagedMarker + "\nexisting content\n")
	if err := os.WriteFile(dst, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a file at the backup target so we can verify it's not modified.
	bakTargetContent := "sensitive data\n"
	if err := os.WriteFile(bakTarget, []byte(bakTargetContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Place a symlink at the backup path pointing to the sensitive file.
	if err := os.Symlink(bakTarget, bakPath); err != nil {
		t.Fatal(err)
	}

	candidate := []byte(ManagedMarker + "\nnew content\n")
	err := installManagedFile(dst, candidate, nil)
	if err == nil {
		t.Fatal("expected error when backup path is a symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected error to mention symlink, got: %v", err)
	}

	// Verify the backup target was NOT overwritten.
	got, readErr := os.ReadFile(bakTarget)
	if readErr != nil {
		t.Fatalf("reading bak target: %v", readErr)
	}
	if string(got) != bakTargetContent {
		t.Errorf("backup symlink target was modified despite rejection; want %q got %q", bakTargetContent, string(got))
	}
}

// TestInstallManagedFile_SymlinkSentinelRejected proves that a symlink at
// the new-file sentinel path is refused (new installation, not an update).
func TestInstallManagedFile_SymlinkSentinelRejected(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "new-config.conf")
	sentinel := newFileSentinel(dst)
	sentinelTarget := filepath.Join(dir, "sentinel-target")

	// Place a file at the sentinel target.
	sentinelTargetContent := "sentinel data\n"
	if err := os.WriteFile(sentinelTarget, []byte(sentinelTargetContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Place a symlink at the sentinel path.
	if err := os.Symlink(sentinelTarget, sentinel); err != nil {
		t.Fatal(err)
	}

	candidate := []byte(ManagedMarker + "\nnew content\n")
	err := installManagedFile(dst, candidate, nil)
	if err == nil {
		t.Fatal("expected error when sentinel path is a symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected error to mention symlink, got: %v", err)
	}

	// Verify sentinel target was NOT overwritten.
	got, readErr := os.ReadFile(sentinelTarget)
	if readErr != nil {
		t.Fatalf("reading sentinel target: %v", readErr)
	}
	if string(got) != sentinelTargetContent {
		t.Errorf("sentinel symlink target was modified despite rejection")
	}
}

// TestSafeWriteFile_SymlinkRejectedBeforeRename is a unit test for the
// safeWriteFile TOCTOU race detection: a symlink placed at dst after the
// initial Lstat (simulated by the pre-rename Lstat in safeWriteFile)
// must be caught before the rename.
func TestSafeWriteFile_SymlinkRejectedBeforeRename(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "attack-target")
	dst := filepath.Join(dir, "managed.conf")

	if err := os.WriteFile(target, []byte("sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a symlink at dst before calling safeWriteFile.
	if err := os.Symlink(target, dst); err != nil {
		t.Fatal(err)
	}

	err := safeWriteFile(dst, []byte("new data\n"), 0o644)
	if err == nil {
		t.Fatal("expected safeWriteFile to reject symlink destination, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}

	// Confirm target was not modified.
	got, _ := os.ReadFile(target)
	if string(got) != "sensitive\n" {
		t.Error("attack target was modified")
	}
}
