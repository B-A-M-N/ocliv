package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Chaos E2: a validation failure whose own restore also fails must not
// silently report a clean rollback. The validation stub below simulates
// a hostile post-write state (dst replaced by a directory) so the
// restore write deterministically fails even for a privileged test
// runner. Before the fix, installManagedFile discarded the restore
// error AND removed the backup, destroying the recovery artifact.
func TestInstallValidationFailureWithFailedRestoreIsLoud(t *testing.T) {
	dir := t.TempDir()
	deploy := t.TempDir()
	if err := os.WriteFile(filepath.Join(deploy, "Caddyfile"), []byte("tls internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "Caddyfile")
	old := ManagedMarker + "\nold config\n"
	if err := os.WriteFile(dst, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	oldValidate := runCaddyValidate
	runCaddyValidate = func(got string) error {
		if err := os.Remove(got); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(got, 0o755); err != nil {
			t.Fatal(err)
		}
		return errors.New("caddy: boom")
	}
	defer func() { runCaddyValidate = oldValidate }()
	err := InstallCaddyfileTo(deploy, dst)
	if err == nil {
		t.Fatal("invalid Caddyfile accepted")
	}
	if !strings.Contains(err.Error(), "restore") {
		t.Fatalf("rollback restore failure must be reported, got: %v", err)
	}
	if _, serr := os.Stat(dst + ".ocliv-bak"); serr != nil {
		t.Fatalf("failed restore must keep the backup as a recovery artifact: %v", serr)
	}
}

// Chaos C1 (compound): a failed install whose automatic restore also
// fails must still leave the operator a working manual recovery path.
// Fault 1: validation rejects the candidate. Fault 2: the restore
// write fails (read-only destination). Expected: loud error, backup
// preserved, and a later RollbackInstalled recovers the old config.
func TestInstallFailRestoreFailThenOperatorRollbackRecovers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission fault needs a non-root runner")
	}
	dir := t.TempDir()
	deploy := t.TempDir()
	if err := os.WriteFile(filepath.Join(deploy, "Caddyfile"), []byte("tls internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "Caddyfile")
	old := ManagedMarker + "\nold config\n"
	if err := os.WriteFile(dst, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	oldValidate := runCaddyValidate
	runCaddyValidate = func(got string) error {
		if err := os.Chmod(got, 0o444); err != nil {
			t.Fatal(err)
		}
		return errors.New("caddy: boom")
	}
	defer func() { runCaddyValidate = oldValidate }()
	if err := InstallCaddyfileTo(deploy, dst); err == nil {
		t.Fatal("invalid Caddyfile accepted")
	} else if !strings.Contains(err.Error(), "restore failed") {
		t.Fatalf("restore failure must be loud, got: %v", err)
	}
	// Operator intervenes: fix permissions, roll back.
	if err := os.Chmod(dst, 0o644); err != nil {
		t.Fatal(err)
	}
	restored, err := RollbackInstalled(dst)
	if err != nil {
		t.Fatalf("operator rollback failed: %v", err)
	}
	if !restored {
		t.Fatal("operator rollback reported nothing to restore")
	}
	raw, _ := os.ReadFile(dst)
	if string(raw) != old {
		t.Fatalf("operator rollback lost the working config:\n%s", raw)
	}
}

// Chaos E3: RollbackInstalled under a permission/shape failure must
// report the failure and keep the backup, never claim success.
func TestRollbackInstalledReportsUnwritableDestination(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv-relay.service")
	// dst is a directory: no restore write can succeed, even as root.
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	backup := ManagedMarker + "\n[Unit]\n"
	if err := os.WriteFile(dst+".ocliv-bak", []byte(backup), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := RollbackInstalled(dst)
	if err == nil {
		t.Fatal("rollback into an unwritable destination reported success")
	}
	if restored {
		t.Fatal("rollback must not report restoration when the write failed")
	}
	raw, rerr := os.ReadFile(dst + ".ocliv-bak")
	if rerr != nil || string(raw) != backup {
		t.Fatal("failed rollback must preserve the backup byte-for-byte")
	}
}
