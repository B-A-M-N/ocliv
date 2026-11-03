package setup

// Bootstrap planning contract (Slice 3b): PlanBootstrap turns the
// detected path and the local tool environment into an explicit step
// list. It never touches the system; executors do that live, only as
// root, with backups. CGNAT/unknown paths block with a reason instead
// of a doomed provisioning run.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanBlocksCGNAT(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: true, Path: PathCGNAT})
	if len(steps) != 0 {
		t.Fatalf("CGNAT planned %d steps; want none", len(steps))
	}
	if reason == "" {
		t.Fatal("CGNAT blocked without a reason")
	}
}

func TestPlanBlocksUnknown(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: true, Path: PathUnknown})
	if len(steps) != 0 || reason == "" {
		t.Fatalf("unknown path: steps=%d reason=%q", len(steps), reason)
	}
}

func TestPlanNonRootIsAllManual(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: false, CaddyPresent: true, Path: PathDirectV6, Hostname: "lab.dynv6.net", DeployDir: "/tmp/x"})
	if reason != "" {
		t.Fatalf("viable path blocked: %q", reason)
	}
	if len(steps) == 0 {
		t.Fatal("no steps planned")
	}
	for _, s := range steps {
		if s.Auto {
			t.Errorf("non-root step %q marked auto", s.Title)
		}
		if s.Manual == "" {
			t.Errorf("non-root step %q has no manual command", s.Title)
		}
	}
}

func TestPlanRootWithCaddyIsAllAuto(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: true, Path: PathDirectV4, Hostname: "lab.dynv6.net", DeployDir: "/tmp/x"})
	if reason != "" {
		t.Fatalf("viable path blocked: %q", reason)
	}
	if len(steps) == 0 {
		t.Fatal("no steps planned")
	}
	for _, s := range steps {
		if !s.Auto {
			t.Errorf("root+caddy step %q not auto", s.Title)
		}
	}
}

func TestInstallRefusesUnmanagedCaddyfile(t *testing.T) {
	dir := t.TempDir()
	deploy := t.TempDir()
	if err := os.WriteFile(filepath.Join(deploy, "Caddyfile"), []byte("tls internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "Caddyfile")
	unrelated := "# corporate reverse proxy\nreverse_proxy 127.0.0.1:9000\n"
	if err := os.WriteFile(dst, []byte(unrelated), 0o644); err != nil {
		t.Fatal(err)
	}
	oldValidate := runCaddyValidate
	runCaddyValidate = func(string) error { return nil }
	defer func() { runCaddyValidate = oldValidate }()
	if err := InstallCaddyfileTo(deploy, dst); err == nil {
		t.Fatal("unmanaged Caddyfile overwritten without refusal")
	} else if !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("refusal must name the hazard, got: %v", err)
	}
	raw, _ := os.ReadFile(dst)
	if string(raw) != unrelated {
		t.Fatalf("unmanaged Caddyfile modified:\n%s", raw)
	}
	if _, err := os.Stat(dst + ".ocliv-bak"); !os.IsNotExist(err) {
		t.Fatal("backup created for a refused install")
	}
}

func TestInstallRestoresBackupOnInvalid(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Caddyfile"), []byte("tls internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "installed-Caddyfile")
	old := ManagedMarker + "\nold config\n"
	if err := os.WriteFile(dst, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	oldValidate := runCaddyValidate
	runCaddyValidate = func(string) error { return errors.New("caddy: boom") }
	defer func() { runCaddyValidate = oldValidate }()
	if err := InstallCaddyfileTo(dir, dst); err == nil {
		t.Fatal("invalid Caddyfile accepted")
	}
	raw, _ := os.ReadFile(dst)
	if string(raw) != old {
		t.Fatalf("previous working config not restored:\n%s", raw)
	}
}

func TestInstallRollbackRestoresWorkingConfig(t *testing.T) {
	dir := t.TempDir()
	deploy := t.TempDir()
	dst := filepath.Join(dir, "ocliv-relay.service")
	old := ManagedMarker + "\n[Unit]\n"
	if err := os.WriteFile(dst, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deploy, "ocliv-relay.service"), []byte("[Unit]\nnew\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldReload := runDaemonReload
	runDaemonReload = func() error { return nil }
	defer func() { runDaemonReload = oldReload }()
	if err := InstallUnitTo(deploy, dst); err != nil {
		t.Fatalf("valid unit refused: %v", err)
	}
	// A later step (e.g. StartRelay) fails: the whole operation must
	// roll back to the previously working configuration.
	RollbackInstalled(dst)
	raw, _ := os.ReadFile(dst)
	if string(raw) != old {
		t.Fatalf("rollback lost the working config:\n%s", raw)
	}
}

func TestPlanRootWithoutCaddyStopsAtInstall(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: false, Path: PathDirectV4})
	if len(steps) != 1 {
		t.Fatalf("want exactly the install-caddy step, got %d", len(steps))
	}
	if steps[0].Auto {
		t.Error("caddy install must be manual (package manager, user consent)")
	}
	if reason == "" {
		t.Error("missing re-run guidance after Caddy install")
	}
}
