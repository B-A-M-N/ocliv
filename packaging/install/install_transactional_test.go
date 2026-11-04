package install_test

// Transactional install drills (P0-1): install.sh stages and validates
// candidates before activation and restores the previous state on ANY
// failure — including the historical Caddy-validation gap, which used to
// exit without rolling back the installed binary. Tests run the real
// script hermetically: destination paths are redirected into a temp dir
// via OCLIV_INSTALL_* and privileged/host commands (id, go, useradd,
// chown, systemctl, systemd-analyze, caddy) are replaced with PATH shims
// so no root or live host is needed.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installSandbox builds a hermetic install target with fake commands.
// The fake `go build` emits a shell script answering `relay --help` and
// `--help` with success; failure modes are injected via shim control
// files in the sandbox (systemd-fail, caddy-fail, build-fail).
type installSandbox struct {
	root   string
	env    []string
	layout struct {
		bin       string
		launcher  string
		dataDir   string
		envFile   string
		unitFile  string
		caddyFile string
	}
}

func newInstallSandbox(t *testing.T, priorContents map[string]string) *installSandbox {
	t.Helper()
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	etcDir := filepath.Join(root, "etc")
	for _, d := range []string{binDir, etcDir, filepath.Join(root, "data"), filepath.Join(root, "src"), filepath.Join(root, "shims")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := &installSandbox{root: root}
	s.layout.bin = filepath.Join(binDir, "ocliv")
	s.layout.launcher = filepath.Join(binDir, "ocliv-relay-launch.sh")
	s.layout.dataDir = filepath.Join(root, "data")
	s.layout.envFile = filepath.Join(etcDir, "relay.env")
	s.layout.unitFile = filepath.Join(etcDir, "ocliv-relay.service")
	s.layout.caddyFile = filepath.Join(etcDir, "Caddyfile")
	// A minimal source tree: install.sh cd's into SRC_DIR and builds
	// ./cmd/ocliv, then copies packaging/systemd/* relative to it.
	src := filepath.Join(root, "src")
	real, err := filepath.Abs("../..")
	if err != nil || !strings.Contains(real, "ocliv") {
		// Package cwd is packaging/install; repo root is two up.
		if abs, aerr := filepath.Abs("."); aerr == nil {
			real = filepath.Join(abs, "..", "..")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := exec.Command("cp", "-R", filepath.Join(real, "packaging"), filepath.Join(src, "packaging")).Run(); err != nil {
		t.Fatalf("copy packaging: %v", err)
	}
	for name, content := range priorContents {
		var dst string
		switch name {
		case "bin":
			dst = s.layout.bin
		case "env":
			dst = s.layout.envFile
		case "launcher":
			dst = s.layout.launcher
		case "unit":
			dst = s.layout.unitFile
		case "caddy":
			dst = s.layout.caddyFile
		default:
			continue
		}
		if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	shimDir := filepath.Join(root, "shims")
	fakeGo := "#!/bin/sh\n" +
		"if [ -f \"$FAKE_BIN_STATE_DIR/go-fail\" ]; then exit 1; fi\n" +
		"if [ \"$1\" = \"build\" ]; then\n" +
		"  shift\n" +
		"  while [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf '#!/bin/sh\\necho new-binary\\n' > \"$1\"; chmod +x \"$1\"; fi; shift; done\n" +
		" fi\n" +
		"exit 0\n"
	writeShim(t, shimDir, "go", fakeGo)
	writeShim(t, shimDir, "id", "#!/bin/sh\necho 0\n")
	writeShim(t, shimDir, "useradd", "#!/bin/sh\nexit 0\n")
	writeShim(t, shimDir, "chown", "#!/bin/sh\nexit 0\n")
	writeShim(t, shimDir, "systemctl", "#!/bin/sh\nif [ -f \"$FAKE_BIN_STATE_DIR/systemctl-fail\" ]; then echo systemctl-fail >&2; exit 1; fi\nexit 0\n")
	writeShim(t, shimDir, "systemd-analyze", "#!/bin/sh\nif [ -f \"$FAKE_BIN_STATE_DIR/systemd-fail\" ]; then echo systemd-fail >&2; exit 1; fi\nexit 0\n")
	writeShim(t, shimDir, "caddy", "#!/bin/sh\nif [ -f \"$FAKE_BIN_STATE_DIR/caddy-fail\" ]; then echo caddy-fail >&2; exit 1; fi\nexit 0\n")
	s.env = []string{
		"SRC_DIR=" + src,
		"OCLIV_INSTALL_BIN=" + s.layout.bin,
		"OCLIV_INSTALL_LAUNCHER=" + s.layout.launcher,
		"OCLIV_INSTALL_DATA_DIR=" + s.layout.dataDir,
		"OCLIV_INSTALL_ENV_DIR=" + etcDir,
		"OCLIV_INSTALL_ENV_FILE=" + s.layout.envFile,
		"OCLIV_INSTALL_UNIT_FILE=" + s.layout.unitFile,
		"OCLIV_INSTALL_CADDY_FILE=" + s.layout.caddyFile,
		"DOMAIN=relay.test",
		"PATH=" + shimDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_BIN_STATE_DIR=" + root,
	}
	return s
}

func writeShim(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (s *installSandbox) inject(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.root, name), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *installSandbox) run() (string, error) {
	cmd := exec.Command("sh", "install.sh")
	cmd.Env = append(os.Environ(), s.env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func TestInstallHappyPathAndIdempotent(t *testing.T) {
	s := newInstallSandbox(t, map[string]string{
		"bin": "old-binary\n", "env": "OCLIV_DOMAIN=old.test\n",
		"launcher": "old-launcher\n", "unit": "old-unit\n", "caddy": "old-caddy\n",
	})
	out, err := s.run()
	if err != nil {
		t.Fatalf("install: %v: %s", err, out)
	}
	if !strings.Contains(readFile(t, s.layout.bin), "new-binary") {
		t.Fatalf("binary not installed: %q", readFile(t, s.layout.bin))
	}
	if got := readFile(t, s.layout.envFile); !strings.Contains(got, "OCLIV_DOMAIN=relay.test") {
		t.Fatalf("env not installed: %q", got)
	}
	// Idempotent re-run: succeeds and keeps the FIRST rollback candidate.
	out, err = s.run()
	if err != nil {
		t.Fatalf("second install: %v: %s", err, out)
	}
	if prev := readFile(t, s.layout.bin+".prev"); prev != "old-binary\n" {
		t.Fatalf("rollback candidate not first-wins: prev=%q", prev)
	}
	// No bak sidecars left behind a good install.
	for _, f := range []string{s.layout.envFile, s.layout.launcher, s.layout.unitFile} {
		if _, err := os.Stat(f + ".ocliv-bak"); !os.IsNotExist(err) {
			t.Fatalf("bak sidecar left behind %s", f)
		}
	}
}

func TestInstallCaddyFailureRollsBackEverything(t *testing.T) {
	s := newInstallSandbox(t, map[string]string{
		"bin": "old-binary\n", "env": "OCLIV_DOMAIN=old.test\n",
		"launcher": "old-launcher\n", "unit": "old-unit\n", "caddy": "old-caddy\n",
	})
	s.inject(t, "caddy-fail")
	_, err := s.run()
	if err == nil {
		t.Fatal("install with failing caddy validation succeeded")
	}
	// The P0 bug: the new binary was left installed. All managed files
	// must be byte-identical to their pre-install state.
	if got := readFile(t, s.layout.bin); got != "old-binary\n" {
		t.Fatalf("binary not rolled back: %q", got)
	}
	if got := readFile(t, s.layout.envFile); got != "OCLIV_DOMAIN=old.test\n" {
		t.Fatalf("env not rolled back: %q", got)
	}
	if got := readFile(t, s.layout.launcher); got != "old-launcher\n" {
		t.Fatalf("launcher not rolled back: %q", got)
	}
	if got := readFile(t, s.layout.unitFile); got != "old-unit\n" {
		t.Fatalf("unit not rolled back: %q", got)
	}
}

func TestInstallCleanHostFailureRemovesNewFiles(t *testing.T) {
	s := newInstallSandbox(t, map[string]string{"caddy": "old-caddy\n"})
	s.inject(t, "systemd-fail")
	_, err := s.run()
	if err == nil {
		t.Fatal("install with failing unit validation succeeded")
	}
	// Clean host: nothing existed before, so rollback must remove
	// everything the install created (no leftover new binary/env/unit).
	for name, p := range map[string]string{"bin": s.layout.bin, "env": s.layout.envFile, "unit": s.layout.unitFile} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left behind after clean-host rollback: %v", name, err)
		}
	}
}

func TestInstallBuildFailureLeavesEverythingUntouched(t *testing.T) {
	s := newInstallSandbox(t, map[string]string{
		"bin": "old-binary\n", "env": "OCLIV_DOMAIN=old.test\n",
		"launcher": "old-launcher\n", "unit": "old-unit\n", "caddy": "old-caddy\n",
	})
	s.inject(t, "go-fail")
	_, err := s.run()
	if err == nil {
		t.Fatal("install with failing build succeeded")
	}
	if got := readFile(t, s.layout.bin); got != "old-binary\n" {
		t.Fatalf("binary changed on build failure: %q", got)
	}
	if got := readFile(t, s.layout.envFile); got != "OCLIV_DOMAIN=old.test\n" {
		t.Fatalf("env changed on build failure: %q", got)
	}
}
