package setup

// Clean-host bootstrap contract (Slice 3b completion): `ocliv setup
// --auto` used to install ONLY the Caddyfile and the systemd unit,
// which leaves a fresh host without the service account, binary,
// launcher, environment file, or data directory the unit requires —
// the relay cannot start and nothing is activated. These tests pin
// the complete artifact set, its ordering, permissions, and the
// rollback contract for each managed piece. Destinations are
// explicit (*To) and system calls are injected, so nothing here
// touches /etc or /usr/local.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The planner must return the COMPLETE clean-host sequence in an order
// that satisfies each step's prerequisites: the account and data dir
// exist before the relay can start; the Caddyfile exists before Caddy
// can be reloaded; the unit exists before it is enabled.
func TestPlanBootstrapCoversFullCleanHostArtifactSet(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{
		AsRoot: true, CaddyPresent: true, Path: PathDirectV4,
		Hostname: "lab.dynv6.net", DeployDir: "/tmp/deploy", DataDir: "/var/lib/ocliv",
	})
	if reason != "" {
		t.Fatalf("viable path blocked: %q", reason)
	}
	want := []string{
		"create service account",
		"install binary",
		"install launcher",
		"create data directory",
		"install relay environment",
		"install Caddyfile",
		"activate and reload Caddy",
		"install systemd unit",
		"enable and start relay",
		"enroll this machine",
		"install and enable dynv6 refresh timer",
	}
	if len(steps) != len(want) {
		t.Fatalf("planned %d steps, want %d: %v", len(steps), len(want), titles(steps))
	}
	for i, w := range want {
		if steps[i].Title != w {
			t.Fatalf("step %d = %q, want %q (full plan: %v)", i, steps[i].Title, w, titles(steps))
		}
		if !steps[i].Auto {
			t.Errorf("root+caddy step %q not auto", steps[i].Title)
		}
		if steps[i].Manual == "" {
			t.Errorf("step %q has no manual command", steps[i].Title)
		}
	}
}

// Non-root plans must print the exact manual commands for the SAME
// complete set — an operator without root needs every artifact named,
// not just the two the bootstrap used to cover.
func TestPlanBootstrapNonRootNamesEveryArtifact(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{
		AsRoot: false, CaddyPresent: true, Path: PathDirectV6,
		Hostname: "lab.dynv6.net", DeployDir: "/tmp/deploy", DataDir: "/var/lib/ocliv",
	})
	if reason != "" {
		t.Fatalf("viable path blocked: %q", reason)
	}
	if len(steps) != 11 {
		t.Fatalf("non-root plan has %d steps, want 11: %v", len(steps), titles(steps))
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

func TestInstallDynv6RefreshKeepsTokenOutOfUnitsAndJournalsToken(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	envPath := filepath.Join(root, "etc", "ocliv", "dns-refresh.env")
	servicePath := filepath.Join(root, "systemd", "ocliv-dns-refresh.service")
	timerPath := filepath.Join(root, "systemd", "ocliv-dns-refresh.timer")
	oldChown, oldReload := chownDynv6Token, runDaemonReload
	chownDynv6Token = func(string) error { return nil }
	runDaemonReload = func() error { return nil }
	defer func() { chownDynv6Token, runDaemonReload = oldChown, oldReload }()

	if err := InstallDynv6RefreshTo("Lab.Dynv6.net.", "secret-token", dataDir, envPath, servicePath, timerPath); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dataDir, "dynv6.token")
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode=%o, want 0600", info.Mode().Perm())
	}
	for _, path := range []string{envPath, servicePath, timerPath} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "secret-token") {
			t.Fatalf("secret leaked into %s", path)
		}
	}
	env, err := os.ReadFile(envPath)
	if err != nil || !strings.Contains(string(env), "OCLIV_DNS_HOST=lab.dynv6.net") || !strings.Contains(string(env), tokenPath) {
		t.Fatalf("unexpected refresh env %q: %v", env, err)
	}
	timer, err := os.ReadFile(timerPath)
	if err != nil || !strings.Contains(string(timer), "OnUnitActiveSec=15min") {
		t.Fatalf("timer is not configured for fifteen minutes: %q: %v", timer, err)
	}
	if err := RollbackDynv6Token(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("rollback left newly created token: %v", err)
	}
}

func TestInstallDynv6RefreshRefusesDifferentExistingToken(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "dynv6.token")
	if err := os.WriteFile(path, []byte("old-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installDynv6Token(path, "new-token"); err == nil {
		t.Fatal("different existing token was silently replaced")
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "old-token\n" {
		t.Fatalf("existing token changed: %q, %v", body, err)
	}
}

func titles(steps []Step) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Title
	}
	return out
}

// The service account step is idempotent: an existing account is left
// untouched and useradd runs at most once per process.
func TestEnsureServiceAccountIdempotent(t *testing.T) {
	added := 0
	exists := false
	oldExists, oldAdd := serviceUserExists, serviceUserAdd
	serviceUserExists = func(string) bool { return exists }
	serviceUserAdd = func(name, home string) error {
		added++
		if name != RelayUser {
			t.Fatalf("useradd name = %q, want %q", name, RelayUser)
		}
		if home != "/var/lib/ocliv" {
			t.Fatalf("useradd home = %q, want the data dir", home)
		}
		exists = true
		return nil
	}
	defer func() { serviceUserExists, serviceUserAdd = oldExists, oldAdd }()
	if err := EnsureServiceAccount(RelayUser, "/var/lib/ocliv"); err != nil {
		t.Fatalf("first EnsureServiceAccount: %v", err)
	}
	if added != 1 {
		t.Fatalf("useradd calls = %d, want 1", added)
	}
	if err := EnsureServiceAccount(RelayUser, "/var/lib/ocliv"); err != nil {
		t.Fatalf("second EnsureServiceAccount: %v", err)
	}
	if added != 1 {
		t.Fatalf("re-run added the account again (calls=%d), want idempotence", added)
	}
}

// A failed useradd must be loud — never silently continue to a relay
// start that will fail on User=ocliv.
func TestEnsureServiceAccountReportsAddFailure(t *testing.T) {
	oldExists, oldAdd := serviceUserExists, serviceUserAdd
	serviceUserExists = func(string) bool { return false }
	serviceUserAdd = func(string, string) error { return os.ErrPermission }
	defer func() { serviceUserExists, serviceUserAdd = oldExists, oldAdd }()
	if err := EnsureServiceAccount(RelayUser, "/var/lib/ocliv"); err == nil {
		t.Fatal("failed useradd reported success")
	}
}

// The data directory is created, fixed to the service account, and
// rolled back ONLY when this run created it. A pre-existing database
// directory is never removed — that would destroy the relay state.
func TestEnsureDataDirCreatesAndRollsBack(t *testing.T) {
	chowned := []string{}
	oldLookup, oldChown := lookupRelayUser, chownPath
	lookupRelayUser = func(string) (int, int, error) { return 4242, 4242, nil }
	chownPath = func(p string, uid, gid int) error {
		chowned = append(chowned, p)
		if uid != 4242 || gid != 4242 {
			t.Fatalf("chown ids = %d/%d, want the resolved service account", uid, gid)
		}
		return nil
	}
	defer func() { lookupRelayUser, chownPath = oldLookup, oldChown }()
	dir := filepath.Join(t.TempDir(), "ocliv-data")
	if err := EnsureDataDir(dir, RelayUser); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}
	if len(chowned) != 1 || chowned[0] != dir {
		t.Fatalf("chown calls = %v, want [%s]", chowned, dir)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("data dir not created: %v", err)
	}
	restored, err := RollbackDataDir(dir)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !restored {
		t.Fatal("rollback reported nothing after creating the dir")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("newly created data dir survived rollback: %s", dir)
	}
	if _, err := os.Stat(dir + ".ocliv-new"); err == nil {
		t.Fatal("rollback left the journal sentinel behind")
	}
}

func TestEnsureDataDirKeepsExistingState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ocliv.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldLookup, oldChown := lookupRelayUser, chownPath
	lookupRelayUser = func(string) (int, int, error) { return 0, 0, nil }
	chownPath = func(string, int, int) error { return nil }
	defer func() { lookupRelayUser, chownPath = oldLookup, oldChown }()
	if err := EnsureDataDir(dir, RelayUser); err != nil {
		t.Fatalf("EnsureDataDir on existing dir: %v", err)
	}
	restored, err := RollbackDataDir(dir)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if restored {
		t.Fatal("rollback claimed changes to a pre-existing data dir")
	}
	if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); err != nil {
		t.Fatalf("existing relay state was disturbed: %v", err)
	}
}

// The binary install preserves a rollback candidate and the FIRST
// candidate wins across consecutive upgrades: re-running the install
// must not overwrite the original rollback point with an already
// upgraded binary (the install.sh contract, pinned here for the Go
// bootstrap path).
func TestInstallBinaryPreservesRollbackPoint(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv")
	src1 := filepath.Join(dir, "src1")
	src2 := filepath.Join(dir, "src2")
	if err := os.WriteFile(src1, []byte("binary-one"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src2, []byte("binary-two"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InstallBinaryTo(src1, dst); err != nil {
		t.Fatalf("first install: %v", err)
	}
	fi, err := os.Stat(dst)
	if err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("installed binary is not executable: %v", err)
	}
	if _, err := os.Stat(dst + ".ocliv-bak"); !os.IsNotExist(err) {
		t.Fatal("backup written on a fresh install (no previous binary)")
	}
	if err := InstallBinaryTo(src2, dst); err != nil {
		t.Fatalf("second install: %v", err)
	}
	bak, err := os.ReadFile(dst + ".ocliv-bak")
	if err != nil {
		t.Fatalf("upgrade lost the rollback candidate: %v", err)
	}
	if string(bak) != "binary-one" {
		t.Fatalf("rollback candidate = %q, want the FIRST candidate (binary-one)", bak)
	}
	restored, err := RollbackBinary(dst)
	if err != nil {
		t.Fatalf("binary rollback: %v", err)
	}
	if !restored {
		t.Fatal("binary rollback reported nothing to restore")
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "binary-one" {
		t.Fatalf("rollback restored %q, want binary-one", got)
	}
	if _, err := os.Stat(dst + ".ocliv-bak"); !os.IsNotExist(err) {
		t.Fatal("binary rollback left the backup behind")
	}
}

// A first-install binary rollback removes the file it created.
func TestRollbackBinaryRemovesWhenNoPrevious(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv")
	if err := os.WriteFile(dst, []byte("fresh"), 0o755); err != nil {
		t.Fatal(err)
	}
	restored, err := RollbackBinary(dst)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !restored {
		t.Fatal("fresh-install rollback reported nothing")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("newly installed binary survived rollback: %s", dst)
	}
}

// The env file is installed 0600, root-owned, with the managed marker
// so a later run cannot clobber an unrelated environment file; the
// rendered content rides along unchanged after the marker line.
func TestInstallEnvToInstalls0600WithMarker(t *testing.T) {
	deploy := t.TempDir()
	body := "OCLIV_DOMAIN=lab.dynv6.net\nOCLIV_MCP_HOST=lab.dynv6.net\n"
	if err := os.WriteFile(filepath.Join(deploy, "relay.env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "relay", "relay.env")
	if err := InstallEnvTo(deploy, dst); err != nil {
		t.Fatalf("InstallEnvTo: %v", err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read installed env: %v", err)
	}
	if !strings.HasPrefix(string(raw), ManagedMarker) {
		t.Fatalf("env file missing the managed marker:\n%s", raw)
	}
	if !strings.Contains(string(raw), body) {
		t.Fatalf("rendered env body not preserved:\n%s", raw)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("env file mode = %o, want 0600 (it names the relay's host and is root-owned)", perm)
	}
	// Rollback after a later failure removes the newly created file.
	restored, err := RollbackInstalled(dst)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !restored {
		t.Fatal("env rollback reported nothing")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("newly created env file survived rollback: %s", dst)
	}
}

// The env install refuses an UNMANAGED destination, exactly like the
// Caddyfile and unit: another application's environment file is never
// adopted or overwritten.
func TestInstallEnvToRefusesUnmanaged(t *testing.T) {
	deploy := t.TempDir()
	if err := os.WriteFile(filepath.Join(deploy, "relay.env"), []byte("OCLIV_DOMAIN=x.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "relay.env")
	foreign := "APP_ENV=production\n"
	if err := os.WriteFile(dst, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	err := InstallEnvTo(deploy, dst)
	if err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("unmanaged env file not refused: %v", err)
	}
	raw, _ := os.ReadFile(dst)
	if string(raw) != foreign {
		t.Fatalf("unmanaged env file modified:\n%s", raw)
	}
}

// The launcher install must stay a valid executable script: the
// shebang stays on line 1 and the managed marker goes after it.
func TestInstallLauncherToKeepsShebangExecutable(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv-relay-launch.sh")
	if err := InstallLauncherTo(dst); err != nil {
		t.Fatalf("InstallLauncherTo: %v", err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	if lines[0] != "#!/bin/sh" {
		t.Fatalf("shebang displaced from line 1: %q", lines[0])
	}
	if !strings.Contains(lines[1], ManagedMarker) {
		t.Fatalf("managed marker not on line 2: %q", lines[1])
	}
	if !strings.Contains(string(raw), "ocliv-relay-launch") {
		t.Fatalf("launcher content missing:\n%s", raw)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o755 {
		t.Fatalf("launcher mode = %o, want 0755", perm)
	}
	if perm := fi.Mode().Perm(); perm&0o111 == 0 {
		t.Fatalf("launcher mode = %o, want the owner-execute bit set (it is ExecStart)", perm)
	}
	// Unix-only: a script with the displaced-shebang bug is a regular
	// file the kernel refuses to exec; check that shebang + marker order
	// is what a loader sees (execute bit plus valid interpreter line).
	if runtime.GOOS != "linux" {
		return
	}
	if first, rerr := os.ReadFile(dst); rerr != nil || len(first) < 2 || first[0] != '#' || first[1] != '!' {
		t.Fatalf("installed launcher does not start with #! (the kernel cannot exec it): %v", rerr)
	}
}
