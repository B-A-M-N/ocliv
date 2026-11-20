package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/protocol"
	"ocliv/internal/store"
)

const userPublisherUnitTemplate = `# User-level Ocliv service publisher (%i).
# Provisioned automatically by ` + "`ocliv service start`" + `.
[Unit]
Description=Ocliv user service publisher (%i)
After=network-online.target ocliv-backend@%i.service

[Service]
Type=simple
EnvironmentFile=%h/.config/ocliv/service-%i.env
ExecStart=__OCLIV_BIN__ service run-publisher --name=${OCLIV_NAME} --profile=${OCLIV_PROFILE}
Restart=on-failure
RestartPreventExitStatus=2 4 6 7
RestartSec=15
KillSignal=SIGTERM
TimeoutStopSec=60
SuccessExitStatus=0
NoNewPrivileges=yes
UMask=0077
PrivateTmp=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=default.target
`

const userBackendUnitTemplate = `# User-level Ocliv managed backend (%i).
# Provisioned automatically by ` + "`ocliv service start`" + ` for --manage services.
[Unit]
Description=Ocliv managed local backend (%i)

[Service]
Type=simple
EnvironmentFile=%h/.config/ocliv/service-%i.env
ExecStart=__OCLIV_BIN__ service run-backend --name=${OCLIV_NAME} --profile=${OCLIV_PROFILE}
Restart=on-failure
RestartPreventExitStatus=2 4 6 7
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
NoNewPrivileges=yes
UMask=0077
RestrictSUIDSGID=yes

[Install]
WantedBy=default.target
`

// systemdQuoteArg quotes a single argument for systemd ExecStart= without
// invoking a shell, preserving spaces and special characters safely.
func systemdQuoteArg(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(s[i])
		case '%':
			// Escape systemd specifiers (%h, %i, etc.) in executable paths.
			b.WriteString("%%")
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

func renderPublisherUnitTemplate(exePath string) string {
	return strings.ReplaceAll(userPublisherUnitTemplate, "__OCLIV_BIN__", systemdQuoteArg(exePath))
}

func renderBackendUnitTemplate(exePath string) string {
	return strings.ReplaceAll(userBackendUnitTemplate, "__OCLIV_BIN__", systemdQuoteArg(exePath))
}

func writeAtomic0600(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ocliv-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dfd, derr := os.Open(dir)
	if derr != nil {
		return fmt.Errorf("rename succeeded, but directory durability check failed: %w", derr)
	}
	syncErr := dfd.Sync()
	closeErr := dfd.Close()
	if syncErr != nil {
		return fmt.Errorf("rename succeeded, but directory sync failed: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("rename succeeded, but directory close failed: %w", closeErr)
	}
	return nil
}

func userSystemdDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("cannot locate home directory for user systemd units")
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

func validUnitComponent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// serviceInstanceID returns the canonical systemd instance identity
// (<profile>--<service-name>-<hash6>) so services with the same name in
// different profiles or containing "--" never collide on unit names or env files.
func serviceInstanceID(profile, name string) (string, error) {
	prof := strings.TrimSpace(profile)
	if prof == "" {
		prof = "default"
	}
	if !validUnitComponent(prof) {
		return "", fmt.Errorf("invalid profile name %q for systemd unit", prof)
	}
	if !validUnitComponent(name) {
		return "", fmt.Errorf("invalid service name %q for systemd unit", name)
	}
	sum := sha256.Sum256([]byte(prof + "\x00" + name))
	return prof + "--" + name + "-" + hex.EncodeToString(sum[:3]), nil
}

func serviceUnitInstance(rec config.ServiceRecord) (string, error) {
	if strings.HasPrefix(rec.SystemdUnit, "ocliv-publisher@") && strings.HasSuffix(rec.SystemdUnit, ".service") {
		inst := strings.TrimSuffix(strings.TrimPrefix(rec.SystemdUnit, "ocliv-publisher@"), ".service")
		if validUnitComponent(inst) {
			return inst, nil
		}
	}
	return serviceInstanceID(rec.Profile, rec.Name)
}

func serviceEnvPath(rec config.ServiceRecord) (string, error) {
	inst, err := serviceUnitInstance(rec)
	if err != nil {
		return "", err
	}
	home, herr := os.UserHomeDir()
	if herr == nil && home != "" {
		return filepath.Join(home, ".config", "ocliv", "service-"+inst+".env"), nil
	}
	dir, err := config.DataDirForProfile(rec.Profile)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "service-"+inst+".env"), nil
}

// sanitizeEnvValue rejects newlines/nulls so env-file writes cannot inject extra variables.
func sanitizeEnvValue(v string) (string, error) {
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", fmt.Errorf("unsafe control character in configuration value")
	}
	return v, nil
}

// resolveManagedExecutable returns the pinned managed executable path at
// ~/.local/share/ocliv/bin/ocliv (P1-7, P1-8). It NEVER silently replaces an
// already-installed managed runtime with a different digest; only explicit
// `ocliv runtime upgrade` may replace it.
func resolveManagedExecutable() (string, error) {
	return ensureManagedRuntime()
}

// ensureManagedRuntime installs the initial pinned runtime if absent, or
// reuses the existing pinned runtime without overwriting it if its digest
// differs from the invoking CLI binary (P1-7, P1-8).
func ensureManagedRuntime() (string, error) {
	src, err := currentExecutablePath()
	if err != nil {
		return "", err
	}
	home, herr := os.UserHomeDir()
	if herr != nil || home == "" {
		return src, nil
	}
	dst := filepath.Join(home, ".local", "share", "ocliv", "bin", "ocliv")
	if src == dst {
		return dst, nil
	}
	unlock, lerr := lockRuntimeDir(filepath.Dir(dst))
	if lerr != nil {
		return "", fmt.Errorf("locking managed runtime dir: %w", lerr)
	}
	defer unlock()

	srcSum, err := fileSHA256(src)
	if err != nil {
		return "", err
	}
	if dstSum, derr := fileSHA256(dst); derr == nil {
		// P1-9: validate the existing pinned binary before trusting it.
		if verr := validatePinnedRuntime(dst, dstSum); verr != nil {
			return "", fmt.Errorf("MANAGED_RUNTIME_INVALID: %w (run `ocliv runtime upgrade` to repair)", verr)
		}
		if dstSum == srcSum {
			return dst, nil
		}
		// P1-7: NEVER silently replace an existing valid managed runtime.
		fmt.Fprintf(os.Stderr, "note: managed runtime at %s (%s) differs from running CLI (%s); keeping pinned runtime (run `ocliv runtime upgrade` to update)\n",
			dst, shortHash(dstSum), shortHash(srcSum))
		return dst, nil
	}
	if err := installManagedExecutableLocked(src, dst, srcSum); err != nil {
		return "", fmt.Errorf("installing initial managed ocliv executable at %s: %w", dst, err)
	}
	return dst, nil
}

// validatePinnedRuntime verifies that an existing managed runtime binary is a
// regular executable file owned by the current user, has a valid runtime.json
// manifest whose SHA-256 matches the binary on disk, and satisfies protocol
// and schema compatibility (P1-9).
func validatePinnedRuntime(dst, dstSum string) error {
	fi, err := os.Lstat(dst)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dst, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not a regular executable file", dst)
	}
	if statT, ok := fi.Sys().(*syscall.Stat_t); ok {
		euid := uint32(os.Geteuid())
		if statT.Uid != euid && statT.Uid != 0 {
			return fmt.Errorf("%s owned by uid %d (expected %d)", dst, statT.Uid, euid)
		}
	}
	m, ok := loadRuntimeManifest(dst)
	if !ok {
		return fmt.Errorf("missing or corrupt manifest at %s", runtimeManifestPath(dst))
	}
	if m.SHA256 != dstSum {
		return fmt.Errorf("binary digest %s does not match manifest %s", shortHash(dstSum), shortHash(m.SHA256))
	}
	if m.ProtocolVersion != "" && !protocol.VersionInRange(m.ProtocolVersion, protocol.MinVersion, protocol.MaxVersion) {
		return fmt.Errorf("manifest protocol %q incompatible with supported range %s-%s", m.ProtocolVersion, protocol.MinVersion, protocol.MaxVersion)
	}
	if m.StoreSchemaVersion > store.SchemaVersion {
		return fmt.Errorf("manifest schema V%d newer than supported V%d", m.StoreSchemaVersion, store.SchemaVersion)
	}
	return nil
}

// listAllProfileNames enumerates "default" plus every valid named profile
// under ~/.config/ocliv/profiles/ so global runtime operations cover all profiles (P1-8).
func listAllProfileNames() []string {
	out := []string{"default"}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return out
	}
	entries, err := os.ReadDir(filepath.Join(home, ".config", "ocliv", "profiles"))
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() && config.ValidProfileName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

func currentExecutablePath() (string, error) {
	src, err := os.Executable()
	if err != nil || src == "" {
		if p, lerr := exec.LookPath("ocliv"); lerr == nil {
			src = p
		} else {
			return "", fmt.Errorf("cannot locate ocliv executable: %w", err)
		}
	}
	if real, rerr := filepath.EvalSymlinks(src); rerr == nil && real != "" {
		src = real
	}
	if st, err := os.Stat(src); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		return "", fmt.Errorf("ocliv executable %q is not runnable", src)
	}
	return src, nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func lockRuntimeDir(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "runtime.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// runtimeManifest records full provenance and compatibility metadata for the
// pinned managed executable at ~/.local/share/ocliv/bin/ocliv (P1-9, P1-18).
type runtimeManifest struct {
	BinaryPath             string `json:"binary_path"`
	SHA256                 string `json:"sha256"`
	SourcePath             string `json:"source_path"`
	Version                string `json:"version"`
	BinaryVersion          string `json:"binary_version"`
	BuildCommit            string `json:"build_commit"`
	Dirty                  bool   `json:"dirty"`
	GoVersion              string `json:"go_version"`
	ProtocolVersion        string `json:"protocol_version"`
	SupportedProtocolRange string `json:"supported_protocol_range"`
	StoreSchemaVersion     int    `json:"store_schema_version"`
	InstalledAt            string `json:"installed_at"`
}

func buildRuntimeManifest(src, dst, sum string) runtimeManifest {
	bi := GetBuildInfo()
	return runtimeManifest{
		BinaryPath:             dst,
		SHA256:                 sum,
		SourcePath:             src,
		Version:                versionString(),
		BinaryVersion:          bi.Version,
		BuildCommit:            bi.BuildCommit,
		Dirty:                  bi.Dirty,
		GoVersion:              bi.GoVersion,
		ProtocolVersion:        bi.ProtocolVersion,
		SupportedProtocolRange: bi.SupportedProtocolRange,
		StoreSchemaVersion:     bi.StoreSchemaVersion,
		InstalledAt:            time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runtimeManifestPath(dst string) string {
	return filepath.Join(filepath.Dir(dst), "runtime.json")
}

func loadRuntimeManifest(dst string) (runtimeManifest, bool) {
	var m runtimeManifest
	raw, err := os.ReadFile(runtimeManifestPath(dst))
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.SHA256 == "" {
		return m, false
	}
	return m, true
}

func saveRuntimeManifest(dst string, m runtimeManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic0600(runtimeManifestPath(dst), string(raw)+"\n")
}

// installManagedExecutable is used by tests and explicit runtime upgrade.
func installManagedExecutable(src, dst string) error {
	unlock, err := lockRuntimeDir(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer unlock()
	srcSum, err := fileSHA256(src)
	if err != nil {
		return err
	}
	return installManagedExecutableLocked(src, dst, srcSum)
}

func installManagedExecutableLocked(src, dst, srcSum string) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if dstSum, derr := fileSHA256(dst); derr == nil && dstSum == srcSum {
		if m, ok := loadRuntimeManifest(dst); ok && m.SHA256 == srcSum && m.StoreSchemaVersion == store.SchemaVersion {
			return nil
		}
		return saveRuntimeManifest(dst, buildRuntimeManifest(src, dst, srcSum))
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(dir, ".ocliv-bin-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	dfd, derr := os.Open(dir)
	if derr != nil {
		return fmt.Errorf("rename succeeded, but directory sync open failed: %w", derr)
	}
	syncErr := dfd.Sync()
	closeErr := dfd.Close()
	if syncErr != nil {
		return fmt.Errorf("rename succeeded, but directory sync failed: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("rename succeeded, but directory close failed: %w", closeErr)
	}
	return saveRuntimeManifest(dst, buildRuntimeManifest(src, dst, srcSum))
}

func upgradeManagedRuntime(src, dst string, allowDowngrade bool) (runtimeManifest, error) {
	unlock, err := lockRuntimeDir(filepath.Dir(dst))
	if err != nil {
		return runtimeManifest{}, err
	}
	defer unlock()
	srcSum, err := fileSHA256(src)
	if err != nil {
		return runtimeManifest{}, err
	}
	// P1-9: compatibility fence — block protocol or schema downgrade without
	// explicit --allow-downgrade.
	if prev, ok := loadRuntimeManifest(dst); ok && !allowDowngrade {
		if prev.StoreSchemaVersion > 0 && store.SchemaVersion < prev.StoreSchemaVersion {
			return runtimeManifest{}, fmt.Errorf("refusing schema downgrade (installed V%d -> running V%d); pass --allow-downgrade to force",
				prev.StoreSchemaVersion, store.SchemaVersion)
		}
		if prev.ProtocolVersion != "" {
			prevRev, perr := protocol.ParseRevision(prev.ProtocolVersion)
			curRev, cerr := protocol.ParseRevision(protocol.Version)
			if perr == nil && cerr == nil && curRev < prevRev {
				return runtimeManifest{}, fmt.Errorf("refusing protocol downgrade (%s -> %s); pass --allow-downgrade to force",
					prev.ProtocolVersion, protocol.Version)
			}
		}
	}
	if src != dst {
		if err := installManagedExecutableLocked(src, dst, srcSum); err != nil {
			return runtimeManifest{}, err
		}
	} else {
		if err := saveRuntimeManifest(dst, buildRuntimeManifest(src, dst, srcSum)); err != nil {
			return runtimeManifest{}, err
		}
	}
	m, _ := loadRuntimeManifest(dst)
	return m, nil
}

// cmdRuntime inspects or explicitly upgrades the managed user-service runtime
// executable and its manifest (`ocliv runtime status|upgrade [--restart] [--allow-downgrade] [--json]`).
func cmdRuntime(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv runtime status [--json] | ocliv runtime upgrade [--restart] [--allow-downgrade] [--json]")
		return apperr.ExitCLIValidation
	}
	sub := argv[0]
	jsonOut := false
	restart := false
	allowDowngrade := false
	allowRoot := false
	for _, a := range argv[1:] {
		switch a {
		case "--json":
			jsonOut = true
		case "--allow-root":
			allowRoot = true
		case "--restart":
			if sub != "upgrade" {
				fmt.Fprintln(os.Stderr, "--restart is only valid with `ocliv runtime upgrade`")
				return apperr.ExitCLIValidation
			}
			restart = true
		case "--allow-downgrade":
			if sub != "upgrade" {
				fmt.Fprintln(os.Stderr, "--allow-downgrade is only valid with `ocliv runtime upgrade`")
				return apperr.ExitCLIValidation
			}
			allowDowngrade = true
		default:
			fmt.Fprintf(os.Stderr, "unknown runtime flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	if os.Geteuid() == 0 && !allowRoot {
		fmt.Fprintln(os.Stderr, "error: refusing to run user-level `ocliv runtime` as root (run as your normal user, or pass --allow-root)")
		return apperr.ExitCLIValidation
	}
	if sub != "status" && sub != "upgrade" {
		fmt.Fprintf(os.Stderr, "unknown runtime subcommand %q (want status or upgrade)\n", sub)
		return apperr.ExitCLIValidation
	}
	src, err := currentExecutablePath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	srcSum, err := fileSHA256(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot hash current executable: "+err.Error())
		return apperr.ExitInternal
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintln(os.Stderr, "error: cannot locate home directory")
		return apperr.ExitInternal
	}
	dst := filepath.Join(home, ".local", "share", "ocliv", "bin", "ocliv")
	if sub == "upgrade" {
		m, uerr := upgradeManagedRuntime(src, dst, allowDowngrade)
		if uerr != nil {
			fmt.Fprintln(os.Stderr, "error: runtime upgrade failed: "+uerr.Error())
			return apperr.ExitInternal
		}
		var restarted []string
		failedServices := map[string]string{}
		profileReports := map[string]any{}
		restartComplete := true
		if restart {
			ops := defaultServiceOps()
			for _, prof := range listAllProfileNames() {
				profRes := map[string]any{"restarted": []string{}, "failed": map[string]string{}}
				svcStore, serr := openServicesForProfile(prof)
				if serr != nil {
					restartComplete = false
					msg := fmt.Sprintf("open service store: %v", serr)
					failedServices[prof+"/*"] = msg
					profRes["error"] = msg
					profileReports[prof] = profRes
					continue
				}
				svcs, lerr := svcStore.List()
				if lerr != nil {
					restartComplete = false
					msg := fmt.Sprintf("list services: %v", lerr)
					failedServices[prof+"/*"] = msg
					profRes["error"] = msg
					profileReports[prof] = profRes
					continue
				}
				var profRestarted []string
				profFailed := map[string]string{}
				for _, svc := range svcs {
					if svc.DesiredState == config.DesiredEnabled {
						if _, _, rerr := restartHostedServiceInProfile(prof, svc.Name, ops); rerr != nil {
							restartComplete = false
							profFailed[svc.Name] = rerr.Error()
							failedServices[prof+"/"+svc.Name] = rerr.Error()
						} else {
							profRestarted = append(profRestarted, svc.Name)
							restarted = append(restarted, prof+"/"+svc.Name)
						}
					}
				}
				profRes["restarted"] = profRestarted
				profRes["failed"] = profFailed
				profileReports[prof] = profRes
			}
		}
		status := "upgraded"
		exitCode := apperr.ExitOK
		if !restartComplete || len(failedServices) > 0 {
			status = "upgraded_with_restart_failures"
			exitCode = apperr.ExitInternal
		}
		out := map[string]any{
			"status":             status,
			"runtime_upgraded":   true,
			"restart_complete":   restartComplete,
			"managed_binary":     dst,
			"sha256":             srcSum,
			"version":            versionString(),
			"manifest_path":      runtimeManifestPath(dst),
			"manifest":           m,
			"profiles":           profileReports,
			"restarted_services": restarted,
			"failed_services":    failedServices,
		}
		if jsonOut {
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
			return exitCode
		}
		fmt.Printf("✓ managed runtime upgraded at %s (sha256=%s)\n", dst, shortHash(srcSum))
		if len(restarted) > 0 {
			fmt.Printf("  restarted services: %s\n", strings.Join(restarted, ", "))
		}
		if len(failedServices) > 0 {
			for name, msg := range failedServices {
				fmt.Fprintf(os.Stderr, "  restart failed for %s: %s\n", name, msg)
			}
		}
		return exitCode
	}
	dstSum, dstErr := fileSHA256(dst)
	m, hasManifest := loadRuntimeManifest(dst)
	inSync := dstErr == nil && dstSum == srcSum
	binaryMatchesManifest := dstErr == nil && hasManifest && m.SHA256 == dstSum
	protocolCompat := !hasManifest || m.ProtocolVersion == "" || protocol.VersionInRange(m.ProtocolVersion, protocol.MinVersion, protocol.MaxVersion)
	schemaCompat := !hasManifest || m.StoreSchemaVersion == 0 || m.StoreSchemaVersion <= store.SchemaVersion
	unitUsesManaged := false
	if pubUnit, uerr := os.ReadFile(filepath.Join(home, ".config", "systemd", "user", "ocliv-publisher@.service")); uerr == nil {
		unitUsesManaged = strings.Contains(string(pubUnit), dst)
	}
	out := map[string]any{
		"running_binary":                      src,
		"running_sha256":                      srcSum,
		"managed_binary":                      dst,
		"managed_present":                     dstErr == nil,
		"managed_sha256":                      dstSum,
		"in_sync":                             inSync,
		"running_cli_matches_managed_runtime": inSync,
		"binary_matches_manifest":             binaryMatchesManifest,
		"unit_uses_managed_runtime":           unitUsesManaged,
		"protocol_compatible":                 protocolCompat,
		"schema_compatible":                   schemaCompat,
		"manifest_valid":                      hasManifest && binaryMatchesManifest,
		"manifest_path":                       runtimeManifestPath(dst),
		"has_manifest":                        hasManifest,
		"manifest":                            m,
	}
	if jsonOut {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	fmt.Printf("Running binary: %s (%s)\n", src, shortHash(srcSum))
	if dstErr != nil {
		fmt.Printf("Managed binary: not installed (%s)\n", dst)
	} else {
		fmt.Printf("Managed binary: %s (%s) in_sync=%v matches_manifest=%v\n", dst, shortHash(dstSum), inSync, binaryMatchesManifest)
	}
	if hasManifest {
		fmt.Printf("Manifest:       %s (version=%s proto=%s schema=V%d installed=%s)\n",
			runtimeManifestPath(dst), m.Version, m.ProtocolVersion, m.StoreSchemaVersion, m.InstalledAt)
	}
	return apperr.ExitOK
}

// extractExecStartBinary parses the quoted executable path from the installed
// systemd unit template's ExecStart= line so persistence checks verify the
// exact binary systemd will invoke.
func extractExecStartBinary(unitPath string) string {
	b, err := os.ReadFile(unitPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		if strings.HasPrefix(rest, `"`) {
			var out strings.Builder
			escaped := false
			for i := 1; i < len(rest); i++ {
				c := rest[i]
				if escaped {
					out.WriteByte(c)
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					return strings.ReplaceAll(out.String(), "%%", "%")
				}
				out.WriteByte(c)
			}
		} else if fields := strings.Fields(rest); len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

// provisionUserSupervisor validates the executable, target, and profile,
// pins a stable managed executable, writes the per-service 0600 env file
// (no bearer secrets), installs the user-level systemd unit templates, and
// reloads the user daemon.
func provisionUserSupervisor(rec config.ServiceRecord, ops serviceOps) error {
	exe, err := resolveManagedExecutable()
	if err != nil {
		return err
	}
	if rec.BackendMode == config.BackendManaged {
		if rec.BackendExec == "" {
			return fmt.Errorf("managed backend requires --exec")
		}
		bpath, berr := exec.LookPath(rec.BackendExec)
		if berr != nil {
			return fmt.Errorf("managed backend executable %q not found: %w", rec.BackendExec, berr)
		}
		if st, err := os.Stat(bpath); err != nil || st.Mode()&0o111 == 0 {
			return fmt.Errorf("managed backend executable %q is not executable", bpath)
		}
	}
	envPath, err := serviceEnvPath(rec)
	if err != nil {
		return err
	}
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	relay := rec.RelayURL
	if relay == "" {
		relay = agentRelayURLForProfile(prof)
	}
	fields := []struct{ k, v string }{
		{"OCLIV_NAME", rec.Name},
		{"OCLIV_TYPE", rec.Type},
		{"OCLIV_AUTH", rec.Auth},
		{"OCLIV_PROFILE", prof},
		{"OCLIV_RELAY_URL", relay},
		{"OCLIV_LOCAL_URL", rec.LocalURL},
	}
	if rec.BackendMode == config.BackendManaged {
		fields = append(fields,
			struct{ k, v string }{"OCLIV_BACKEND_EXEC", rec.BackendExec},
		)
	}
	var sb strings.Builder
	sb.WriteString("# Managed by `ocliv service` (mode 0600; no bearer secrets).\n")
	for _, f := range fields {
		clean, cerr := sanitizeEnvValue(f.v)
		if cerr != nil {
			return fmt.Errorf("%s: %w", f.k, cerr)
		}
		sb.WriteString(f.k)
		sb.WriteByte('=')
		sb.WriteString(clean)
		sb.WriteByte('\n')
	}
	_, existedBefore := os.Stat(envPath)
	if err := writeAtomic0600(envPath, sb.String()); err != nil {
		return fmt.Errorf("writing service env file: %w", err)
	}

	unitDir, err := userSystemdDir()
	if err != nil {
		if os.IsNotExist(existedBefore) {
			_ = os.Remove(envPath)
		}
		return err
	}
	pubUnit := filepath.Join(unitDir, "ocliv-publisher@.service")
	if err := writeAtomic0600(pubUnit, renderPublisherUnitTemplate(exe)); err != nil {
		if os.IsNotExist(existedBefore) {
			_ = os.Remove(envPath)
		}
		return fmt.Errorf("writing publisher unit template: %w", err)
	}
	if rec.BackendMode == config.BackendManaged {
		beUnit := filepath.Join(unitDir, "ocliv-backend@.service")
		if err := writeAtomic0600(beUnit, renderBackendUnitTemplate(exe)); err != nil {
			if os.IsNotExist(existedBefore) {
				_ = os.Remove(envPath)
			}
			return fmt.Errorf("writing backend unit template: %w", err)
		}
	}
	if out, err := ops.systemctl("daemon-reload"); err != nil {
		if os.IsNotExist(existedBefore) {
			_ = os.Remove(envPath)
		}
		return fmt.Errorf("systemctl --user daemon-reload failed: %v (%s)", err, out)
	}
	return nil
}

// PersistenceVerification records whether systemd persistence prerequisites
// are synchronously configured (`PersistenceConfigured`), kept strictly
// distinct from whether an actual machine reboot recovery has been proven
// (`RebootRecoveryProven`).
type PersistenceVerification struct {
	ManagerReachable      bool   `json:"manager_reachable"`
	PublisherUnitEnabled  bool   `json:"publisher_unit_enabled"`
	BackendUnitEnabled    bool   `json:"backend_unit_enabled"`
	LingerEnabled         bool   `json:"linger_enabled"`
	ExecutableVerified    bool   `json:"executable_verified"`
	PersistenceConfigured bool   `json:"persistence_configured"`
	RebootRecoveryProven  bool   `json:"reboot_recovery_proven"`
	FailureReason         string `json:"failure_reason,omitempty"`
}

func runLoginctl(ops serviceOps, args ...string) (string, error) {
	if ops.loginctl != nil {
		return ops.loginctl(args...)
	}
	out, err := exec.Command("loginctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func readEnvValue(envPath, key string) string {
	b, err := os.ReadFile(envPath)
	if err != nil {
		return ""
	}
	prefix := key + "="
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

// verifyRebootPersistence checks all prerequisites for true reboot-safe hosting:
// user systemd manager reachable, publisher unit enabled, managed backend unit
// enabled (when applicable), user lingering enabled, and saved executable(s)
// still present and executable.
func verifyRebootPersistence(rec config.ServiceRecord, ops serviceOps) PersistenceVerification {
	var pv PersistenceVerification
	pubInfo := inspectUnit(rec.SystemdUnit, ops)
	pv.ManagerReachable = pubInfo.ManagerReachable
	pv.PublisherUnitEnabled = pubInfo.EnabledKnown && pubInfo.Enabled

	if !pv.ManagerReachable {
		pv.FailureReason = "systemd user manager unreachable: " + pubInfo.Error
		return pv
	}
	if !pv.PublisherUnitEnabled {
		pv.FailureReason = fmt.Sprintf("publisher unit %s is not enabled for reboot persistence (state=%s)", rec.SystemdUnit, pubInfo.EnabledState)
		return pv
	}

	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		beInfo := inspectUnit(rec.BackendUnit, ops)
		if !beInfo.ManagerReachable {
			pv.ManagerReachable = false
			pv.FailureReason = "systemd user manager unreachable while checking backend unit: " + beInfo.Error
			return pv
		}
		pv.BackendUnitEnabled = beInfo.EnabledKnown && beInfo.Enabled
		if !pv.BackendUnitEnabled {
			pv.FailureReason = fmt.Sprintf("managed backend unit %s is not enabled for reboot persistence (state=%s)", rec.BackendUnit, beInfo.EnabledState)
			return pv
		}
	} else {
		pv.BackendUnitEnabled = true
	}

	// Verify user lingering so user systemd services survive logout and start at boot.
	u := strings.TrimSpace(os.Getenv("USER"))
	if u == "" {
		pv.FailureReason = "cannot determine current USER to verify systemd lingering"
		return pv
	}
	lout, lerr := runLoginctl(ops, "show-user", u, "-p", "Linger", "--value")
	if lerr == nil && strings.TrimSpace(lout) == "no" {
		_, _ = runLoginctl(ops, "enable-linger", u)
		lout, lerr = runLoginctl(ops, "show-user", u, "-p", "Linger", "--value")
	}
	if lerr != nil || strings.TrimSpace(lout) != "yes" {
		pv.FailureReason = fmt.Sprintf("systemd user lingering is not enabled for %q (got %q, err=%v); run `sudo loginctl enable-linger %s`", u, strings.TrimSpace(lout), lerr, u)
		return pv
	}
	pv.LingerEnabled = true

	// Verify the exact executable referenced by the installed systemd unit template.
	exe := ""
	if unitDir, err := userSystemdDir(); err == nil {
		exe = extractExecStartBinary(filepath.Join(unitDir, "ocliv-publisher@.service"))
	}
	if exe == "" {
		if cur, err := os.Executable(); err == nil {
			exe = cur
		}
	}
	if exe == "" {
		pv.FailureReason = "cannot locate saved ocliv executable"
		return pv
	}
	if st, err := os.Stat(exe); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		pv.FailureReason = fmt.Sprintf("saved ocliv executable %q is missing or not executable", exe)
		return pv
	}
	if rec.BackendMode == config.BackendManaged && rec.BackendExec != "" {
		bpath, berr := exec.LookPath(rec.BackendExec)
		if berr != nil {
			pv.FailureReason = fmt.Sprintf("managed backend executable %q not found: %v", rec.BackendExec, berr)
			return pv
		}
		if st, err := os.Stat(bpath); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			pv.FailureReason = fmt.Sprintf("managed backend executable %q is not executable", bpath)
			return pv
		}
	}
	pv.ExecutableVerified = true
	pv.PersistenceConfigured = true
	// RebootRecoveryProven remains false until an actual reboot qualification
	// receipt is recorded for this artifact and service configuration.
	pv.RebootRecoveryProven = false
	return pv
}

// UnitInspection holds structured systemd user unit state without leaking
// raw D-Bus/systemctl error strings as process states.
type UnitInspection struct {
	ManagerReachable bool   `json:"manager_reachable"`
	LoadState        string `json:"load_state,omitempty"`
	ActiveState      string `json:"active_state"`
	Enabled          bool   `json:"enabled,omitempty"`
	EnabledKnown     bool   `json:"enabled_known"`
	EnabledState     string `json:"enabled_state,omitempty"`
	Error            string `json:"error,omitempty"`
}

func inspectUnit(unit string, ops serviceOps) UnitInspection {
	if unit == "" {
		return UnitInspection{ManagerReachable: true, ActiveState: "not-configured", EnabledKnown: true, EnabledState: "not-configured"}
	}
	loadState, lerr := ops.systemctl("show", "-p", "LoadState", "--value", unit)
	ls := strings.TrimSpace(loadState)
	if lerr != nil && (strings.Contains(ls, "Failed to connect") || strings.Contains(lerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, ActiveState: "manager-unreachable", EnabledState: "enabled-unknown", Error: ls}
	}
	if lerr == nil && ls == "not-found" {
		return UnitInspection{ManagerReachable: true, LoadState: "not-found", ActiveState: "not-found", EnabledKnown: true, EnabledState: "not-found"}
	}
	enabled := false
	enabledKnown := false
	enabledState := "enabled-unknown"
	enOut, eerr := ops.systemctl("is-enabled", unit)
	en := strings.TrimSpace(enOut)
	if eerr != nil && (strings.Contains(en, "Failed to connect") || strings.Contains(eerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, LoadState: ls, ActiveState: "manager-unreachable", EnabledState: "enabled-unknown", Error: en}
	}
	switch en {
	case "enabled", "enabled-runtime", "static", "indirect":
		enabled = true
		enabledKnown = true
		enabledState = en
	case "disabled", "masked", "not-found":
		enabled = false
		enabledKnown = true
		enabledState = en
	default:
		if eerr == nil && en != "" {
			enabledState = en
		}
	}
	act, aerr := ops.systemctl("is-active", unit)
	act = strings.TrimSpace(act)
	if aerr != nil && (strings.Contains(act, "Failed to connect") || strings.Contains(aerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, LoadState: ls, ActiveState: "manager-unreachable", Enabled: enabled, EnabledKnown: enabledKnown, EnabledState: enabledState, Error: act}
	}
	switch act {
	case "active", "activating", "deactivating", "reloading", "inactive", "failed", "not-found":
		return UnitInspection{ManagerReachable: true, LoadState: ls, ActiveState: act, Enabled: enabled, EnabledKnown: enabledKnown, EnabledState: enabledState}
	}
	errMsg := "unknown active state"
	if aerr != nil {
		errMsg = aerr.Error()
	}
	return UnitInspection{ManagerReachable: true, LoadState: ls, ActiveState: "unknown", Enabled: enabled, EnabledKnown: enabledKnown, EnabledState: enabledState, Error: errMsg}
}

// queryUnitState distinguishes "not-found", "active", "activating", "failed",
// "inactive", and "manager-unreachable".
func queryUnitState(unit string, ops serviceOps) string {
	return inspectUnit(unit, ops).ActiveState
}

// UnitStopEvidence records authoritative systemd stop and disable proof so
// local service records are never removed while a unit is active, enabled,
// or unreachable.
type UnitStopEvidence struct {
	Unit              string `json:"unit"`
	ActiveState       string `json:"active_state"`
	StoppedNow        bool   `json:"stopped_now"`
	DisabledForReboot bool   `json:"disabled_for_reboot"`
	Error             string `json:"error,omitempty"`
}

func stopAndVerifyUnit(unit string, disable bool, ops serviceOps) UnitStopEvidence {
	ev := UnitStopEvidence{Unit: unit}
	if unit == "" {
		ev.ActiveState = "not-configured"
		ev.StoppedNow = true
		ev.DisabledForReboot = true
		return ev
	}
	before := inspectUnit(unit, ops)
	ev.ActiveState = before.ActiveState
	if !before.ManagerReachable {
		ev.Error = "STOP_UNCONFIRMED: systemd manager unreachable (" + before.Error + ")"
		return ev
	}
	if before.ActiveState == "not-found" {
		ev.StoppedNow = true
		ev.DisabledForReboot = true
		return ev
	}
	if out, err := ops.systemctl("stop", unit); err != nil {
		ev.Error = fmt.Sprintf("systemctl stop %s failed: %v (%s)", unit, err, strings.TrimSpace(out))
	}
	after := inspectUnit(unit, ops)
	ev.ActiveState = after.ActiveState
	if !after.ManagerReachable {
		ev.Error = "STOP_UNCONFIRMED: systemd manager became unreachable after stop"
		return ev
	}
	switch after.ActiveState {
	case "inactive", "failed", "not-found":
		ev.StoppedNow = true
	default:
		if ev.Error == "" {
			ev.Error = fmt.Sprintf("STOP_UNCONFIRMED: unit %s is %s", unit, after.ActiveState)
		}
	}
	if !disable {
		ev.DisabledForReboot = after.EnabledKnown && !after.Enabled
		return ev
	}
	if out, derr := ops.systemctl("disable", unit); derr != nil {
		afterDis := inspectUnit(unit, ops)
		if afterDis.ManagerReachable && afterDis.ActiveState == "not-found" {
			ev.DisabledForReboot = true
			return ev
		}
		ev.DisabledForReboot = false
		if ev.Error == "" {
			ev.Error = fmt.Sprintf("STOP_UNCONFIRMED: systemctl disable %s failed: %v (%s)", unit, derr, strings.TrimSpace(out))
		}
		return ev
	}
	afterDis := inspectUnit(unit, ops)
	if !afterDis.ManagerReachable || !afterDis.EnabledKnown || afterDis.Enabled {
		ev.DisabledForReboot = false
		if ev.Error == "" {
			ev.Error = fmt.Sprintf("STOP_UNCONFIRMED: unit %s enabled state after disable is %s", unit, afterDis.EnabledState)
		}
		return ev
	}
	ev.DisabledForReboot = true
	return ev
}
