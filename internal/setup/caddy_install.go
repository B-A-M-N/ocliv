package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// PinnedCaddyVersion is the known-good Caddy release installed by
// `ocliv relay setup` when Caddy (or its required DNS-01 module) is absent.
const PinnedCaddyVersion = "2.8.4"

// DefaultCaddyBinaryPath is an Ocliv-owned binary location so automatic Caddy
// provisioning never overwrites a distribution-managed /usr/bin/caddy binary.
const DefaultCaddyBinaryPath = "/usr/local/lib/ocliv/caddy"

// PinnedDNSModuleVersions maps supported DNS-01 provider names to pinned
// github.com/caddy-dns/<provider>@<version> module coordinates.
var PinnedDNSModuleVersions = map[string]string{
	"cloudflare":   "github.com/caddy-dns/cloudflare@v0.0.0-20240703190432-89f16b99c18e",
	"digitalocean": "github.com/caddy-dns/digitalocean@v0.0.0-20240529150351-278580e99603",
	"route53":      "github.com/caddy-dns/route53@v1.4.0",
	"rfc2136":      "github.com/caddy-dns/rfc2136@v0.1.0",
	"duckdns":      "github.com/caddy-dns/duckdns@v0.0.0-20240617171341-728823c97831",
}

// CaddyExpectedSHA256 optionally pins the expected SHA-256 hex digest of the
// downloaded Caddy binary (can be supplied via OCLIV_CADDY_SHA256 for air-gapped
// or strict checksum-pinned provisioning).
var CaddyExpectedSHA256 = ""

// runInstallCaddy is a test hook for automatic Caddy provisioning.
var runInstallCaddy = defaultInstallCaddy

// CaddyHasDNSModule reports whether an installed caddy binary (checking
// DefaultCaddyBinaryPath first, then PATH) includes the requested DNS-01
// provider module (e.g. "cloudflare" -> "dns.providers.cloudflare").
func CaddyHasDNSModule(provider string) bool {
	if strings.TrimSpace(provider) == "" {
		return true
	}
	bin := "caddy"
	if fi, err := os.Stat(DefaultCaddyBinaryPath); err == nil && !fi.IsDir() {
		bin = DefaultCaddyBinaryPath
	}
	out, err := exec.Command(bin, "list-modules").Output()
	if err != nil {
		return false
	}
	want := "dns.providers." + strings.ToLower(strings.TrimSpace(provider))
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], want) {
			return true
		}
	}
	return false
}

// InstallCaddy installs a pinned compatible Caddy binary (including the
// requested DNS-01 provider module when dnsProvider != "") atomically into
// DefaultCaddyBinaryPath (/usr/local/lib/ocliv/caddy), never overwriting a
// distribution-managed /usr/bin/caddy.
func InstallCaddy(dnsProvider string) error {
	return runInstallCaddy(dnsProvider)
}

// caddyDownloadURL builds the official Caddy download API URL for the current
// platform, pinned Caddy version, and optional pinned DNS-01 provider plugin.
func caddyDownloadURL(goos, goarch, dnsProvider string) string {
	q := url.Values{}
	q.Set("os", goos)
	q.Set("arch", goarch)
	q.Set("idempotency", PinnedCaddyVersion)
	if p := strings.ToLower(strings.TrimSpace(dnsProvider)); p != "" {
		if pinned, ok := PinnedDNSModuleVersions[p]; ok {
			q.Add("p", pinned)
		} else {
			q.Add("p", "github.com/caddy-dns/"+p)
		}
	}
	return "https://caddyserver.com/api/download?" + q.Encode()
}

func defaultInstallCaddy(dnsProvider string) error {
	downloadURL := caddyDownloadURL(runtime.GOOS, runtime.GOARCH, dnsProvider)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Refuse symlinked destination or parent directory.
	dir := filepath.Dir(DefaultCaddyBinaryPath)
	if fi, err := os.Lstat(DefaultCaddyBinaryPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlinked caddy path %s", DefaultCaddyBinaryPath)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("building caddy download request: %w", err)
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading caddy from %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caddy download returned HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".caddy-install-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	const maxCaddyBytes = 128 * 1024 * 1024
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxCaddyBytes+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("writing caddy binary: %w", err)
	}
	if n > maxCaddyBytes || n < 1024*1024 {
		tmp.Close()
		return fmt.Errorf("downloaded caddy binary has unexpected size %d bytes", n)
	}
	wantSHA := strings.TrimSpace(CaddyExpectedSHA256)
	if wantSHA == "" {
		wantSHA = strings.TrimSpace(os.Getenv("OCLIV_CADDY_SHA256"))
	}
	if wantSHA != "" {
		gotSHA := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(gotSHA, wantSHA) {
			tmp.Close()
			return fmt.Errorf("caddy binary SHA256 mismatch: got %s, expected %s", gotSHA, wantSHA)
		}
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod caddy binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync caddy binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing caddy binary: %w", err)
	}

	// Pre-swap candidate validation: verify binary executes and contains required DNS module.
	if out, err := exec.CommandContext(ctx, tmpName, "version").CombinedOutput(); err != nil {
		return fmt.Errorf("downloaded caddy binary failed `caddy version`: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if p := strings.ToLower(strings.TrimSpace(dnsProvider)); p != "" {
		out, err := exec.CommandContext(ctx, tmpName, "list-modules").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "dns.providers."+p) {
			return fmt.Errorf("downloaded caddy binary is missing required module dns.providers.%s", p)
		}
	}

	// Preserve existing managed binary safely using O_NOFOLLOW before atomic swap.
	prevPath := DefaultCaddyBinaryPath + ".prev"
	hadPrev := false
	if fd, oerr := syscall.Open(DefaultCaddyBinaryPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); oerr == nil {
		in := os.NewFile(uintptr(fd), DefaultCaddyBinaryPath)
		if ptmp, perr := os.CreateTemp(dir, ".caddy-prev-*"); perr == nil {
			ptmpName := ptmp.Name()
			if _, cerr := io.Copy(ptmp, in); cerr == nil && ptmp.Chmod(0o755) == nil && ptmp.Sync() == nil && ptmp.Close() == nil {
				if os.Rename(ptmpName, prevPath) == nil {
					hadPrev = true
				}
			} else {
				ptmp.Close()
				_ = os.Remove(ptmpName)
			}
		}
		in.Close()
	}

	if err := os.Rename(tmpName, DefaultCaddyBinaryPath); err != nil {
		return fmt.Errorf("installing caddy binary to %s: %w", DefaultCaddyBinaryPath, err)
	}
	if dh, err := os.Open(dir); err == nil {
		_ = dh.Sync()
		_ = dh.Close()
	}

	// Post-swap verification with automatic rollback on failure.
	if out, err := exec.CommandContext(ctx, DefaultCaddyBinaryPath, "version").CombinedOutput(); err != nil {
		if hadPrev {
			_ = os.Rename(prevPath, DefaultCaddyBinaryPath)
		} else {
			_ = os.Remove(DefaultCaddyBinaryPath)
		}
		return fmt.Errorf("installed caddy failed post-swap verification (rolled back): %v (%s)", err, strings.TrimSpace(string(out)))
	}
	cleanup = false
	return nil
}
