// Package installer downloads and verifies Ocliv release artifacts from a
// relay's well-known manifest endpoint. All writes are atomic: a temp file
// receives the download, its SHA256 and candidate execution are verified,
// then it is renamed into place with rollback on post-swap failure.
package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const maxDownloadBytes = 100 * 1024 * 1024 // 100 MB

// AllowUnqualifiedRelease disables the govulncheck=pass requirement.
// Set to true only for testing or emergency override scenarios.
var AllowUnqualifiedRelease bool

// ReleaseManifest matches the dist/*/release-manifest.json format.
// Artifacts contains only binary distribution artifacts served by the relay
// artifact endpoint (ocliv-{os}-{arch} naming). Sbom is optional provenance
// metadata that is NOT served by the artifact endpoint.
type ReleaseManifest struct {
	Commit          string                   `json:"commit"`
	Dirty           bool                     `json:"dirty"`
	NonProduction   bool                     `json:"non_production,omitempty"`
	SigningKeyID    string                   `json:"signing_key_id,omitempty"`
	BuildTime       string                   `json:"build_time"`
	ProtocolVersion string                   `json:"protocol_version"`
	SchemaVersion   int                      `json:"schema_version"`
	Govulncheck     string                   `json:"govulncheck"`
	Artifacts       map[string]ArtifactEntry `json:"artifacts"`
	// Sbom is the optional SBOM provenance entry. Not served by the artifact endpoint.
	Sbom *ArtifactEntry `json:"sbom,omitempty"`
}

// ArtifactEntry holds provenance data for one artifact.
type ArtifactEntry struct {
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size,omitempty"`
	Platform string `json:"platform,omitempty"`
}

// ArtifactName returns the canonical artifact name for a given platform, e.g.
// "ocliv-linux-amd64". Unrecognised values pass through as-is so callers can
// provide overrides without special-casing.
func ArtifactName(goos, goarch string) string {
	return "ocliv-" + strings.ToLower(goos) + "-" + strings.ToLower(goarch)
}

// ManifestURL returns the conventional manifest URL for a relay base URL.
func ManifestURL(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + "/.well-known/ocliv-release-manifest.json"
}

// ArtifactURL returns the conventional artifact download URL for a relay.
func ArtifactURL(baseURL, artifactName string) string {
	return strings.TrimRight(baseURL, "/") + "/.well-known/ocliv-artifacts/" + artifactName
}

// VerifyManifest verifies that rawManifest was signed by pubKey.
// sigHex must be a hex-encoded Ed25519 signature over the exact manifest bytes.
// Never silently succeeds — the caller decides whether to skip verification.
func VerifyManifest(rawManifest []byte, sigHex string, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length %d (want %d)", len(pubKey), ed25519.PublicKeySize)
	}
	if sigHex == "" {
		return fmt.Errorf("manifest signature missing")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("manifest signature malformed")
	}
	if !ed25519.Verify(pubKey, rawManifest, sig) {
		return fmt.Errorf("manifest signature invalid")
	}
	return nil
}

// VerifyManifestAny verifies rawManifest against a set of trusted Ed25519
// public keys. Returns nil if any valid key in keys verifies the signature.
// Empty key sets always fail closed.
func VerifyManifestAny(rawManifest []byte, sigHex string, keys []ed25519.PublicKey) error {
	if len(keys) == 0 {
		return fmt.Errorf("no trusted release public keys configured")
	}
	if sigHex == "" {
		return fmt.Errorf("manifest signature missing")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("manifest signature malformed")
	}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, rawManifest, sig) {
			return nil
		}
	}
	return fmt.Errorf("manifest signature invalid (not verified by any trusted key)")
}

// FetchManifest downloads and parses the manifest from manifestURL.
// It fails if the manifest is missing, malformed, dirty, or govulncheck != "pass"
// (unless AllowUnqualifiedRelease is true). No signature verification is
// performed — use FetchManifestSigned / FetchManifestSignedAny for production.
func FetchManifest(ctx context.Context, client *http.Client, manifestURL string) (*ReleaseManifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("manifest request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manifest fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("relay does not publish a release manifest (operator must set ReleaseManifestJSON)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest fetch: HTTP %d", resp.StatusCode)
	}
	var m ReleaseManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}
	if m.Dirty {
		return nil, fmt.Errorf("refusing dirty build: manifest reports dirty=true (non-reproducible provenance)")
	}
	if len(m.Artifacts) == 0 {
		return nil, fmt.Errorf("manifest contains no artifacts")
	}
	if !AllowUnqualifiedRelease && m.Govulncheck != "pass" {
		return nil, fmt.Errorf("refusing release: govulncheck=%q (expected \"pass\")", m.Govulncheck)
	}
	return &m, nil
}

// FetchManifestSigned downloads the manifest, fetches its detached .sig signature,
// verifies the signature using pubKey, then parses and validates the manifest.
// Never skips verification — if you have no signing key, call FetchManifest instead.
func FetchManifestSigned(ctx context.Context, client *http.Client, manifestURL string, pubKey ed25519.PublicKey) (*ReleaseManifest, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length %d (want %d)", len(pubKey), ed25519.PublicKeySize)
	}
	return FetchManifestSignedAny(ctx, client, manifestURL, []ed25519.PublicKey{pubKey})
}

// FetchManifestSignedAny downloads the manifest and its detached .sig signature,
// verifies the signature against any key in pubKeys, then parses and validates.
func FetchManifestSignedAny(ctx context.Context, client *http.Client, manifestURL string, pubKeys []ed25519.PublicKey) (*ReleaseManifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("manifest request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manifest fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("relay does not publish a release manifest")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest fetch: HTTP %d", resp.StatusCode)
	}
	rawManifest, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("manifest read: %w", err)
	}

	sigURL := manifestURL + ".sig"
	sigReq, err := http.NewRequestWithContext(ctx, http.MethodGet, sigURL, nil)
	if err != nil {
		return nil, fmt.Errorf("signature request: %w", err)
	}
	sigResp, err := client.Do(sigReq)
	if err != nil {
		return nil, fmt.Errorf("signature fetch: %w", err)
	}
	defer sigResp.Body.Close()
	if sigResp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("relay does not publish a manifest signature; unsigned manifests are not accepted by this client")
	}
	if sigResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signature fetch: HTTP %d", sigResp.StatusCode)
	}
	sigBytes, err := io.ReadAll(io.LimitReader(sigResp.Body, 256))
	if err != nil {
		return nil, fmt.Errorf("signature read: %w", err)
	}
	// Accept either 64 raw signature bytes or hex-encoded signature.
	var sigHex string
	if len(sigBytes) == ed25519.SignatureSize {
		sigHex = hex.EncodeToString(sigBytes)
	} else {
		sigHex = strings.TrimSpace(string(sigBytes))
	}
	if err := VerifyManifestAny(rawManifest, sigHex, pubKeys); err != nil {
		return nil, err
	}

	var m ReleaseManifest
	if err := json.Unmarshal(rawManifest, &m); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}
	if m.NonProduction {
		return nil, fmt.Errorf("refusing non-production release manifest (non_production=true)")
	}
	if m.Dirty {
		return nil, fmt.Errorf("refusing dirty build: manifest reports dirty=true")
	}
	if len(m.Artifacts) == 0 {
		return nil, fmt.Errorf("manifest contains no artifacts")
	}
	if !AllowUnqualifiedRelease && m.Govulncheck != "pass" {
		return nil, fmt.Errorf("refusing release: govulncheck=%q (expected \"pass\")", m.Govulncheck)
	}
	return &m, nil
}

// DownloadToTemp downloads artifactURL into a new temporary file in dir,
// enforces the maximum size (distinguishing exact-limit from oversized via
// maxDownloadBytes+1), verifies SHA256 against expected, sets mode 0755, and
// fsyncs the file. Caller owns removing the returned path if not renamed.
func DownloadToTemp(ctx context.Context, client *http.Client, artifactURL, expected, dir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return "", fmt.Errorf("artifact request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("artifact fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifact fetch: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dir, "ocliv-install-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	limited := io.LimitReader(resp.Body, maxDownloadBytes+1)
	n, err := io.Copy(io.MultiWriter(tmp, h), limited)
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("downloading artifact: %w", err)
	}
	if n > maxDownloadBytes {
		tmp.Close()
		return "", fmt.Errorf("artifact exceeds maximum size (%d bytes)", maxDownloadBytes)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing temp file: %w", err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return "", fmt.Errorf("digest mismatch: got %s, expected %s", got, expected)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", fmt.Errorf("chmod temp file: %w", err)
	}
	cleanup = false
	return tmpName, nil
}

// ValidateBinaryCandidate executes `<binPath> version --json` and verifies
// that the binary runs cleanly and matches the authenticated manifest's
// commit, protocol_version, and schema_version (when populated in manifest).
func ValidateBinaryCandidate(ctx context.Context, binPath string, manifest *ReleaseManifest) error {
	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(vctx, binPath, "version", "--json").Output()
	if err != nil {
		return fmt.Errorf("candidate binary failed `version --json`: %w", err)
	}
	var info struct {
		Version         string `json:"version"`
		Commit          string `json:"commit"`
		BuildCommit     string `json:"build_commit"`
		ProtocolVersion string `json:"protocol_version"`
		SchemaVersion   int    `json:"schema_version"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return fmt.Errorf("candidate binary returned invalid version JSON: %w", err)
	}
	if info.Version == "" {
		return fmt.Errorf("candidate binary reported empty version")
	}
	if manifest != nil {
		gotCommit := info.BuildCommit
		if gotCommit == "" {
			gotCommit = info.Commit
		}
		if manifest.Commit != "" && gotCommit != manifest.Commit {
			return fmt.Errorf("candidate commit %q does not match manifest commit %q", gotCommit, manifest.Commit)
		}
		if manifest.ProtocolVersion != "" && info.ProtocolVersion != manifest.ProtocolVersion {
			return fmt.Errorf("candidate protocol_version %q does not match manifest %q", info.ProtocolVersion, manifest.ProtocolVersion)
		}
		if manifest.SchemaVersion > 0 && info.SchemaVersion != manifest.SchemaVersion {
			return fmt.Errorf("candidate schema_version %d does not match manifest %d", info.SchemaVersion, manifest.SchemaVersion)
		}
	}
	return nil
}

// ActivateBinary atomically replaces dst with candidatePath.
// Before replacing, if dst exists as a regular file, it is safely copied into
// a sibling temp file (using O_NOFOLLOW when reading dst) and atomically
// renamed to dst+".prev" so a malicious symlink at dst+".prev" is never
// followed. After renaming candidatePath to dst and fsyncing the directory,
// postCheck (if non-nil) is invoked on dst; if postCheck fails, ActivateBinary
// automatically rolls back dst from dst+".prev" (or removes dst if new).
func ActivateBinary(candidatePath, dst string, postCheck func(string) error) error {
	dir := filepath.Dir(dst)
	prevPath := dst + ".prev"
	hadPrev := false

	// Preserve existing regular file safely without following symlinks on src or .prev.
	if fi, serr := os.Lstat(dst); serr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlink destination %s", dst)
		}
		if fi.Mode().IsRegular() {
			if cerr := copyFileAtomicNoFollow(dst, prevPath); cerr != nil {
				return fmt.Errorf("preserving previous binary: %w", cerr)
			}
			hadPrev = true
		}
	}

	if err := os.Rename(candidatePath, dst); err != nil {
		return fmt.Errorf("installing binary: %w", err)
	}
	syncDir(dir)

	if postCheck != nil {
		if err := postCheck(dst); err != nil {
			// Automatic rollback on post-swap verification failure.
			if hadPrev {
				if rerr := os.Rename(prevPath, dst); rerr != nil {
					return fmt.Errorf("post-install verification failed (%v) AND rollback failed (%v)", err, rerr)
				}
				syncDir(dir)
				return fmt.Errorf("post-install verification failed (rolled back to previous binary): %w", err)
			}
			_ = os.Remove(dst)
			syncDir(dir)
			return fmt.Errorf("post-install verification failed (removed failed binary): %w", err)
		}
	}
	return nil
}

// DownloadAndVerify downloads the binary at artifactURL, verifies its SHA256
// against expected (hex string), and atomically installs it at dst with mode
// 0755. The previous binary is safely preserved as dst+".prev" without
// following symlinks. For full pre-swap and post-swap binary validation with
// automatic rollback, use DownloadValidateAndInstall.
func DownloadAndVerify(ctx context.Context, client *http.Client, artifactURL, expected, dst string) error {
	dir := filepath.Dir(dst)
	tmpName, err := DownloadToTemp(ctx, client, artifactURL, expected, dir)
	if err != nil {
		return err
	}
	if err := ActivateBinary(tmpName, dst, nil); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// DownloadValidateAndInstall downloads artifactURL into dst's directory,
// verifies SHA256, runs pre-swap candidate validation (`version --json` +
// manifest commit/protocol/schema check), safely preserves dst+".prev",
// atomically activates dst, and runs post-swap validation with automatic
// rollback on failure.
func DownloadValidateAndInstall(ctx context.Context, client *http.Client, artifactURL, expected, dst string, manifest *ReleaseManifest) error {
	dir := filepath.Dir(dst)
	tmpName, err := DownloadToTemp(ctx, client, artifactURL, expected, dir)
	if err != nil {
		return err
	}
	if err := ValidateBinaryCandidate(ctx, tmpName, manifest); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("pre-swap validation failed: %w", err)
	}
	if err := ActivateBinary(tmpName, dst, func(installed string) error {
		return ValidateBinaryCandidate(ctx, installed, manifest)
	}); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// copyFileAtomicNoFollow opens src with O_NOFOLLOW (verifying regular file),
// copies it into a fresh temp file in dst's directory, fsyncs it, and
// atomically renames it onto dst. A symlink at dst is atomically replaced
// rather than followed.
func copyFileAtomicNoFollow(src, dst string) error {
	fd, err := syscall.Open(src, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	in := os.NewFile(uintptr(fd), src)
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", src)
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".ocliv-prev-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	syncDir(dir)
	cleanup = false
	return nil
}

func syncDir(dir string) {
	if dh, err := os.Open(dir); err == nil {
		_ = dh.Sync()
		_ = dh.Close()
	}
}
