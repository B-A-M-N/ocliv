// Package installer downloads and verifies Ocliv release artifacts from a
// relay's well-known manifest endpoint. All writes are atomic: a temp file
// receives the download, its SHA256 is verified, then it is renamed into
// place — a partial or corrupt binary is never installed.
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
	"path/filepath"
	"strings"
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

// FetchManifest downloads and parses the manifest from manifestURL.
// It fails if the manifest is missing, malformed, dirty, or govulncheck != "pass"
// (unless AllowUnqualifiedRelease is true). No signature verification is
// performed — use FetchManifestSigned when ReleasePublicKey is configured.
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
	sigHexBytes, err := io.ReadAll(io.LimitReader(sigResp.Body, 256))
	if err != nil {
		return nil, fmt.Errorf("signature read: %w", err)
	}
	if err := VerifyManifest(rawManifest, strings.TrimSpace(string(sigHexBytes)), pubKey); err != nil {
		return nil, err
	}

	var m ReleaseManifest
	if err := json.Unmarshal(rawManifest, &m); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
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

// DownloadAndVerify downloads the binary at artifactURL, verifies its SHA256
// against expected (hex string), and installs it at dst with mode 0755.
// The write is atomic: a temp file receives the download, the digest is
// verified, then it is renamed into place. The previous binary is preserved
// as dst+".prev" for rollback. The parent directory is fsynced after install.
func DownloadAndVerify(ctx context.Context, client *http.Client, artifactURL, expected, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return fmt.Errorf("artifact request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("artifact fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("artifact fetch: HTTP %d", resp.StatusCode)
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "ocliv-install-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	limited := io.LimitReader(resp.Body, maxDownloadBytes)
	n, err := io.Copy(io.MultiWriter(tmp, h), limited)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("downloading artifact: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if n >= maxDownloadBytes {
		return fmt.Errorf("artifact exceeds maximum size (%d bytes)", maxDownloadBytes)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("digest mismatch: got %s, expected %s", got, expected)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}

	// Preserve the existing binary as .prev before replacing (best-effort rollback).
	prevPath := dst + ".prev"
	if _, serr := os.Stat(dst); serr == nil {
		if cerr := copyFile(dst, prevPath); cerr != nil {
			return fmt.Errorf("preserving previous binary: %w", cerr)
		}
	}

	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("installing binary: %w", err)
	}

	// Fsync the parent directory to make the rename durable across a crash.
	if dh, err := os.Open(dir); err == nil {
		_ = dh.Sync()
		dh.Close()
	}
	return nil
}

// copyFile copies src to dst (mode 0755), syncing before close.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
