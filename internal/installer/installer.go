// Package installer downloads and verifies Ocliv release artifacts from a
// relay's well-known manifest endpoint. All writes are atomic: a temp file
// receives the download, its SHA256 is verified, then it is renamed into
// place — a partial or corrupt binary is never installed.
package installer

import (
	"context"
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

// ReleaseManifest matches the dist/*/release-manifest.json format.
type ReleaseManifest struct {
	Commit          string                   `json:"commit"`
	Dirty           bool                     `json:"dirty"`
	BuildTime       string                   `json:"build_time"`
	ProtocolVersion string                   `json:"protocol_version"`
	SchemaVersion   int                      `json:"schema_version"`
	Govulncheck     string                   `json:"govulncheck"`
	Artifacts       map[string]ArtifactEntry `json:"artifacts"`
}

// ArtifactEntry holds provenance data for one platform binary.
type ArtifactEntry struct {
	SHA256 string `json:"sha256"`
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

// FetchManifest downloads and parses the manifest from manifestURL.
// It returns an error if the manifest is missing, malformed, or the build
// is dirty (a dirty binary has non-reproducible provenance).
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
	return &m, nil
}

// DownloadAndVerify downloads the binary at artifactURL, verifies its SHA256
// against expected (hex string), and installs it at dst with mode 0755.
// The write is atomic: a temp file in the same directory receives the download,
// the digest is verified, then it is renamed into place — dst is never touched
// unless the digest matches.
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
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("installing binary: %w", err)
	}
	return nil
}
