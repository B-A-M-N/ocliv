package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/store"
)

func newArtifactServer(t *testing.T, artifactDir string, manifestJSON []byte) *Server {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{
		DB:                  db,
		Namespace:           "t.example.test",
		ReleaseManifestJSON: manifestJSON,
		ReleaseArtifactDir:  artifactDir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func artifactManifest(t *testing.T, artifacts map[string][]byte) ([]byte, string) {
	t.Helper()
	dir := t.TempDir()
	entries := map[string]interface{}{}
	for name, content := range artifacts {
		h := sha256.Sum256(content)
		entries[name] = map[string]string{"sha256": hex.EncodeToString(h[:])}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	m := map[string]interface{}{
		"commit":      "abc",
		"dirty":       false,
		"govulncheck": "pass",
		"artifacts":   entries,
	}
	b, _ := json.Marshal(m)
	return b, dir
}

func TestIsValidArtifactName(t *testing.T) {
	valid := []string{
		"ocliv-linux-amd64",
		"ocliv-linux-arm64",
		"ocliv-darwin-amd64",
	}
	invalid := []string{
		"",
		"sbom.cdx.json",
		"../etc/passwd",
		"ocliv-linux-amd64/foo",
		"ocliv%2flinux-amd64",
		".hidden",
		"notocliv-linux-amd64",
		"ocliv-linux amd64",
	}
	for _, n := range valid {
		if !isValidArtifactName(n) {
			t.Errorf("expected %q to be valid", n)
		}
	}
	for _, n := range invalid {
		if isValidArtifactName(n) {
			t.Errorf("expected %q to be invalid", n)
		}
	}
}

func TestHandleReleaseArtifactGET(t *testing.T) {
	content := []byte("fake-binary-content")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	s := newArtifactServer(t, dir, manifestJSON)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/ocliv-artifacts/ocliv-linux-amd64", nil)
	w := httptest.NewRecorder()
	s.handleReleaseArtifact(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != string(content) {
		t.Errorf("body mismatch: got %q", w.Body.String())
	}
}

func TestHandleReleaseArtifactHEAD(t *testing.T) {
	content := []byte("fake-binary-content")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	s := newArtifactServer(t, dir, manifestJSON)

	r := httptest.NewRequest(http.MethodHead, "/.well-known/ocliv-artifacts/ocliv-linux-amd64", nil)
	w := httptest.NewRecorder()
	s.handleReleaseArtifact(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD should have no body")
	}
}

func TestHandleReleaseArtifactUndeclared(t *testing.T) {
	content := []byte("fake-binary-content")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	// Add an extra file that is NOT in the manifest.
	_ = os.WriteFile(filepath.Join(dir, "ocliv-linux-arm64"), []byte("other"), 0644)
	s := newArtifactServer(t, dir, manifestJSON)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/ocliv-artifacts/ocliv-linux-arm64", nil)
	w := httptest.NewRecorder()
	s.handleReleaseArtifact(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for undeclared artifact, got %d", w.Code)
	}
}

func TestHandleReleaseArtifactTraversal(t *testing.T) {
	content := []byte("data")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	s := newArtifactServer(t, dir, manifestJSON)

	for _, path := range []string{
		"/../etc/passwd",
		"../etc/passwd",
		"ocliv%2flinux-amd64",
		"ocliv-linux-amd64/../../etc",
	} {
		r := httptest.NewRequest(http.MethodGet, "/.well-known/ocliv-artifacts/"+path, nil)
		w := httptest.NewRecorder()
		s.handleReleaseArtifact(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("traversal %q: expected 404, got %d", path, w.Code)
		}
	}
}

func TestHandleReleaseArtifactMethodNotAllowed(t *testing.T) {
	content := []byte("data")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	s := newArtifactServer(t, dir, manifestJSON)

	r := httptest.NewRequest(http.MethodPost, "/.well-known/ocliv-artifacts/ocliv-linux-amd64", nil)
	w := httptest.NewRecorder()
	s.handleReleaseArtifact(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleReleaseArtifactSBOMNotServed(t *testing.T) {
	content := []byte("data")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	// SBOM is in the separate "sbom" field, not "artifacts" — the endpoint must not serve it.
	_ = os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), []byte("sbom-data"), 0644)
	s := newArtifactServer(t, dir, manifestJSON)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/ocliv-artifacts/sbom.cdx.json", nil)
	w := httptest.NewRecorder()
	s.handleReleaseArtifact(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for SBOM request, got %d", w.Code)
	}
}

func TestValidateArtifactDirSHA256(t *testing.T) {
	dir := t.TempDir()
	content := []byte("artifact-bytes")
	if err := os.WriteFile(filepath.Join(dir, "ocliv-linux-amd64"), content, 0644); err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(content)
	goodHash := hex.EncodeToString(h[:])
	badHash := strings.Repeat("0", 64)

	// Correct hash passes.
	manifest, _ := json.Marshal(map[string]interface{}{
		"artifacts": map[string]interface{}{
			"ocliv-linux-amd64": map[string]string{"sha256": goodHash},
		},
	})
	if err := validateArtifactDir(manifest, dir); err != nil {
		t.Errorf("expected no error with correct hash: %v", err)
	}

	// Wrong hash fails.
	manifestBad, _ := json.Marshal(map[string]interface{}{
		"artifacts": map[string]interface{}{
			"ocliv-linux-amd64": map[string]string{"sha256": badHash},
		},
	})
	if err := validateArtifactDir(manifestBad, dir); err == nil {
		t.Error("expected error with wrong hash, got nil")
	}

	// SBOM in manifest top-level field does not cause validation failure.
	manifestWithSBOM, _ := json.Marshal(map[string]interface{}{
		"artifacts": map[string]interface{}{
			"ocliv-linux-amd64": map[string]string{"sha256": goodHash},
		},
		"sbom": map[string]string{"sha256": "ignored", "name": "sbom.cdx.json"},
	})
	if err := validateArtifactDir(manifestWithSBOM, dir); err != nil {
		t.Errorf("SBOM field should not affect artifact validation: %v", err)
	}
}

func TestValidateArtifactDirMissingFile(t *testing.T) {
	dir := t.TempDir()
	manifest, _ := json.Marshal(map[string]interface{}{
		"artifacts": map[string]interface{}{
			"ocliv-linux-amd64": map[string]string{"sha256": strings.Repeat("a", 64)},
		},
	})
	err := validateArtifactDir(manifest, dir)
	if err == nil {
		t.Error("expected error for missing artifact file, got nil")
	}
}

func TestValidateArtifactDirInvalidName(t *testing.T) {
	dir := t.TempDir()
	manifest, _ := json.Marshal(map[string]interface{}{
		"artifacts": map[string]interface{}{
			"sbom.cdx.json": map[string]string{"sha256": strings.Repeat("a", 64)},
		},
	})
	err := validateArtifactDir(manifest, dir)
	if err == nil {
		t.Error("expected error for invalid artifact name, got nil")
	}
}
