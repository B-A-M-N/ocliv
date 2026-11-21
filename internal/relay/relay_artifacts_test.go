package relay

import (
	"crypto/ed25519"
	"crypto/rand"
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifestJSON)
	s, err := New(Options{
		DB:                  db,
		Namespace:           "t.example.test",
		ReleaseManifestJSON: manifestJSON,
		ReleaseManifestSig:  sig,
		ReleaseArtifactDir:  artifactDir,
		ReleaseVerifyKeys:   []ed25519.PublicKey{pub},
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
		"manifest_version": 1,
		"release_sequence": 1,
		"commit":           "abc",
		"dirty":            false,
		"govulncheck":      "pass",
		"artifacts":        entries,
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

func TestReleaseConfigCoherence(t *testing.T) {
	content := []byte("fake-binary")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	goodSig := ed25519.Sign(priv, manifestJSON)
	badSig := make([]byte, ed25519.SignatureSize)

	newDB := func(t *testing.T) *store.DB {
		t.Helper()
		db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}

	cases := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name:    "none configured is valid (disabled)",
			opts:    Options{Namespace: "t.example.test"},
			wantErr: false,
		},
		{
			name:    "manifest only rejected",
			opts:    Options{Namespace: "t.example.test", ReleaseManifestJSON: manifestJSON},
			wantErr: true,
		},
		{
			name:    "artifact dir only rejected",
			opts:    Options{Namespace: "t.example.test", ReleaseArtifactDir: dir},
			wantErr: true,
		},
		{
			name:    "sig only rejected",
			opts:    Options{Namespace: "t.example.test", ReleaseManifestSig: goodSig},
			wantErr: true,
		},
		{
			name:    "manifest + artifact dir without sig rejected",
			opts:    Options{Namespace: "t.example.test", ReleaseManifestJSON: manifestJSON, ReleaseArtifactDir: dir},
			wantErr: true,
		},
		{
			name:    "manifest + artifact dir + bad sig rejected",
			opts:    Options{Namespace: "t.example.test", ReleaseManifestJSON: manifestJSON, ReleaseArtifactDir: dir, ReleaseManifestSig: badSig, ReleaseVerifyKeys: []ed25519.PublicKey{pub}},
			wantErr: true,
		},
		{
			name:    "complete valid signed tuple accepted",
			opts:    Options{Namespace: "t.example.test", ReleaseManifestJSON: manifestJSON, ReleaseArtifactDir: dir, ReleaseManifestSig: goodSig, ReleaseVerifyKeys: []ed25519.PublicKey{pub}},
			wantErr: false,
		},
		{
			name:    "explicit AllowUnsignedRelease with manifest + dir accepted",
			opts:    Options{Namespace: "t.example.test", ReleaseManifestJSON: manifestJSON, ReleaseArtifactDir: dir, AllowUnsignedRelease: true},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.opts.AllowUnsignedRelease {
				t.Setenv("OCLIV_ENV", "development")
			}
			tc.opts.DB = newDB(t)
			_, err := New(tc.opts)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHandleReleaseArtifactSymlinkReplacementRefused(t *testing.T) {
	content := []byte("valid-binary")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	s := newArtifactServer(t, dir, manifestJSON)

	// Replace valid artifact with a symlink after startup validation.
	target := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	artPath := filepath.Join(dir, "ocliv-linux-amd64")
	if err := os.Remove(artPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, artPath); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/.well-known/ocliv-artifacts/ocliv-linux-amd64", nil)
	w := httptest.NewRecorder()
	s.handleReleaseArtifact(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("symlinked artifact must be refused (404), got %d", w.Code)
	}
}

func TestAllowUnsignedDevReleaseRefusedOnPublicRelayHost(t *testing.T) {
	content := []byte("fake-binary")
	manifestJSON, dir := artifactManifest(t, map[string][]byte{
		"ocliv-linux-amd64": content,
	})
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// 1. Public host + OCLIV_ENV=development MUST fail.
	t.Setenv("OCLIV_ENV", "development")
	if _, err := New(Options{
		DB:                   db,
		Namespace:            "t.prod.example",
		RelayHost:            "relay.prod.example",
		ReleaseManifestJSON:  manifestJSON,
		ReleaseArtifactDir:   dir,
		AllowUnsignedRelease: true,
	}); err == nil {
		t.Fatal("expected error for AllowUnsignedRelease on public RelayHost even with OCLIV_ENV=development")
	}

	// 2. Loopback host + production env (OCLIV_ENV="") MUST fail.
	t.Setenv("OCLIV_ENV", "")
	if _, err := New(Options{
		DB:                   db,
		Namespace:            "t.stage.local",
		RelayHost:            "127.0.0.1",
		ReleaseManifestJSON:  manifestJSON,
		ReleaseArtifactDir:   dir,
		AllowUnsignedRelease: true,
	}); err == nil {
		t.Fatal("expected error for AllowUnsignedRelease on loopback without OCLIV_ENV=development")
	}

	// 3. Loopback host + OCLIV_ENV=development + explicit flag succeeds and reports UNSIGNED_DEVELOPMENT.
	t.Setenv("OCLIV_ENV", "development")
	s, err := New(Options{
		DB:                   db,
		Namespace:            "t.stage.local",
		RelayHost:            "127.0.0.1",
		ReleaseManifestJSON:  manifestJSON,
		ReleaseArtifactDir:   dir,
		AllowUnsignedRelease: true,
	})
	if err != nil {
		t.Fatalf("unexpected error on loopback dev host: %v", err)
	}
	if st := s.StatusSnapshot(); st.ReleaseTrustMode != "UNSIGNED_DEVELOPMENT" {
		t.Fatalf("ReleaseTrustMode=%q, want UNSIGNED_DEVELOPMENT", st.ReleaseTrustMode)
	}
	// Verify release manifest and artifacts are authorized through s.Handler() on relayHost (not 421).
	req := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/.well-known/ocliv-release-manifest.json", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET manifest via Handler() on relayHost: got %d, want 200", rec.Code)
	}
	req2 := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/.well-known/ocliv-artifacts/ocliv-linux-amd64", nil)
	req2.Host = "127.0.0.1"
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET artifact via Handler() on relayHost: got %d, want 200", rec2.Code)
	}
}

func TestNonProductionManifestRejectedEvenWithValidSignature(t *testing.T) {
	dir := t.TempDir()
	binContent := []byte("fake-binary")
	if err := os.WriteFile(filepath.Join(dir, "ocliv-linux-amd64"), binContent, 0o644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(binContent)
	manifestJSON, _ := json.Marshal(map[string]any{
		"commit":         "abc",
		"dirty":          false,
		"non_production": true,
		"govulncheck":    "pass",
		"artifacts":      map[string]any{"ocliv-linux-amd64": map[string]string{"sha256": hex.EncodeToString(h[:])}},
	})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, manifestJSON)
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := New(Options{
		DB:                  db,
		Namespace:           "t.example.test",
		RelayHost:           "relay.example.test",
		ReleaseManifestJSON: manifestJSON,
		ReleaseManifestSig:  sig,
		ReleaseArtifactDir:  dir,
		ReleaseVerifyKeys:   []ed25519.PublicKey{pub},
	}); err == nil {
		t.Fatal("non_production=true manifest must be rejected even with a valid signature from a trusted key")
	}

	// Missing manifest_version or release_sequence must also be rejected in production mode.
	for _, tc := range []struct {
		name string
		m    map[string]any
	}{
		{"missing manifest_version", map[string]any{"release_sequence": 1, "commit": "abc", "dirty": false, "govulncheck": "pass", "artifacts": map[string]any{"ocliv-linux-amd64": map[string]string{"sha256": hex.EncodeToString(h[:])}}}},
		{"missing release_sequence", map[string]any{"manifest_version": 1, "commit": "abc", "dirty": false, "govulncheck": "pass", "artifacts": map[string]any{"ocliv-linux-amd64": map[string]string{"sha256": hex.EncodeToString(h[:])}}}},
	} {
		raw, _ := json.Marshal(tc.m)
		msig := ed25519.Sign(priv, raw)
		if _, err := New(Options{
			DB:                  db,
			Namespace:           "t.example.test",
			RelayHost:           "relay.example.test",
			ReleaseManifestJSON: raw,
			ReleaseManifestSig:  msig,
			ReleaseArtifactDir:  dir,
			ReleaseVerifyKeys:   []ed25519.PublicKey{pub},
		}); err == nil {
			t.Fatalf("%s must be rejected in production mode", tc.name)
		}
	}
}

func TestValidateArtifactDirVerifiesProvenanceSBOM(t *testing.T) {
	dir := t.TempDir()
	bin := []byte("bin-data")
	sbom := []byte(`{"bomFormat":"CycloneDX"}`)
	_ = os.WriteFile(filepath.Join(dir, "ocliv-linux-amd64"), bin, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), sbom, 0o644)
	hb := sha256.Sum256(bin)
	hs := sha256.Sum256(sbom)

	goodManifest, _ := json.Marshal(map[string]any{
		"artifacts": map[string]any{"ocliv-linux-amd64": map[string]string{"sha256": hex.EncodeToString(hb[:])}},
		"provenance": map[string]any{
			"sbom": map[string]string{
				"format": "cyclonedx-json",
				"file":   "sbom.cdx.json",
				"sha256": hex.EncodeToString(hs[:]),
			},
		},
	})
	if err := validateArtifactDir(goodManifest, dir); err != nil {
		t.Fatalf("valid provenance SBOM should pass: %v", err)
	}

	// Tamper SBOM on disk -> startup validation MUST fail.
	_ = os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), []byte(`{"tampered":true}`), 0o644)
	if err := validateArtifactDir(goodManifest, dir); err == nil {
		t.Fatal("tampered provenance SBOM must fail validateArtifactDir")
	}
}
