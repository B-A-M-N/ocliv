package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactName(t *testing.T) {
	cases := []struct{ goos, goarch, want string }{
		{"linux", "amd64", "ocliv-linux-amd64"},
		{"linux", "arm64", "ocliv-linux-arm64"},
		{"darwin", "amd64", "ocliv-darwin-amd64"},
		{"darwin", "arm64", "ocliv-darwin-arm64"},
	}
	for _, c := range cases {
		if got := ArtifactName(c.goos, c.goarch); got != c.want {
			t.Errorf("ArtifactName(%q,%q)=%q want %q", c.goos, c.goarch, got, c.want)
		}
	}
}

func TestFetchManifestValid(t *testing.T) {
	m := ReleaseManifest{
		Commit:      "abc123",
		Dirty:       false,
		BuildTime:   "2026-11-21T00:00:00Z",
		Govulncheck: "pass",
		Artifacts: map[string]ArtifactEntry{
			"ocliv-linux-amd64": {SHA256: "deadbeef"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer srv.Close()
	got, err := FetchManifest(context.Background(), srv.Client(), srv.URL+"/manifest.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Commit != "abc123" {
		t.Errorf("commit=%q want abc123", got.Commit)
	}
	if _, ok := got.Artifacts["ocliv-linux-amd64"]; !ok {
		t.Error("missing artifact entry")
	}
}

func TestFetchManifestDirtyRefused(t *testing.T) {
	m := ReleaseManifest{Dirty: true, Artifacts: map[string]ArtifactEntry{"x": {}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer srv.Close()
	_, err := FetchManifest(context.Background(), srv.Client(), srv.URL+"/manifest.json")
	if err == nil {
		t.Fatal("expected error for dirty build, got nil")
	}
}

func TestFetchManifest404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, err := FetchManifest(context.Background(), srv.Client(), srv.URL+"/manifest.json")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestDownloadAndVerifyMatchingDigest(t *testing.T) {
	content := []byte("fake ocliv binary content")
	sum := sha256.Sum256(content)
	expected := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "ocliv")
	err := DownloadAndVerify(context.Background(), srv.Client(), srv.URL+"/ocliv-linux-amd64", expected, dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading installed binary: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch")
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("mode=%o want 755", fi.Mode().Perm())
	}
}

func TestDownloadAndVerifyBadDigest(t *testing.T) {
	content := []byte("fake binary")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "ocliv")
	err := DownloadAndVerify(context.Background(), srv.Client(), srv.URL+"/ocliv", "0000000000000000000000000000000000000000000000000000000000000000", dst)
	if err == nil {
		t.Fatal("expected digest mismatch error, got nil")
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Error("dst should not exist after digest mismatch")
	}
}
