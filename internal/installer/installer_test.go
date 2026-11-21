package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestProductionPublicKey(t *testing.T) {
	k := ProductionPublicKey()
	if len(k) != ed25519.PublicKeySize {
		t.Fatalf("ProductionPublicKey() returned %d bytes, want %d", len(k), ed25519.PublicKeySize)
	}
}

func TestVerifyManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"commit":"abc","dirty":false}`)
	sig := ed25519.Sign(priv, msg)
	sigHex := hex.EncodeToString(sig)

	if err := VerifyManifest(msg, sigHex, pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Wrong key
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyManifest(msg, sigHex, pub2); err == nil {
		t.Fatal("wrong key should be rejected")
	}

	// Empty sig
	if err := VerifyManifest(msg, "", pub); err == nil {
		t.Fatal("empty signature should be rejected")
	}

	// Malformed hex
	if err := VerifyManifest(msg, "nothex", pub); err == nil {
		t.Fatal("malformed hex should be rejected")
	}

	// Wrong-length key
	if err := VerifyManifest(msg, sigHex, ed25519.PublicKey([]byte("short"))); err == nil {
		t.Fatal("wrong-length key should be rejected")
	}
}

func TestFetchManifestSignedRejectsUnsigned(t *testing.T) {
	// Server that serves manifest but 404s on .sig
	m := ReleaseManifest{
		Commit:      "abc123",
		Dirty:       false,
		Govulncheck: "pass",
		Artifacts:   map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json.sig" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer srv.Close()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err := FetchManifestSigned(context.Background(), srv.Client(), srv.URL+"/manifest.json", pub)
	if err == nil {
		t.Fatal("FetchManifestSigned should reject manifest without .sig")
	}
}

func TestFetchManifestSignedVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := ReleaseManifest{
		Commit:      "abc123",
		Dirty:       false,
		Govulncheck: "pass",
		Artifacts:   map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}},
	}
	manifestBytes, _ := json.Marshal(m)
	manifestBytes = append(manifestBytes, '\n')
	sig := ed25519.Sign(priv, manifestBytes)
	sigHex := hex.EncodeToString(sig)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json.sig" {
			_, _ = w.Write([]byte(sigHex))
			return
		}
		_, _ = w.Write(manifestBytes)
	}))
	defer srv.Close()

	got, err := FetchManifestSigned(context.Background(), srv.Client(), srv.URL+"/manifest.json", pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Commit != "abc123" {
		t.Errorf("commit=%q want abc123", got.Commit)
	}
}

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

func TestVerifyManifestAnyRotation(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	_, priv3, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte(`{"commit":"abc","dirty":false}` + "\n")
	keys := []ed25519.PublicKey{pub1, pub2}

	if err := VerifyManifestAny(msg, hex.EncodeToString(ed25519.Sign(priv1, msg)), keys); err != nil {
		t.Fatalf("key1 should verify: %v", err)
	}
	if err := VerifyManifestAny(msg, hex.EncodeToString(ed25519.Sign(priv2, msg)), keys); err != nil {
		t.Fatalf("key2 should verify: %v", err)
	}
	if err := VerifyManifestAny(msg, hex.EncodeToString(ed25519.Sign(priv3, msg)), keys); err == nil {
		t.Fatal("untrusted key3 should be rejected")
	}
	if err := VerifyManifestAny(msg, hex.EncodeToString(ed25519.Sign(priv1, msg)), nil); err == nil {
		t.Fatal("empty key set should be rejected")
	}
}

func TestActivateBinaryPrevSymlinkNotFollowedAndRollback(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ocliv")
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Plant a malicious symlink at dst+".prev" pointing at victim.
	if err := os.Symlink(victim, dst+".prev"); err != nil {
		t.Fatal(err)
	}
	cand := filepath.Join(dir, "cand")
	if err := os.WriteFile(cand, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Simulate post-swap check failure: must rollback dst to old-binary AND not clobber victim.
	err := ActivateBinary(cand, dst, func(string) error {
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal("expected post-swap failure")
	}
	gotVictim, _ := os.ReadFile(victim)
	if string(gotVictim) != "precious" {
		t.Fatalf("victim file was clobbered through .prev symlink: got %q", gotVictim)
	}
	gotDst, _ := os.ReadFile(dst)
	if string(gotDst) != "old-binary" {
		t.Fatalf("dst was not rolled back: got %q, want old-binary", gotDst)
	}
}

func TestVerifyManifestWithTrustLifecycle(t *testing.T) {
	pubActive, privActive, _ := ed25519.GenerateKey(rand.Reader)
	pubRetiring, privRetiring, _ := ed25519.GenerateKey(rand.Reader)
	pubRevoked, privRevoked, _ := ed25519.GenerateKey(rand.Reader)
	_, privUnknown, _ := ed25519.GenerateKey(rand.Reader)

	tr := TrustRoot{
		SchemaVersion: 1,
		Keys: []TrustedKeyEntry{
			{ID: "k-active", PublicHex: hex.EncodeToString(pubActive), Status: KeyStatusActive},
			{ID: "k-retiring", PublicHex: hex.EncodeToString(pubRetiring), Status: KeyStatusRetiring},
			{ID: "k-revoked", PublicHex: hex.EncodeToString(pubRevoked), Status: KeyStatusRevoked},
		},
	}
	msg := []byte(`{"commit":"abc","dirty":false}` + "\n")

	// Active key accepted.
	if kid, err := VerifyManifestWithTrust(msg, hex.EncodeToString(ed25519.Sign(privActive, msg)), "k-active", tr); err != nil || kid != "k-active" {
		t.Fatalf("active key rejected: kid=%q err=%v", kid, err)
	}
	// Retiring key accepted during overlap.
	if kid, err := VerifyManifestWithTrust(msg, hex.EncodeToString(ed25519.Sign(privRetiring, msg)), "k-retiring", tr); err != nil || kid != "k-retiring" {
		t.Fatalf("retiring key rejected: kid=%q err=%v", kid, err)
	}
	// Revoked key MUST be rejected (with or without explicit signing_key_id).
	if _, err := VerifyManifestWithTrust(msg, hex.EncodeToString(ed25519.Sign(privRevoked, msg)), "k-revoked", tr); err == nil {
		t.Fatal("revoked key with id must be rejected")
	}
	if _, err := VerifyManifestWithTrust(msg, hex.EncodeToString(ed25519.Sign(privRevoked, msg)), "", tr); err == nil {
		t.Fatal("revoked key without id must be rejected")
	}
	// Unknown key MUST be rejected.
	if _, err := VerifyManifestWithTrust(msg, hex.EncodeToString(ed25519.Sign(privUnknown, msg)), "", tr); err == nil {
		t.Fatal("unknown key must be rejected")
	}
}

func TestTrustRootParityWithInstallClientScript(t *testing.T) {
	tr := ProductionTrustRoot()
	scriptPath := filepath.Join("..", "..", "packaging", "install", "install-client.sh")
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("reading install-client.sh: %v", err)
	}
	content := string(raw)
	for _, k := range tr.Keys {
		want := k.ID + "|" + k.Status + "|" + k.PublicHex
		if !containsString(content, want) {
			t.Errorf("install-client.sh missing canonical trust entry %q from release-trust.json", want)
		}
	}
}

func containsString(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexString(s, sub) >= 0
}

func indexString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
