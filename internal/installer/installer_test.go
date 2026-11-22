package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
		ManifestVersion: 1,
		ReleaseSequence: 1,
		Commit:          "abc123",
		Dirty:           false,
		ProtocolVersion: "ocliv/1",
		SchemaVersion:   22,
		Govulncheck:     "pass",
		Artifacts:       map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}},
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

func TestFetchManifestSignedRejectsNonProductionEvenWithValidSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := ReleaseManifest{
		Commit:        "abc123",
		Dirty:         false,
		NonProduction: true,
		Govulncheck:   "pass",
		Artifacts:     map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}},
	}
	manifestBytes, _ := json.Marshal(m)
	sigHex := hex.EncodeToString(ed25519.Sign(priv, manifestBytes))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json.sig" {
			_, _ = w.Write([]byte(sigHex))
			return
		}
		_, _ = w.Write(manifestBytes)
	}))
	defer srv.Close()

	if _, err := FetchManifestSigned(context.Background(), srv.Client(), srv.URL+"/manifest.json", pub); err == nil {
		t.Fatal("FetchManifestSigned must reject non_production=true even with a valid signature")
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

func TestReleaseSequenceAntiRollback(t *testing.T) {
	seqPath := filepath.Join(t.TempDir(), ".ocliv-release-seq")
	if err := CheckReleaseSequence(seqPath, 100, false); err != nil {
		t.Fatalf("initial sequence should pass: %v", err)
	}
	if err := RecordReleaseSequence(seqPath, 100); err != nil {
		t.Fatalf("record sequence: %v", err)
	}
	// Equal or higher sequence allowed.
	if err := CheckReleaseSequence(seqPath, 100, false); err != nil {
		t.Fatalf("equal sequence should pass: %v", err)
	}
	if err := CheckReleaseSequence(seqPath, 200, false); err != nil {
		t.Fatalf("higher sequence should pass: %v", err)
	}
	// Lower sequence MUST be rejected without override.
	if err := CheckReleaseSequence(seqPath, 99, false); err == nil {
		t.Fatal("lower release_sequence must be refused without allowDowngrade")
	}
	// Explicit override allows downgrade.
	if err := CheckReleaseSequence(seqPath, 99, true); err != nil {
		t.Fatalf("explicit allowDowngrade should pass: %v", err)
	}
	// Symlink sequence file must be refused.
	symDir := t.TempDir()
	victim := filepath.Join(symDir, "victim")
	_ = os.WriteFile(victim, []byte("1\n"), 0o600)
	symSeq := filepath.Join(symDir, ".ocliv-release-seq")
	_ = os.Symlink(victim, symSeq)
	if err := CheckReleaseSequence(symSeq, 100, false); err == nil {
		t.Fatal("symlink release sequence file must be refused")
	}
	// Non-positive sequence must be refused.
	if err := CheckReleaseSequence(seqPath, 0, false); err == nil {
		t.Fatal("non-positive release_sequence must be refused")
	}
	// Immutable identity on equal sequence: same identity allowed, different commit or SHA refused.
	idSeqPath := filepath.Join(t.TempDir(), ".ocliv-release-seq")
	if err := RecordReleaseSequenceIdentity(idSeqPath, 50, "commit-a", "sha-a"); err != nil {
		t.Fatalf("record identity: %v", err)
	}
	if err := CheckReleaseSequenceIdentity(idSeqPath, 50, "commit-a", "sha-a", false); err != nil {
		t.Fatalf("idempotent reinstall with identical identity should pass: %v", err)
	}
	if err := CheckReleaseSequenceIdentity(idSeqPath, 50, "commit-b", "sha-a", false); err == nil {
		t.Fatal("same release_sequence with different commit must be refused")
	}
	if err := CheckReleaseSequenceIdentity(idSeqPath, 50, "commit-a", "sha-b", false); err == nil {
		t.Fatal("same release_sequence with different artifact_sha256 must be refused")
	}
	if err := CheckReleaseSequenceIdentity(idSeqPath, 51, "commit-b", "sha-b", false); err != nil {
		t.Fatalf("higher sequence with new identity should pass: %v", err)
	}
}

func TestFetchManifestSignedRejectsMissingVersionOrSequence(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name string
		m    ReleaseManifest
	}{
		{
			name: "missing manifest_version",
			m:    ReleaseManifest{ReleaseSequence: 10, Commit: "abc", ProtocolVersion: "ocliv/1", SchemaVersion: 22, Govulncheck: "pass", Artifacts: map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}}},
		},
		{
			name: "missing release_sequence",
			m:    ReleaseManifest{ManifestVersion: 1, Commit: "abc", ProtocolVersion: "ocliv/1", SchemaVersion: 22, Govulncheck: "pass", Artifacts: map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}}},
		},
		{
			name: "missing schema_version",
			m:    ReleaseManifest{ManifestVersion: 1, ReleaseSequence: 10, Commit: "abc", ProtocolVersion: "ocliv/1", Govulncheck: "pass", Artifacts: map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}}},
		},
		{
			name: "missing protocol_version",
			m:    ReleaseManifest{ManifestVersion: 1, ReleaseSequence: 10, Commit: "abc", SchemaVersion: 22, Govulncheck: "pass", Artifacts: map[string]ArtifactEntry{"ocliv-linux-amd64": {SHA256: "deadbeef"}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.m)
			sigHex := hex.EncodeToString(ed25519.Sign(priv, raw))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/manifest.json.sig" {
					_, _ = w.Write([]byte(sigHex))
					return
				}
				_, _ = w.Write(raw)
			}))
			defer srv.Close()
			if _, err := FetchManifestSigned(context.Background(), srv.Client(), srv.URL+"/manifest.json", pub); err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
		})
	}
}

func TestInstallClientScriptMultiKeyRotationAndPinning(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("install-client.sh test runs on Linux only")
	}
	shell := "/bin/sh"
	if dashPath, err := exec.LookPath("dash"); err == nil {
		shell = dashPath
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		if _, err2 := exec.LookPath("wget"); err2 != nil {
			t.Skip("neither curl nor wget installed")
		}
	}

	// Generate 3 distinct Ed25519 keys whose IDs intentionally contain 'n'
	// (regression test for the old broken POSIX IFS='\n' splitting bug).
	pubActive, privActive, _ := ed25519.GenerateKey(rand.Reader)
	pubRetiring, privRetiring, _ := ed25519.GenerateKey(rand.Reader)
	pubRevoked, privRevoked, _ := ed25519.GenerateKey(rand.Reader)

	origScript, err := os.ReadFile(filepath.Join("..", "..", "packaging", "install", "install-client.sh"))
	if err != nil {
		t.Fatalf("read install-client.sh: %v", err)
	}
	const beginMarker = "# BEGIN GENERATED TRUST ROOT (from internal/installer/release-trust.json)"
	const endMarker = "# END GENERATED TRUST ROOT"
	s := string(origScript)
	bi := strings.Index(s, beginMarker)
	ei := strings.Index(s, endMarker)
	if bi < 0 || ei < 0 || ei <= bi {
		t.Fatal("install-client.sh missing generated trust root markers")
	}
	trustBlock := fmt.Sprintf(
		"%s\nTRUSTED_RELEASE_KEYS='active-n-key|active|%s\nretiring-n-key|retiring|%s\nrevoked-n-key|revoked|%s'\n%s",
		beginMarker,
		hex.EncodeToString(pubActive),
		hex.EncodeToString(pubRetiring),
		hex.EncodeToString(pubRevoked),
		endMarker,
	)
	patched := s[:bi] + trustBlock + s[ei+len(endMarker):]
	tmpDir := t.TempDir()
	scriptCopy := filepath.Join(tmpDir, "install-client.sh")
	if err := os.WriteFile(scriptCopy, []byte(patched), 0o755); err != nil {
		t.Fatal(err)
	}

	// Build a fake ocliv executable that responds to `version --json` with full metadata.
	const commitSHA = "deadbeef1234567890"
	goodBin := []byte(fmt.Sprintf("#!/bin/sh\necho '{\"version\":\"0.0.0-test\",\"build_commit\":\"%s\",\"dirty\":false,\"protocol_version\":\"ocliv/1\",\"schema_version\":22}'\n", commitSHA))
	curBin := goodBin
	artifact := ArtifactName(runtime.GOOS, runtime.GOARCH)

	var curManifest []byte
	var curSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocliv-release-manifest.json":
			_, _ = w.Write(curManifest)
		case "/.well-known/ocliv-release-manifest.json.sig":
			_, _ = w.Write([]byte(curSig))
		case "/.well-known/ocliv-artifacts/" + artifact:
			_, _ = w.Write(curBin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	makeSignedFull := func(signingKeyID string, seq int64, schema int, proto string, bin []byte, signer ed25519.PrivateKey) ([]byte, string) {
		curBin = bin
		sum := sha256.Sum256(bin)
		m := map[string]any{
			"manifest_version": 1,
			"release_sequence": seq,
			"commit":           commitSHA,
			"dirty":            false,
			"govulncheck":      "pass",
			"artifacts": map[string]any{
				artifact: map[string]any{"sha256": hex.EncodeToString(sum[:])},
			},
		}
		if schema > 0 {
			m["schema_version"] = schema
		}
		if proto != "" {
			m["protocol_version"] = proto
		}
		if signingKeyID != "" {
			m["signing_key_id"] = signingKeyID
		}
		raw, _ := json.MarshalIndent(m, "", "  ")
		raw = append(raw, '\n')
		sig := hex.EncodeToString(ed25519.Sign(signer, raw))
		return raw, sig
	}
	makeSigned := func(signingKeyID string, seq int64, signer ed25519.PrivateKey) ([]byte, string) {
		return makeSignedFull(signingKeyID, seq, 22, "ocliv/1", goodBin, signer)
	}

	runInstall := func(instDir string, extraEnv ...string) (int, string) {
		cmd := exec.Command(shell, scriptCopy, srv.URL)
		cmd.Env = append(os.Environ(), "OCLIV_INSTALL_DIR="+instDir)
		cmd.Env = append(cmd.Env, extraEnv...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode(), string(out)
			}
			return -1, string(out) + err.Error()
		}
		return 0, string(out)
	}

	instDir := filepath.Join(tmpDir, "inst")

	// 1. Missing signing_key_id must be rejected.
	curManifest, curSig = makeSigned("", 10, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("missing signing_key_id should fail, got rc=0: %s", out)
	}

	// 2. Unknown signing_key_id must be rejected.
	curManifest, curSig = makeSigned("unknown-n-key", 10, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("unknown signing_key_id should fail, got rc=0: %s", out)
	}

	// 3. Revoked key must be rejected.
	curManifest, curSig = makeSigned("revoked-n-key", 10, privRevoked)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("revoked signing_key_id should fail, got rc=0: %s", out)
	}

	// 4. Wrong signing_key_id (declared active, signed by retiring) must be rejected.
	curManifest, curSig = makeSigned("active-n-key", 10, privRetiring)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("mismatched signing_key_id/signature should fail, got rc=0: %s", out)
	}

	// 5. Valid retiring key must succeed.
	curManifest, curSig = makeSigned("retiring-n-key", 10, privRetiring)
	if rc, out := runInstall(instDir); rc != 0 {
		t.Fatalf("retiring-n-key install failed (rc=%d): %s", rc, out)
	}

	// 6. Valid active key with higher release_sequence must succeed.
	curManifest, curSig = makeSigned("active-n-key", 20, privActive)
	if rc, out := runInstall(instDir); rc != 0 {
		t.Fatalf("active-n-key install failed (rc=%d): %s", rc, out)
	}

	// 7. Release sequence downgrade (20 -> 15) must be refused without OCLIV_ALLOW_DOWNGRADE=1.
	curManifest, curSig = makeSigned("active-n-key", 15, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("release_sequence downgrade should fail, got rc=0: %s", out)
	}

	// 8. Test trust override without OCLIV_ALLOW_TEST_TRUST=1 must be refused.
	curManifest, curSig = makeSigned("active-n-key", 20, privActive)
	if rc, out := runInstall(instDir, "OCLIV_TEST_SIGNING_PUBLIC_KEY_PEM=dummy"); rc == 0 {
		t.Fatalf("test trust override without OCLIV_ALLOW_TEST_TRUST=1 should fail, got rc=0: %s", out)
	}

	// 9. Missing release_sequence (0) must be refused.
	curManifest, curSig = makeSigned("active-n-key", 0, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("release_sequence=0 should fail, got rc=0: %s", out)
	}

	// 10. Symlink .ocliv-release-seq must be refused.
	symDir := filepath.Join(tmpDir, "sym-inst")
	_ = os.MkdirAll(symDir, 0o755)
	_ = os.Symlink("/etc/hosts", filepath.Join(symDir, ".ocliv-release-seq"))
	curManifest, curSig = makeSigned("active-n-key", 20, privActive)
	if rc, out := runInstall(symDir); rc == 0 {
		t.Fatalf("symlink .ocliv-release-seq should fail, got rc=0: %s", out)
	}

	// 11. Fail-closed negatives: missing dirty, malformed dirty, missing schema_version, missing protocol_version.
	missingDirtyBin := []byte(fmt.Sprintf("#!/bin/sh\necho '{\"version\":\"0.0.0-test\",\"build_commit\":\"%s\",\"protocol_version\":\"ocliv/1\",\"schema_version\":22}'\n", commitSHA))
	curManifest, curSig = makeSignedFull("active-n-key", 30, 22, "ocliv/1", missingDirtyBin, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("binary missing dirty field should fail, got rc=0: %s", out)
	}

	malformedDirtyBin := []byte(fmt.Sprintf("#!/bin/sh\necho '{\"version\":\"0.0.0-test\",\"build_commit\":\"%s\",\"dirty\":\"no\",\"protocol_version\":\"ocliv/1\",\"schema_version\":22}'\n", commitSHA))
	curManifest, curSig = makeSignedFull("active-n-key", 30, 22, "ocliv/1", malformedDirtyBin, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("binary with malformed dirty field should fail, got rc=0: %s", out)
	}

	curManifest, curSig = makeSignedFull("active-n-key", 30, 0, "ocliv/1", goodBin, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("manifest missing schema_version should fail, got rc=0: %s", out)
	}

	curManifest, curSig = makeSignedFull("active-n-key", 30, 22, "", goodBin, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("manifest missing protocol_version should fail, got rc=0: %s", out)
	}

	// 12. Same release_sequence (20) with identical identity succeeds (idempotent reinstall),
	//     but same release_sequence (20) with different binary bytes MUST be rejected.
	curManifest, curSig = makeSignedFull("active-n-key", 20, 22, "ocliv/1", goodBin, privActive)
	if rc, out := runInstall(instDir); rc != 0 {
		t.Fatalf("idempotent reinstall at seq=20 should pass, got rc=%d: %s", rc, out)
	}
	altBin := append(append([]byte{}, goodBin...), []byte("# alt\n")...)
	curManifest, curSig = makeSignedFull("active-n-key", 20, 22, "ocliv/1", altBin, privActive)
	if rc, out := runInstall(instDir); rc == 0 {
		t.Fatalf("same release_sequence=20 with different artifact_sha256 must be rejected, got rc=0: %s", out)
	}
}

func TestValidateBinaryCandidateRejectsMissingDirty(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake")
	_ = os.WriteFile(bin, []byte("#!/bin/sh\necho '{\"version\":\"1.0.0\",\"build_commit\":\"abc\",\"protocol_version\":\"ocliv/1\",\"schema_version\":22}'\n"), 0o755)
	m := &ReleaseManifest{Commit: "abc", ProtocolVersion: "ocliv/1", SchemaVersion: 22}
	if err := ValidateBinaryCandidate(context.Background(), bin, m); err == nil {
		t.Fatal("ValidateBinaryCandidate must reject binary missing dirty field")
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
