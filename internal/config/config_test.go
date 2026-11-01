package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCertPool: unset env keeps default verification (nil, nil); a
// missing file and a non-PEM file fail loudly instead of silently
// falling back; a valid bundle loads. Never disables verification.
func TestCertPool(t *testing.T) {
	t.Setenv("OCLIV_CACERT", "")
	if pool, err := CertPool(); err != nil || pool != nil {
		t.Fatalf("unset: pool=%v err=%v, want nil,nil", pool, err)
	}
	t.Setenv("OCLIV_CACERT", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := CertPool(); err == nil {
		t.Fatal("missing bundle accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_CACERT", bad)
	if _, err := CertPool(); err == nil {
		t.Fatal("non-PEM bundle accepted")
	}
	// A valid self-signed bundle loads into a pool that verifies it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(t.TempDir(), "good.pem")
	if err := os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_CACERT", good)
	pool, err := CertPool()
	if err != nil || pool == nil {
		t.Fatalf("valid bundle rejected: pool=%v err=%v", pool, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("loaded pool does not verify its own CA: %v", err)
	}
}

func TestValidatePort(t *testing.T) {
	for _, ok := range []string{"1", "3000", "65535", " 8080 "} {
		if _, err := ValidatePort(ok); err != nil {
			t.Fatalf("port %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "-1", "65536", "abc", "", "1.5"} {
		if _, err := ValidatePort(bad); err == nil {
			t.Fatalf("port %q accepted", bad)
		}
	}
}

func TestCheckRelayTLS(t *testing.T) {
	for _, ok := range []string{
		"https://relay.example.com",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
	} {
		if err := CheckRelayTLS(ok); err != nil {
			t.Fatalf("relay URL %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://relay.example.com",
		"http://192.168.1.10:8080",
		"ws://relay.example.com",
		"not-a-url",
	} {
		if err := CheckRelayTLS(bad); err == nil {
			t.Fatalf("relay URL %q accepted", bad)
		}
	}
}

func TestLoopbackTarget(t *testing.T) {
	if got := LoopbackTarget(3000, false); got != "127.0.0.1:3000" {
		t.Fatalf("ipv4 target = %q", got)
	}
	if got := LoopbackTarget(3000, true); got != "[::1]:3000" {
		t.Fatalf("ipv6 target = %q", got)
	}
}
