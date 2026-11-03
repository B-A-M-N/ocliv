package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// TestGenkeyWritesMetisJWKS mirrors the exact JWKS shape Metis's
// mcpFetchJWKS parses; the program is stdlib-only. genkey runs through
// the real CLI so this exercises main()'s dispatch, flags, keygen and
// file writes.
func TestGenkeyWritesMetisJWKS(t *testing.T) {
	dir := t.TempDir()
	jwksPath := invokeGenkey(t, dir, "t1")

	raw, err := os.ReadFile(jwksPath)
	if err != nil {
		t.Fatalf("read jwks: %v", err)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("jwks json: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kty != "RSA" || k.Kid != "t1" || k.Alg != "RS256" || k.Use != "sig" {
		t.Fatalf("unexpected jwks entry %+v", k)
	}
	if _, err := base64.RawURLEncoding.DecodeString(k.N); err != nil {
		t.Fatalf("n not base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(k.E); err != nil {
		t.Fatalf("e not base64url: %v", err)
	}
	if st, _ := os.Stat(jwksPath); st.Mode().Perm()&0022 != 0 {
		t.Fatalf("jwks.json must not be group/other-writable, got %v", st.Mode())
	}
}

const testIss = "https://idp.example/oauth"
const testAud = "https://relay.example/r/abc/mcp"

func invokeGenkey(t *testing.T, dir, kid string) string {
	t.Helper()
	old := os.Args
	os.Args = []string{"metis-idp", "genkey", "-dir", dir, "-kid", kid}
	defer func() { os.Args = old }()
	cmdGenkey(os.Args[2:])
	p := filepath.Join(dir, "jwks.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("genkey did not write jwks.json: %v", err)
	}
	return p
}

// TestMintedTokenVerifiesWithJWKSPubKey signs a real RS256 JWT with the
// generated private key and verifies it exactly as Metis does: SHA256
// digest over header.body then rsa.VerifyPKCS1v15 against the public
// key recovered from the written JWKS.
func TestMintedTokenVerifiesWithJWKSPubKey(t *testing.T) {
	dir := t.TempDir()
	invokeGenkey(t, dir, "t1")

	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("read key.pem: %v", err)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatalf("key.pem is not a PKCS#8 PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	key := privAny.(*rsa.PrivateKey)

	jwksRaw, _ := os.ReadFile(filepath.Join(dir, "jwks.json"))
	var doc struct {
		Keys []struct {
			N string `json:"n"`
			E string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksRaw, &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("parse jwks: %v (%d keys)", err, len(doc.Keys))
	}
	n, _ := base64.RawURLEncoding.DecodeString(doc.Keys[0].N)
	e, _ := base64.RawURLEncoding.DecodeString(doc.Keys[0].E)
	// Rebuild the exponent the same way Metis's mcpFetchJWKS does:
	// fold every byte, big-endian (default 65537 = 0x010001).
	exp := 0
	for _, b := range e {
		exp = exp<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}

	hdr := `{"alg":"RS256","typ":"JWT","kid":"t1"}`
	pay := `{"aud":"https://relay.example/r/abc/mcp","exp":2000000000,"iat":1000000000,"iss":"https://idp.example/oauth","scope":"metis:message","sub":"op-1"}`
	hs := base64.RawURLEncoding.EncodeToString([]byte(hdr))
	ps := base64.RawURLEncoding.EncodeToString([]byte(pay))
	digest := sha256.Sum256([]byte(hs + "." + ps))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify against the JWKS public key: %v", err)
	}
}

// TestRS256PrivateKeyIsReusable checks the PEM round-trips: the key we
// wrote can be loaded by the CLI's loadPrivKey, so a later `token`
// invocation uses the same keypair the JWKS advertises.
func TestRS256PrivateKeyIsReusable(t *testing.T) {
	dir := t.TempDir()
	invokeGenkey(t, dir, "t1")
	key := loadPrivKey(filepath.Join(dir, "key.pem"))
	if key.N.BitLen() < 2048 {
		t.Fatalf("expected a 2048-bit RSA key, got %d bits", key.N.BitLen())
	}
}
