// Command metis-idp is TEST-ONLY scaffold — not product code. It is a
// minimal RS256 JWT issuer designed to mint access tokens that Metis's
// “metis mcp serve-http“ transport accepts, so the Ocliv→Metis
// composed OAuth integration test can be exercised without a real IdP.
//
// Metis (mcp_http.go) accepts ONLY RS256/ES256 signed JWTs (HS256 is
// rejected as "unsupported token alg"), requires a kid header, fetches
// the key from a JWKS (URL or file) with a 5-minute cache, and per
// request verifies:
//   - iss                     equals METIS_MCP_ISSUER exactly
//   - sub                     non-empty
//   - aud (string or array)   equals the exact resource URL
//   - exp                     required, with a 60s leeway
//   - nbf                     optional, with a 60s leeway
//   - scope / scp             space-separated; one of
//     metis:message | metis:provision |
//     metis:input | metis:stop (nothing implies
//     another)
//
// This tool implements two verbs:
//
//	metis-idp genkey -dir DIR [-kid t1] [-force]
//	  Generate a fresh 2048-bit RSA keypair and write, into an existing
//	  DIR:
//	    DIR/key.pem    PKCS#8 private key (mode 0600)
//	    DIR/jwks.json  JWKS document (mode 0600) for METIS_MCP_JWKS_FILE
//	  and print the absolute jwks.json path on stdout. Refuses to
//	  overwrite an existing key unless -force.
//
//	metis-idp token <flags> ...
//	  Mint one RS256 JWT and print it on stdout. Real-sign the header+
//	  payload with the given RSA private key. Every claim is
//	  configurable so the same tool can mint deliberately BAD tokens
//	  for negative tests (wrong aud/iss, expired, future nbf, unknown
//	  kid, HS256, malformed, missing/insufficient scope).
//
// Safety: stdlib only, loopback-friendly, no network egress, never
// reads or writes outside the caller-chosen paths. Key material and
// JWKS are written 0600 inside a caller-supplied private dir.
package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	defaultIss   = "https://idp.example/oauth"
	defaultAud   = "https://relay.example/r/abc/mcp"
	defaultKid   = "t1"
	defaultSub   = "op-1"
	defaultScope = "metis:message"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "metis-idp: "+format+"\n", args...)
	os.Exit(2)
}

func usage() {
	fmt.Fprint(os.Stderr, `metis-idp — TEST-ONLY RS256 JWT issuer for the Metis MCP transport

usage:
  metis-idp genkey -dir DIR [-kid t1] [-force]
      write DIR/key.pem + DIR/jwks.json; print the jwks.json path

  metis-idp token -privkey PEM [-iss URL] [-sub S] [-aud URL] [-scope S]
      [-exp SECS] [-nbf SECS] [-kid ID] [-alg ALG] [-no-scope] [-malformed]
      mint one JWT to stdout (RS256 real-sign unless -alg changes it)

negative-token recipes (each requires its own -privkey):
  wrong audience     -aud https://evil.example/r/other/mcp
  wrong issuer       -iss https://evil.example/oauth
  expired            -exp -60
  not-yet-valid      -nbf 7200
  unknown kid        -kid no-such-key
  HS256 (rejected)   -alg HS256
  missing scope      -no-scope
  insufficient scope -scope metis:read   (not one Metis grants)
  malformed          -malformed          (corrupted signature segment)
`)
}

func cmdGenkey(args []string) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	dir := fs.String("dir", "", "existing output directory")
	kid := fs.String("kid", defaultKid, "JWKS key id")
	force := fs.Bool("force", false, "overwrite an existing key/JWKS")
	_ = fs.Parse(args)

	if *dir == "" {
		fatalf("genkey: -dir is required")
	}
	keyPath := *dir + "/key.pem"
	jwksPath := *dir + "/jwks.json"
	if !*force {
		if _, err := os.Stat(keyPath); err == nil || os.IsExist(err) {
			fatalf("genkey: %s already exists (use -force to replace)", keyPath)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("genkey: rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fatalf("genkey: marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writePrivate(keyPath, keyPEM); err != nil {
		fatalf("genkey: %v", err)
	}

	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": *kid, "alg": "RS256", "use": "sig",
		"n": b64(key.N.Bytes()),
		"e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}}
	raw, err := json.Marshal(jwks)
	if err != nil {
		fatalf("genkey: marshal jwks: %v", err)
	}
	if err := os.WriteFile(jwksPath, raw, 0o600); err != nil {
		fatalf("genkey: %v", err)
	}
	fmt.Println(jwksPath)
}

const pkgLabel = "test-only metis-idp scaffold (not product code)"

func writePrivate(path string, pemBytes []byte) error {
	return os.WriteFile(path, pemBytes, 0o600)
}

func loadPrivKey(path string) *rsa.PrivateKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalf("token: read private key %s: %v", path, err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		fatalf("token: %s is not a PKCS#8 PRIVATE KEY PEM", path)
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		fatalf("token: parse private key %s: %v", path, err)
	}
	key, ok := anyKey.(*rsa.PrivateKey)
	if !ok {
		fatalf("token: %s does not hold an RSA private key", path)
	}
	return key
}

func cmdToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	privkey := fs.String("privkey", "", "path to PKCS#8 RSA private key PEM (from genkey)")
	iss := fs.String("iss", defaultIss, "issuer claim (must equal METIS_MCP_ISSUER for Metis)")
	sub := fs.String("sub", defaultSub, "subject claim (must be non-empty)")
	aud := fs.String("aud", defaultAud, "audience claim (must be the exact resource URL)")
	scope := fs.String("scope", defaultScope, "space-separated scope claim")
	exp := fs.Int("exp", 3600, "token lifetime in seconds from now; negative => already expired")
	nbf := fs.Int("nbf", 0, "nbf in seconds from now; <=0 omits nbf")
	kid := fs.String("kid", defaultKid, "JWT kid header (must resolve in the JWKS)")
	alg := fs.String("alg", "RS256", "JWT alg header (RS256 real-sign; other values are structural negatives)")
	noScope := fs.Bool("no-scope", false, "omit the scope claim entirely")
	malformed := fs.Bool("malformed", false, "corrupt the signature to make a structurally-invalid token")
	_ = fs.Parse(args)

	if *alg == "RS256" && *privkey == "" {
		fatalf("token: -privkey is required for RS256 signing")
	}

	now := time.Now()
	claims := map[string]any{
		"iss": *iss,
		"sub": *sub,
		"aud": *aud,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(*exp) * time.Second).Unix(),
	}
	if *nbf > 0 {
		claims["nbf"] = now.Add(time.Duration(*nbf) * time.Second).Unix()
	}
	if !*noScope {
		claims["scope"] = *scope
	}
	hdr := map[string]string{"alg": *alg, "typ": "JWT", "kid": *kid}

	hs, _ := json.Marshal(hdr)
	ps, _ := json.Marshal(claims)
	hss, pss := b64(hs), b64(ps)
	signingInput := hss + "." + pss

	var token string
	switch *alg {
	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, loadPrivKey(*privkey), crypto.SHA256, digest[:])
		if err != nil {
			fatalf("token: sign: %v", err)
		}
		token = signingInput + "." + b64(sig)
	default:
		// Structural negative: HS256 or any non-RS256 alg. Metis rejects
		// the alg before signature/key lookup, so the signature content
		// is irrelevant; we HMAC with a fixed test string to keep the
		// token well-formed at the three-segment level.
		mac := hmac.New(sha256.New, []byte(pkgLabel))
		mac.Write([]byte(signingInput))
		token = signingInput + "." + b64(mac.Sum(nil))
	}

	if *malformed {
		// Keep exactly three `.`-separated segments but corrupt the
		// signature to an invalid base64url string so header parses and
		// the signature decode (or verify) fails.
		token = hss + "." + pss + ".$$%NOT-BASE64%%"
	}
	fmt.Println(token)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "genkey":
		cmdGenkey(os.Args[2:])
	case "token":
		cmdToken(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "metis-idp: unknown verb %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}
