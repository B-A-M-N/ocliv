// Package identity owns agent Ed25519 identity, enrollment grants, and the
// challenge-response handshake (invariants B02-B09). It is the sole
// authority for agent authentication decisions.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"ocliv/internal/apperr"
)

// Handshake domain separation. Never sign ambiguous payloads (B06).
const (
	SignDomain      = "ocliv-agent-v1"
	NonceBytes      = 32
	NonceTTL        = 2 * time.Minute
	ClockSkewBound  = 5 * time.Minute
	KeyIDBytes      = 8
	EnrollmentBytes = 16
)

// KeyID is a short public identifier for an agent key.
type KeyID string

// KeyPair is an enrolled agent identity.
type KeyPair struct {
	Seed []byte // 32-byte ed25519 seed, 0600 on disk
}

// Generate creates a fresh keypair from the system CSPRNG.
func Generate() (*KeyPair, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, apperr.E(apperr.CodeInternal, "CSPRNG failure generating agent key", err)
	}
	return &KeyPair{Seed: seed}, nil
}

// Private returns the ed25519 private key.
func (k *KeyPair) Private() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(k.Seed)
}

// Public returns the ed25519 public key.
func (k *KeyPair) Public() ed25519.PublicKey {
	return k.Private().Public().(ed25519.PublicKey)
}

// ID derives the stable key identifier.
func (k *KeyPair) ID() KeyID {
	sum := sha256.Sum256(k.Public())
	return KeyID(hex.EncodeToString(sum[:KeyIDBytes]))
}

// Save writes the seed with owner-only permissions (B08). Refuses to
// overwrite an existing key and refuses unsafe file modes.
func (k *KeyPair) Save(path string) error {
	if _, err := os.Stat(path); err == nil {
		return apperr.E(apperr.CodeInternal, "agent key exists; refusing to overwrite (use logout first)", nil)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k.Seed)), 0o600); err != nil {
		return apperr.E(apperr.CodeInternal, "writing agent key", err)
	}
	return nil
}

// Load reads a key file, failing closed on unreadable or unsafe files (B08).
func Load(path string) (*KeyPair, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, apperr.E(apperr.CodeEnrollAuth, "no agent enrollment found; run `ocliv login` first", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, apperr.E(apperr.CodeEnrollAuth,
			fmt.Sprintf("agent key %s has unsafe permissions %o; want 0600", path, fi.Mode().Perm()), nil)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, apperr.E(apperr.CodeEnrollAuth, "reading agent key", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, apperr.E(apperr.CodeEnrollAuth, "agent key is corrupt", nil)
	}
	return &KeyPair{Seed: seed}, nil
}

// Challenge is a one-time server nonce bound to an origin and version.
type Challenge struct {
	Nonce     []byte
	Origin    string // relay origin the session is bound to, e.g. https://relay.example.com
	Version   string
	ExpiresAt time.Time
}

// NewChallenge mints a fresh unpredictable nonce (B07).
func NewChallenge(origin, version string) (*Challenge, error) {
	nonce := make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, apperr.E(apperr.CodeInternal, "CSPRNG failure minting challenge", err)
	}
	return &Challenge{Nonce: nonce, Origin: origin, Version: version, ExpiresAt: time.Now().Add(NonceTTL)}, nil
}

// Sign produces the domain-separated handshake signature (B06):
// domain || nonce || keyID || origin || version || timestamp || leaseIntent
func (k *KeyPair) Sign(nonce []byte, origin, version string, ts time.Time, leaseIntent string) []byte {
	msg := HandshakeMessage(nonce, string(k.ID()), origin, version, ts, leaseIntent)
	return ed25519.Sign(k.Private(), msg)
}

// HandshakeMessage builds the exact signed bytes.
func HandshakeMessage(nonce []byte, keyID, origin, version string, ts time.Time, leaseIntent string) []byte {
	return []byte(fmt.Sprintf("%s\n%x\n%s\n%s\n%s\n%d\n%s",
		SignDomain, nonce, keyID, origin, version, ts.Unix(), leaseIntent))
}

// Verify checks a handshake signature against a known public key.
func Verify(pub ed25519.PublicKey, nonce []byte, keyID, origin, version string, ts time.Time, leaseIntent string, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return apperr.E(apperr.CodeEnrollAuth, "unknown agent key", nil)
	}
	if time.Since(ts).Abs() > ClockSkewBound {
		return apperr.E(apperr.CodeEnrollAuth, "handshake timestamp outside clock-skew bound", nil)
	}
	if !ed25519.Verify(pub, HandshakeMessage(nonce, keyID, origin, version, ts, leaseIntent), sig) {
		return apperr.E(apperr.CodeEnrollAuth, "handshake signature invalid", nil)
	}
	return nil
}

// MintEnrollmentCode creates a one-time operator enrollment grant (B05).
func MintEnrollmentCode() (code string, verifier string, err error) {
	raw := make([]byte, EnrollmentBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", apperr.E(apperr.CodeInternal, "CSPRNG failure minting enrollment code", err)
	}
	code = "ocliv-enroll-" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(code))
	return code, hex.EncodeToString(sum[:]), nil
}

// VerifyEnrollmentCode checks a presented code against a stored verifier.
func VerifyEnrollmentCode(code, verifier string) bool {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:]) == verifier
}
