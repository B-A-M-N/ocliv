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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	return KeyIDFor(k.Public())
}

// KeyIDFor derives the stable key identifier from a raw Ed25519 public key.
func KeyIDFor(pub ed25519.PublicKey) KeyID {
	sum := sha256.Sum256(pub)
	return KeyID(hex.EncodeToString(sum[:KeyIDBytes]))
}

// Save durably writes the seed with owner-only permissions using
// O_CREATE|O_EXCL|O_NOFOLLOW, fsyncs the file, and fsyncs the parent directory
// (P0-2, B08). Refuses to overwrite an existing file or follow a symlink.
func (k *KeyPair) Save(path string) error {
	if k == nil || len(k.Seed) != ed25519.SeedSize {
		return apperr.E(apperr.CodeInternal, "cannot save invalid agent key", nil)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.E(apperr.CodeInternal, "creating agent key directory", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return apperr.E(apperr.CodeInternal, "agent key exists; refusing to overwrite (use logout first)", err)
		}
		return apperr.E(apperr.CodeInternal, "creating agent key", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(path)
		}
	}()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return apperr.E(apperr.CodeInternal, "agent key target is not a regular file", err)
	}
	encoded := base64.StdEncoding.EncodeToString(k.Seed)
	if _, err := io.WriteString(f, encoded); err != nil {
		_ = f.Close()
		return apperr.E(apperr.CodeInternal, "writing agent key", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return apperr.E(apperr.CodeInternal, "setting agent key permissions", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return apperr.E(apperr.CodeInternal, "syncing agent key", err)
	}
	if err := f.Close(); err != nil {
		return apperr.E(apperr.CodeInternal, "closing agent key", err)
	}
	if err := syncParentDir(dir); err != nil {
		return apperr.E(apperr.CodeInternal, "syncing agent key directory", err)
	}
	cleanup = false
	return nil
}

// SaveDurableReplace atomically and durably replaces path with k using a
// staged 0600 file + fsync + rename + parent-dir fsync (P0-2). Used for
// crash-safe key rotation after remote commit.
func (k *KeyPair) SaveDurableReplace(path string) error {
	if k == nil || len(k.Seed) != ed25519.SeedSize {
		return apperr.E(apperr.CodeInternal, "cannot save invalid agent key", nil)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.E(apperr.CodeInternal, "creating agent key directory", err)
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return apperr.E(apperr.CodeInternal, "refusing to replace symlinked agent key", nil)
	}
	tmp, err := os.CreateTemp(dir, ".agent-key-replace-*")
	if err != nil {
		return apperr.E(apperr.CodeInternal, "staging replacement agent key", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return apperr.E(apperr.CodeInternal, "chmod replacement agent key", err)
	}
	if _, err := io.WriteString(tmp, base64.StdEncoding.EncodeToString(k.Seed)); err != nil {
		_ = tmp.Close()
		return apperr.E(apperr.CodeInternal, "writing replacement agent key", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return apperr.E(apperr.CodeInternal, "syncing replacement agent key", err)
	}
	if err := tmp.Close(); err != nil {
		return apperr.E(apperr.CodeInternal, "closing replacement agent key", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return apperr.E(apperr.CodeInternal, "renaming replacement agent key", err)
	}
	if err := syncParentDir(dir); err != nil {
		return apperr.E(apperr.CodeInternal, "syncing agent key directory after rename", err)
	}
	return nil
}

func syncParentDir(dir string) error {
	dfd, err := os.Open(dir)
	if err != nil {
		return err
	}
	serr := dfd.Sync()
	cerr := dfd.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// Load reads a key file via a single O_NOFOLLOW file descriptor, verifying
// regular-file type and owner-only 0600 permissions before reading (P0-2, B08).
func Load(path string) (*KeyPair, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, apperr.E(apperr.CodeEnrollAuth, "no agent enrollment found; run `ocliv login` first", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, apperr.E(apperr.CodeEnrollAuth, "stat agent key", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, apperr.E(apperr.CodeEnrollAuth, "agent key is not a regular file", nil)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, apperr.E(apperr.CodeEnrollAuth,
			fmt.Sprintf("agent key %s has unsafe permissions %o; want 0600", path, fi.Mode().Perm()), nil)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 256))
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
