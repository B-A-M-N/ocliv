// Persistent visitor-session HMAC key storage (P0-4, P0-5, P1-5).
//
// Browser visitor cookies are signed with an HMAC-SHA256 server key. Persisting
// that 256-bit key in <dataDir>/visitor-hmac.key (mode 0600) ensures real relay
// restarts and machine reboots preserve existing protected visitor sessions
// without re-authentication.
//
// Security invariants:
//   - Existing key loads use O_NOFOLLOW + f.Stat() checking regular file,
//     owner-only mode (0600), expected UID, and exact hex length.
//   - First-start creation uses O_CREATE|O_EXCL so concurrent startups race
//     cleanly and the loser loads the winner's key rather than overwriting it.
//   - RotateVisitorKey preserves existing file (or dataDir) uid/gid ownership
//     so operator/root rotation never bricks the ocliv service account on restart.
package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const visitorKeyFileName = "visitor-hmac.key"

// VisitorKeyFingerprint returns the non-secret SHA-256 hex fingerprint of a
// 32-byte visitor HMAC key (bound into DB/restore continuity checks).
func VisitorKeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// LoadOrCreateVisitorKey loads a durable 32-byte HMAC key from
// <dataDir>/visitor-hmac.key with strict symlink/mode/owner verification,
// or creates one race-freely via O_CREATE|O_EXCL.
func LoadOrCreateVisitorKey(dataDir string) ([]byte, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("visitor key dataDir is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating relay data dir: %w", err)
	}
	path := filepath.Join(dataDir, visitorKeyFileName)
	key, err := readVisitorKeyStrict(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var raw [32]byte
	if _, rerr := rand.Read(raw[:]); rerr != nil {
		return nil, fmt.Errorf("generating visitor HMAC key: %w", rerr)
	}
	encoded := hex.EncodeToString(raw[:]) + "\n"
	f, oerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if oerr != nil {
		if errors.Is(oerr, os.ErrExist) {
			return readVisitorKeyStrict(path)
		}
		return nil, fmt.Errorf("creating visitor HMAC key: %w", oerr)
	}
	if _, werr := io.WriteString(f, encoded); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("writing visitor HMAC key: %w", werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("syncing visitor HMAC key: %w", serr)
	}
	if cerr := f.Close(); cerr != nil {
		return nil, fmt.Errorf("closing visitor HMAC key: %w", cerr)
	}
	if derr := syncDir(dataDir); derr != nil {
		return nil, derr
	}
	return raw[:], nil
}

// targetVisitorKeyOwner resolves the uid/gid that visitor-hmac.key MUST retain
// across rotation: the existing key file's owner (via O_NOFOLLOW fstat), or
// the dataDir owner if no key file exists yet (P0-5).
func targetVisitorKeyOwner(dataDir, keyPath string) (uid, gid int, hasOwner bool, err error) {
	if f, oerr := os.OpenFile(keyPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); oerr == nil {
		st, serr := f.Stat()
		_ = f.Close()
		if serr != nil {
			return 0, 0, false, fmt.Errorf("stat existing visitor HMAC key: %w", serr)
		}
		if !st.Mode().IsRegular() {
			return 0, 0, false, fmt.Errorf("existing visitor HMAC key %s is not a regular file", keyPath)
		}
		if statT, ok := st.Sys().(*syscall.Stat_t); ok {
			return int(statT.Uid), int(statT.Gid), true, nil
		}
		return 0, 0, false, nil
	} else if !errors.Is(oerr, os.ErrNotExist) {
		return 0, 0, false, fmt.Errorf("opening existing visitor HMAC key: %w", oerr)
	}
	if st, serr := os.Stat(dataDir); serr == nil {
		if statT, ok := st.Sys().(*syscall.Stat_t); ok {
			return int(statT.Uid), int(statT.Gid), true, nil
		}
	}
	return 0, 0, false, nil
}

// RotateVisitorKey explicitly replaces <dataDir>/visitor-hmac.key with a fresh
// 256-bit key while preserving existing file/dataDir uid/gid ownership so a
// root-invoked rotation never breaks the ocliv service account on restart (P0-5).
func RotateVisitorKey(dataDir string) ([]byte, error) {
	return rotateVisitorKeyWithChown(dataDir, func(f *os.File, uid, gid int) error {
		return f.Chown(uid, gid)
	})
}

func rotateVisitorKeyWithChown(dataDir string, chownFn func(*os.File, int, int) error) ([]byte, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("visitor key dataDir is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating relay data dir: %w", err)
	}
	path := filepath.Join(dataDir, visitorKeyFileName)
	wantUID, wantGID, hasOwner, err := targetVisitorKeyOwner(dataDir, path)
	if err != nil {
		return nil, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("generating visitor HMAC key: %w", err)
	}
	encoded := hex.EncodeToString(raw[:]) + "\n"
	tmp, err := os.CreateTemp(dataDir, ".visitor-hmac-*")
	if err != nil {
		return nil, fmt.Errorf("staging visitor HMAC key: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if hasOwner {
		if cerr := chownFn(tmp, wantUID, wantGID); cerr != nil {
			_ = tmp.Close()
			return nil, fmt.Errorf("preserving visitor HMAC key ownership (%d:%d): %w", wantUID, wantGID, cerr)
		}
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := io.WriteString(tmp, encoded); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("installing rotated visitor HMAC key: %w", err)
	}
	if err := syncDir(dataDir); err != nil {
		return nil, err
	}
	// Post-rotation verification: regular file, 0600, decodes to 32 bytes.
	verified, err := readVisitorKeyStrictAnyOwner(path, hasOwner, wantUID, wantGID)
	if err != nil {
		return nil, fmt.Errorf("verifying rotated visitor HMAC key: %w", err)
	}
	return verified, nil
}

func readVisitorKeyStrict(path string) ([]byte, error) {
	return readVisitorKeyStrictAnyOwner(path, false, 0, 0)
}

func readVisitorKeyStrictAnyOwner(path string, checkExactOwner bool, wantUID, wantGID int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat visitor HMAC key: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("visitor HMAC key %s must be a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("visitor HMAC key %s has unsafe mode %04o (want 0600)", path, st.Mode().Perm())
	}
	if statT, ok := st.Sys().(*syscall.Stat_t); ok {
		if checkExactOwner {
			if int(statT.Uid) != wantUID || int(statT.Gid) != wantGID {
				return nil, fmt.Errorf("visitor HMAC key %s owner is %d:%d (expected %d:%d)", path, statT.Uid, statT.Gid, wantUID, wantGID)
			}
		} else {
			euid := uint32(os.Geteuid())
			if statT.Uid != euid && statT.Uid != 0 {
				return nil, fmt.Errorf("visitor HMAC key %s owned by uid %d (expected %d)", path, statT.Uid, euid)
			}
		}
	}
	if st.Size() < 64 || st.Size() > 128 {
		return nil, fmt.Errorf("visitor HMAC key %s has invalid size %d", path, st.Size())
	}
	raw, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return nil, fmt.Errorf("reading visitor HMAC key: %w", err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("visitor HMAC key %s is corrupt (want 64 hex chars)", path)
	}
	return decoded, nil
}

func syncDir(dir string) error {
	dfd, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("syncing dir %s: %w", dir, err)
	}
	serr := dfd.Sync()
	cerr := dfd.Close()
	if serr != nil {
		return fmt.Errorf("syncing dir %s: %w", dir, serr)
	}
	return cerr
}
