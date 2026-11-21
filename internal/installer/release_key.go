package installer

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed release-trust.json
var embeddedTrustJSON []byte

// Key status constants for release trust root lifecycle.
const (
	KeyStatusActive   = "active"
	KeyStatusRetiring = "retiring"
	KeyStatusRevoked  = "revoked"
)

// TrustedKeyEntry represents one versioned Ed25519 release signing key
// loaded from the canonical release-trust.json trust root.
type TrustedKeyEntry struct {
	ID        string `json:"id"`
	PublicHex string `json:"ed25519"`
	Status    string `json:"status"`
}

// TrustRoot is the canonical non-secret release trust configuration shared
// between the Go installer/relay and the shell bootstrap installer.
type TrustRoot struct {
	SchemaVersion int               `json:"schema_version"`
	Keys          []TrustedKeyEntry `json:"keys"`
}

// ParseTrustRoot decodes and validates a release-trust.json document.
func ParseTrustRoot(raw []byte) (TrustRoot, error) {
	var tr TrustRoot
	if err := json.Unmarshal(raw, &tr); err != nil {
		return TrustRoot{}, fmt.Errorf("parsing release-trust.json: %w", err)
	}
	if len(tr.Keys) == 0 {
		return TrustRoot{}, fmt.Errorf("release-trust.json contains no keys")
	}
	seen := map[string]bool{}
	for _, k := range tr.Keys {
		if strings.TrimSpace(k.ID) == "" {
			return TrustRoot{}, fmt.Errorf("release-trust.json contains key with empty id")
		}
		if seen[k.ID] {
			return TrustRoot{}, fmt.Errorf("release-trust.json contains duplicate key id %q", k.ID)
		}
		seen[k.ID] = true
		b, err := hex.DecodeString(strings.TrimSpace(k.PublicHex))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return TrustRoot{}, fmt.Errorf("release-trust.json key %q has invalid ed25519 hex", k.ID)
		}
		switch k.Status {
		case KeyStatusActive, KeyStatusRetiring, KeyStatusRevoked:
		default:
			return TrustRoot{}, fmt.Errorf("release-trust.json key %q has invalid status %q", k.ID, k.Status)
		}
	}
	return tr, nil
}

// ProductionTrustRoot returns the parsed embedded canonical trust root.
func ProductionTrustRoot() TrustRoot {
	tr, err := ParseTrustRoot(embeddedTrustJSON)
	if err != nil {
		panic("installer: " + err.Error())
	}
	return tr
}

// ProductionPublicKeys returns all non-revoked (active + retiring) decoded
// Ed25519 public keys from the embedded canonical trust root.
func ProductionPublicKeys() []ed25519.PublicKey {
	tr := ProductionTrustRoot()
	keys := make([]ed25519.PublicKey, 0, len(tr.Keys))
	for _, entry := range tr.Keys {
		if entry.Status == KeyStatusRevoked {
			continue
		}
		b, _ := hex.DecodeString(strings.TrimSpace(entry.PublicHex))
		keys = append(keys, ed25519.PublicKey(b))
	}
	if len(keys) == 0 {
		panic("installer: production trust root has no non-revoked keys")
	}
	return keys
}

// ProductionPublicKey returns the primary active production signing key.
func ProductionPublicKey() ed25519.PublicKey {
	return ProductionPublicKeys()[0]
}

// VerifyManifestWithTrust verifies rawManifest + sigHex against tr, enforcing
// key revocation status and optional signingKeyID pinning. Returns the ID of
// the authenticating trusted key on success.
func VerifyManifestWithTrust(rawManifest []byte, sigHex, signingKeyID string, tr TrustRoot) (string, error) {
	if len(tr.Keys) == 0 {
		return "", fmt.Errorf("no trusted release keys configured")
	}
	if sigHex == "" {
		return "", fmt.Errorf("manifest signature missing")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("manifest signature malformed")
	}
	for _, entry := range tr.Keys {
		if signingKeyID != "" && entry.ID != signingKeyID {
			continue
		}
		if entry.Status == KeyStatusRevoked {
			if signingKeyID != "" {
				return "", fmt.Errorf("manifest signing key %q has been revoked", entry.ID)
			}
			continue
		}
		if entry.Status != KeyStatusActive && entry.Status != KeyStatusRetiring {
			continue
		}
		b, derr := hex.DecodeString(strings.TrimSpace(entry.PublicHex))
		if derr != nil || len(b) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(b), rawManifest, sig) {
			return entry.ID, nil
		}
		if signingKeyID != "" {
			return "", fmt.Errorf("manifest signature invalid for signing_key_id %q", entry.ID)
		}
	}
	if signingKeyID != "" {
		return "", fmt.Errorf("manifest signing_key_id %q is not in the trusted key set", signingKeyID)
	}
	return "", fmt.Errorf("manifest signature invalid (not verified by any active/retiring trusted key)")
}
