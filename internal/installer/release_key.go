package installer

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// productionPublicKeyHex is the hex-encoded Ed25519 public key used to verify
// all official ocliv release manifests. Replace this placeholder with the real
// key before production shipping.
//
// To generate a key pair:
//
//	openssl genpkey -algorithm ed25519 -out signing.key
//	openssl pkey -in signing.key -pubout -outform DER | tail -c 32 | xxd -p -cols 32
//
// The placeholder value (all zeros) is intentionally invalid: it will fail
// every real signature check, preventing silent acceptance of an unsigned
// or wrongly-signed manifest.
const productionPublicKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"

// ProductionPublicKey returns the decoded production signing key.
// Panics at program start if the embedded hex is not valid or the wrong length.
// Using a typed constant avoids the -X ldflags limitation on []byte variables.
func ProductionPublicKey() ed25519.PublicKey {
	b, err := hex.DecodeString(productionPublicKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("installer: embedded productionPublicKeyHex is invalid: %v", err))
	}
	return ed25519.PublicKey(b)
}
