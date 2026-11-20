// Signed relay management client wrappers delegating to internal/control.
package cli

import (
	"net/http"
	"time"

	"ocliv/internal/control"
	"ocliv/internal/identity"
)

func mgmtHTTPClient(timeout time.Duration) (*http.Client, error) {
	return control.HTTPClient(timeout)
}

func mgmtCall(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte, error) {
	return control.NewClient(relayURL, k, keyID).Call(method, path)
}

func mgmtCallBody(relayURL string, k *identity.KeyPair, keyID, method, path string, reqBody []byte) (int, []byte, error) {
	return control.NewClient(relayURL, k, keyID).CallBody(method, path, reqBody)
}

func mgmtCallBodyWithNonce(relayURL string, k *identity.KeyPair, keyID, method, path, nonce string, reqBody []byte) (int, []byte, error) {
	return control.NewClient(relayURL, k, keyID).CallBodyWithNonce(method, path, nonce, reqBody)
}
