// Signed relay management client wrappers delegating to internal/control.
package cli

import (
	"fmt"
	"net/http"
	"time"

	"ocliv/internal/control"
	"ocliv/internal/identity"
)

func mgmtHTTPClient(timeout time.Duration) (*http.Client, error) {
	return control.HTTPClient(timeout)
}

func mgmtCall(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte, error) {
	c, err := control.NewClient(relayURL, k, keyID)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid relay URL: %w", err)
	}
	return c.Call(method, path)
}

func mgmtCallBody(relayURL string, k *identity.KeyPair, keyID, method, path string, reqBody []byte) (int, []byte, error) {
	c, err := control.NewClient(relayURL, k, keyID)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid relay URL: %w", err)
	}
	return c.CallBody(method, path, reqBody)
}

func mgmtCallBodyWithNonce(relayURL string, k *identity.KeyPair, keyID, method, path, nonce string, reqBody []byte) (int, []byte, error) {
	c, err := control.NewClient(relayURL, k, keyID)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid relay URL: %w", err)
	}
	return c.CallBodyWithNonce(method, path, nonce, reqBody)
}
