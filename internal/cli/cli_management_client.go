// Signed relay management client used by tunnel lifecycle commands.
package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/identity"
)

// mgmtCall performs a signed agent management request. Mutations carry a
// one-time nonce the relay consumes; without a fresh nonce the relay
// rejects the call as a potential replay (P1-07).
func mgmtCall(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte) {
	ts := time.Now().UTC()
	nonce, err := agent.MgmtNonce()
	if err != nil {
		return 0, nil
	}
	sig := ed25519.Sign(k.Private(), agent.MgmtMessage(keyID, method, path, ts, nonce))
	req, _ := http.NewRequest(method, strings.TrimRight(relayURL, "/")+path, nil)
	req.Header.Set("X-Ocliv-Key", keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, body
}
