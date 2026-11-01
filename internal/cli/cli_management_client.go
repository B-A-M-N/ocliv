// Signed relay management client used by tunnel lifecycle commands.
package cli

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/config"
	"ocliv/internal/identity"
)

// mgmtHTTPClient builds the HTTP client for signed relay management
// (route register/delete, lease close) and local MCP discovery probing.
// It honors the OCLIV_CACERT lab bundle exactly like the agent transport:
// without it, every HTTPS management call against a private-CA edge
// (e.g. Caddy `tls internal`) fails while the tunnel itself attaches
// fine, so route registration silently never happens. A set-but-broken
// bundle is an error, never a silent downgrade; unset keeps default
// verification. Verification is never disabled.
func mgmtHTTPClient(timeout time.Duration) (*http.Client, error) {
	pool, err := config.CertPool()
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: timeout}
	if pool != nil {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}}
	}
	return client, nil
}

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
	client, err := mgmtHTTPClient(15 * time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: unreadable OCLIV_CACERT bundle: "+err.Error())
		return 0, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, body
}
