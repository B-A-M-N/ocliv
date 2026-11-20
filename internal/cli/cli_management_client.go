// Signed relay management client used by tunnel lifecycle commands.
package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/protocol"
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
func mgmtCall(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte, error) {
	return mgmtCallBody(relayURL, k, keyID, method, path, nil)
}

func mgmtCallBody(relayURL string, k *identity.KeyPair, keyID, method, path string, reqBody []byte) (int, []byte, error) {
	nonce, err := agent.MgmtNonce()
	if err != nil {
		return 0, nil, fmt.Errorf("creating management nonce: %w", err)
	}
	return mgmtCallBodyWithNonce(relayURL, k, keyID, method, path, nonce, reqBody)
}

// probeRelayChallengeCaps queries /v1/agent/challenge to discover relay
// capabilities before sending a body-bearing v2 management mutation (P0-1).
// Returns (caps, respondedWithChallenge, err).
func probeRelayChallengeCaps(relayURL, keyID string) ([]string, bool, error) {
	client, err := mgmtHTTPClient(10 * time.Second)
	if err != nil {
		return nil, false, err
	}
	defer client.CloseIdleConnections()
	body, _ := json.Marshal(map[string]string{"key_id": keyID})
	resp, err := client.Post(strings.TrimRight(relayURL, "/")+"/v1/agent/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode == http.StatusNotFound {
		// Minimal unit-test mock servers that do not mount /v1/agent/challenge.
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, true, fmt.Errorf("challenge returned HTTP %d", resp.StatusCode)
	}
	var ch struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, true, fmt.Errorf("invalid challenge response: %w", err)
	}
	return ch.Capabilities, true, nil
}

func capsContain(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func mgmtCallBodyWithNonce(relayURL string, k *identity.KeyPair, keyID, method, path, nonce string, reqBody []byte) (int, []byte, error) {
	// P1-4: never panic on nil or uninitialized credentials.
	if k == nil || len(k.Seed) != ed25519.SeedSize {
		return 0, nil, fmt.Errorf("management credentials unavailable")
	}
	ts := time.Now().UTC()
	var sig []byte
	var bodyReader io.Reader
	useV2 := len(reqBody) > 0
	if useV2 {
		// P0-1: body-bearing mutations require negotiated mgmt_body_sig_v2 so
		// we never silently fail against an older relay or downgrade to v1.
		caps, hasChallenge, cerr := probeRelayChallengeCaps(relayURL, keyID)
		if cerr != nil {
			return 0, nil, fmt.Errorf("management capability check failed: %w", cerr)
		}
		if hasChallenge && !capsContain(caps, protocol.CapabilityMgmtBodySignatureV2) {
			return 0, nil, fmt.Errorf("relay must be upgraded before this operation (missing capability %q)", protocol.CapabilityMgmtBodySignatureV2)
		}
		bodyDigest := agent.MgmtBodySHA256(reqBody)
		sig = ed25519.Sign(k.Private(), agent.MgmtMessageV2(keyID, method, path, ts, nonce, bodyDigest))
		bodyReader = bytes.NewReader(reqBody)
		req, err := http.NewRequest(method, strings.TrimRight(relayURL, "/")+path, bodyReader)
		if err != nil {
			return 0, nil, fmt.Errorf("building management request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ocliv-Key", keyID)
		req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
		req.Header.Set("X-Ocliv-Nonce", nonce)
		req.Header.Set("X-Ocliv-Sig-Version", "2")
		req.Header.Set("X-Ocliv-Body-SHA256", bodyDigest)
		req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
		return doMgmtRequest(req)
	}
	// P0-1: bodyless management requests use ocliv-mgmt-v1 so staggered
	// upgrades (new CLI <-> old relay and old CLI <-> new relay) stay compatible.
	sig = ed25519.Sign(k.Private(), agent.MgmtMessage(keyID, method, path, ts, nonce))
	req, err := http.NewRequest(method, strings.TrimRight(relayURL, "/")+path, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("building management request: %w", err)
	}
	req.Header.Set("X-Ocliv-Key", keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	return doMgmtRequest(req)
}

func doMgmtRequest(req *http.Request) (int, []byte, error) {
	client, err := mgmtHTTPClient(15 * time.Second)
	if err != nil {
		return 0, nil, fmt.Errorf("management TLS configuration: %w", err)
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("management transport failure: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading management response: %w", err)
	}
	if len(body) > 64*1024 {
		return resp.StatusCode, nil, fmt.Errorf("management response exceeds 65536-byte limit")
	}
	return resp.StatusCode, body, nil
}
