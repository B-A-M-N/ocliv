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

// probeRelayCapabilities discovers relay protocol capabilities before sending
// a body-bearing v2 management mutation (A4, P0-1). It prefers the read-only
// GET /v1/agent/capabilities endpoint (so no attachment challenge nonce is
// wasted), falling back to POST /v1/agent/challenge ONLY when capabilities
// returns 404 on an older relay. Any 404 on both, 500, malformed response, or
// transport error fails closed — NEVER permitting an unnegotiated mutation.
func probeRelayCapabilities(relayURL, keyID string) ([]string, error) {
	client, err := mgmtHTTPClient(10 * time.Second)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	base := strings.TrimRight(relayURL, "/")

	// 1) Preferred read-only capabilities endpoint (allocates zero nonces).
	resp, err := client.Get(base + "/v1/agent/capabilities")
	if err != nil {
		return nil, err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var capsResp struct {
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal(raw, &capsResp); err != nil {
			return nil, fmt.Errorf("invalid capabilities response: %w", err)
		}
		return capsResp.Capabilities, nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return nil, fmt.Errorf("capabilities endpoint returned HTTP %d", resp.StatusCode)
	}

	// 2) Fallback to /v1/agent/challenge for relays that predate /v1/agent/capabilities.
	body, _ := json.Marshal(map[string]string{"key_id": keyID})
	cResp, err := client.Post(base+"/v1/agent/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer cResp.Body.Close()
	cRaw, _ := io.ReadAll(io.LimitReader(cResp.Body, 16*1024))
	if cResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("challenge capability discovery returned HTTP %d", cResp.StatusCode)
	}
	var ch struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(cRaw, &ch); err != nil {
		return nil, fmt.Errorf("invalid challenge response: %w", err)
	}
	return ch.Capabilities, nil
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
		// A4 / P0-1: body-bearing mutations strictly require negotiated
		// mgmt_body_sig_v2. Any discovery failure (404, 500, malformed,
		// unreachable, or missing capability) fails closed BEFORE sending the
		// mutation request.
		caps, cerr := probeRelayCapabilities(relayURL, keyID)
		if cerr != nil {
			return 0, nil, fmt.Errorf("management capability check failed: %w", cerr)
		}
		if !capsContain(caps, protocol.CapabilityMgmtBodySignatureV2) {
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
