// Package control implements the signed relay-management HTTP client and
// fail-closed capability negotiation used by CLI and hosting operations.
package control

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

// Client performs signed management requests against a single relay authority.
type Client struct {
	RelayURL string
	Key      *identity.KeyPair
	KeyID    string
	Timeout  time.Duration
}

// NewClient constructs a signed relay-management client bound to relayURL and key.
func NewClient(relayURL string, key *identity.KeyPair, keyID string) *Client {
	return &Client{
		RelayURL: strings.TrimRight(strings.TrimSpace(relayURL), "/"),
		Key:      key,
		KeyID:    keyID,
		Timeout:  15 * time.Second,
	}
}

// HTTPClient builds an HTTP client honoring OCLIV_CACERT without ever
// disabling TLS verification.
func HTTPClient(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
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

// ProbeCapabilities discovers relay protocol capabilities before sending a
// body-bearing v2 management mutation. It prefers the read-only
// GET /v1/agent/capabilities endpoint (allocating zero nonces), falling back
// to POST /v1/agent/challenge ONLY when capabilities returns 404 on an older
// relay. Any 404 on both, 500, malformed response, or transport error fails
// closed.
func (c *Client) ProbeCapabilities() ([]string, error) {
	httpClient, err := HTTPClient(10 * time.Second)
	if err != nil {
		return nil, err
	}
	defer httpClient.CloseIdleConnections()

	resp, err := httpClient.Get(c.RelayURL + "/v1/agent/capabilities")
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

	body, _ := json.Marshal(map[string]string{"key_id": c.KeyID})
	cResp, err := httpClient.Post(c.RelayURL+"/v1/agent/challenge", "application/json", bytes.NewReader(body))
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

// Call performs a bodyless signed management request (ocliv-mgmt-v1).
func (c *Client) Call(method, path string) (int, []byte, error) {
	return c.CallBody(method, path, nil)
}

// CallBody performs a signed management request with an automatically minted nonce.
func (c *Client) CallBody(method, path string, reqBody []byte) (int, []byte, error) {
	nonce, err := agent.MgmtNonce()
	if err != nil {
		return 0, nil, fmt.Errorf("creating management nonce: %w", err)
	}
	return c.CallBodyWithNonce(method, path, nonce, reqBody)
}

// CallBodyWithNonce performs a signed management request with an explicit nonce.
// Body-bearing mutations strictly require negotiated mgmt_body_sig_v2.
func (c *Client) CallBodyWithNonce(method, path, nonce string, reqBody []byte) (int, []byte, error) {
	if c == nil || c.Key == nil || len(c.Key.Seed) != ed25519.SeedSize {
		return 0, nil, fmt.Errorf("management credentials unavailable")
	}
	ts := time.Now().UTC()
	if len(reqBody) > 0 {
		caps, cerr := c.ProbeCapabilities()
		if cerr != nil {
			return 0, nil, fmt.Errorf("management capability check failed: %w", cerr)
		}
		if !capsContain(caps, protocol.CapabilityMgmtBodySignatureV2) {
			return 0, nil, fmt.Errorf("relay must be upgraded before this operation (missing capability %q)", protocol.CapabilityMgmtBodySignatureV2)
		}
		bodyDigest := agent.MgmtBodySHA256(reqBody)
		sig := ed25519.Sign(c.Key.Private(), agent.MgmtMessageV2(c.KeyID, method, path, ts, nonce, bodyDigest))
		req, err := http.NewRequest(method, c.RelayURL+path, bytes.NewReader(reqBody))
		if err != nil {
			return 0, nil, fmt.Errorf("building management request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ocliv-Key", c.KeyID)
		req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
		req.Header.Set("X-Ocliv-Nonce", nonce)
		req.Header.Set("X-Ocliv-Sig-Version", "2")
		req.Header.Set("X-Ocliv-Body-SHA256", bodyDigest)
		req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
		return c.do(req)
	}
	sig := ed25519.Sign(c.Key.Private(), agent.MgmtMessage(c.KeyID, method, path, ts, nonce))
	req, err := http.NewRequest(method, c.RelayURL+path, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("building management request: %w", err)
	}
	req.Header.Set("X-Ocliv-Key", c.KeyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	return c.do(req)
}

func (c *Client) do(req *http.Request) (int, []byte, error) {
	httpClient, err := HTTPClient(c.Timeout)
	if err != nil {
		return 0, nil, fmt.Errorf("management TLS configuration: %w", err)
	}
	defer httpClient.CloseIdleConnections()
	resp, err := httpClient.Do(req)
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

func capsContain(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}
