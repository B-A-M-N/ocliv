package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAttachVerifiedIngressHeadersStripsSpoofAndSignsV2(t *testing.T) {
	secret := []byte("ocliv-test-ingress-secret-0123456789")
	now := time.Unix(1700000123, 0).UTC()

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:3000/mcp", nil)
	req.Host = "127.0.0.1:3000"
	// Attempt to spoof verified headers before publisher runs.
	req.Header.Set(HeaderVerifiedSubject, "spoofed-admin")
	req.Header.Set(HeaderIngressSig, "forged-sig")

	// Without a verified relay principal, spoofed headers MUST be stripped and nothing signed.
	AttachVerifiedIngressHeaders(req, secret, "route-1", "", "", now)
	if got := req.Header.Get(HeaderVerifiedSubject); got != "" {
		t.Fatalf("spoofed subject survived stripping: %q", got)
	}
	if got := req.Header.Get(HeaderIngressSig); got != "" {
		t.Fatalf("spoofed sig survived stripping: %q", got)
	}

	// With a verified relay principal + route, publisher attaches valid ocliv-ingress-v2 HMAC.
	AttachVerifiedIngressHeaders(req, secret, "route-1", "client:chatgpt-1", "ocliv:read ocliv:write", now)
	sub := req.Header.Get(HeaderVerifiedSubject)
	route := req.Header.Get(HeaderVerifiedRoute)
	scopes := req.Header.Get(HeaderVerifiedScopes)
	ts := req.Header.Get(HeaderIngressTS)
	nonce := req.Header.Get(HeaderIngressNonce)
	sig := req.Header.Get(HeaderIngressSig)
	if sub != "client:chatgpt-1" || route != "route-1" || ts != "1700000123" || nonce == "" || sig == "" {
		t.Fatalf("incomplete signed ingress headers: sub=%q route=%q ts=%q nonce=%q sig=%q", sub, route, ts, nonce, sig)
	}

	// Independently verify the exact ocliv-ingress-v2 MAC format expected by Skybridge.
	payload := strings.Join([]string{
		IngressAuthProtocolVersion,
		"POST",
		"/mcp",
		"127.0.0.1:3000",
		"route-1",
		"client:chatgpt-1",
		scopes,
		ts,
		nonce,
	}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if sig != wantSig {
		t.Fatalf("signature mismatch: got %q want %q", sig, wantSig)
	}
}
