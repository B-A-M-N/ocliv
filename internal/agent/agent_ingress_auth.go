package agent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// IngressAuthProtocolVersion is the canonical publisher-to-local-MCP HMAC
	// identity assertion format verified by Skybridge and local management MCPs.
	IngressAuthProtocolVersion = "ocliv-ingress-v2"

	HeaderVerifiedSubject = "X-Ocliv-Verified-Subject"
	HeaderVerifiedRoute   = "X-Ocliv-Verified-Route"
	HeaderVerifiedScopes  = "X-Ocliv-Verified-Scopes"
	HeaderIngressTS       = "X-Ocliv-Ingress-TS"
	HeaderIngressNonce    = "X-Ocliv-Ingress-Nonce"
	HeaderIngressSig      = "X-Ocliv-Ingress-Sig"
)

// LoadIngressSecretFromEnv loads the optional publisher-to-local-MCP HMAC
// signing secret from OCLIV_INGRESS_SECRET_FILE using single-FD O_NOFOLLOW,
// regular-file, 0600, and owner-UID checks. Returns nil when unset.
func LoadIngressSecretFromEnv() ([]byte, error) {
	path := strings.TrimSpace(os.Getenv("OCLIV_INGRESS_SECRET_FILE"))
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open OCLIV_INGRESS_SECRET_FILE: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || (fi.Mode().Perm()&0o077) != 0 {
		return nil, fmt.Errorf("OCLIV_INGRESS_SECRET_FILE must be a regular 0600 file")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("OCLIV_INGRESS_SECRET_FILE must be owned by the current user")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, err
	}
	sec := strings.TrimSpace(string(raw))
	if len(sec) < 16 {
		return nil, fmt.Errorf("OCLIV_INGRESS_SECRET_FILE must contain at least 16 bytes")
	}
	return []byte(sec), nil
}

// SignIngressAssertion computes the canonical ocliv-ingress-v2 HMAC-SHA256
// assertion bound to HTTP method, request path, destination host, route ID,
// authenticated principal, scopes, unix timestamp, and single-use nonce.
func SignIngressAssertion(secret []byte, method, reqPath, host, route, subject, scopes string, now time.Time, nonce string) (tsStr, nonceOut, sig string) {
	if nonce == "" {
		var buf [16]byte
		_, _ = rand.Read(buf[:])
		nonce = base64.RawURLEncoding.EncodeToString(buf[:])
	}
	tsStr = strconv.FormatInt(now.UTC().Unix(), 10)
	payload := strings.Join([]string{
		IngressAuthProtocolVersion,
		strings.ToUpper(method),
		reqPath,
		strings.ToLower(host),
		route,
		subject,
		scopes,
		tsStr,
		nonce,
	}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return tsStr, nonce, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// StripIngressAssertionHeaders removes any spoofed ingress identity headers
// from an incoming forwarded request before the publisher evaluates authority.
func StripIngressAssertionHeaders(h http.Header) {
	h.Del(HeaderVerifiedSubject)
	h.Del(HeaderVerifiedRoute)
	h.Del(HeaderVerifiedScopes)
	h.Del(HeaderIngressTS)
	h.Del(HeaderIngressNonce)
	h.Del(HeaderIngressSig)
}

// AttachVerifiedIngressHeaders strips any spoofed ingress headers and, when a
// verified relay principal (X-Ocliv-Upstream-Sub) and route (X-Ocliv-Route)
// are present alongside a configured ingress secret, attaches a fresh
// ocliv-ingress-v2 HMAC-SHA256 assertion bound to the exact request context.
func AttachVerifiedIngressHeaders(req *http.Request, secret []byte, route, subject, scopes string, now time.Time) {
	StripIngressAssertionHeaders(req.Header)
	if len(secret) < 16 || subject == "" || route == "" {
		return
	}
	if scopes == "" {
		scopes = "ocliv:read ocliv:write"
	}
	reqPath := req.URL.RequestURI()
	if reqPath == "" {
		reqPath = "/"
	}
	tsStr, nonce, sig := SignIngressAssertion(secret, req.Method, reqPath, req.Host, route, subject, scopes, now, "")
	req.Header.Set(HeaderVerifiedSubject, subject)
	req.Header.Set(HeaderVerifiedRoute, route)
	req.Header.Set(HeaderVerifiedScopes, scopes)
	req.Header.Set(HeaderIngressTS, tsStr)
	req.Header.Set(HeaderIngressNonce, nonce)
	req.Header.Set(HeaderIngressSig, sig)
}
