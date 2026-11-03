package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Dynv6UpdateEndpoint is the provider's address-update API. It takes
// hostname+token+addresses as query parameters (provider's contract,
// not our choice); the token is sent only here and never logged.
const Dynv6UpdateEndpoint = "https://dynv6.com/api/update"

// validDynv6Zone accepts exactly the free namespace this adapter
// supports: <label>.dynv6.net. Anything else is refused before any
// network call so a typo can never push an update at the wrong zone.
func validDynv6Zone(zone string) bool {
	z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if !strings.HasSuffix(z, ".dynv6.net") {
		return false
	}
	label := strings.TrimSuffix(z, ".dynv6.net")
	if label == "" || strings.Contains(label, ".") {
		return false
	}
	for _, r := range label {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return label[0] != '-' && label[len(label)-1] != '-'
}

// tokenForms lists every representation url.Values encoding can give
// the token on the wire: raw, QueryEscape (+/space/=), and the %20
// space variant a server echo may use instead of +.
func tokenForms(token string) []string {
	if token == "" {
		return nil
	}
	q := url.QueryEscape(token)
	forms := []string{token, q}
	if strings.Contains(q, "+") {
		forms = append(forms, strings.ReplaceAll(q, "+", "%20"))
	}
	return forms
}

// redactToken removes the credential in every encoded form it can
// take. It guards provider-controlled content (response bodies);
// our own request URLs are never embedded in errors at all.
func redactToken(s, token string) string {
	for _, f := range tokenForms(token) {
		if f != "" {
			s = strings.ReplaceAll(s, f, "***")
		}
	}
	return s
}

// sanitizeDynv6Error classifies a transport failure without embedding
// the credential-bearing request URL (*url.Error text carries it, in
// whatever percent-encoding the query used). The returned category
// stays actionable; the URL stays out entirely.
func sanitizeDynv6Error(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS resolution failure"
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection refused"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "certificate"),
		strings.Contains(msg, "tls"),
		strings.Contains(msg, "handshake"):
		return "TLS failure"
	case strings.Contains(msg, "no such host"):
		return "DNS resolution failure"
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "timeout"),
		strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	}
	return "transport failure"
}

// UpdateDynv6 sets the zone's A/AAAA records via the provider update
// API. Empty ipv4/ipv6 keeps the current record; "auto" lets the
// provider use the observed client address. baseURL is the endpoint
// (production default Dynv6UpdateEndpoint; injectable for tests).
// Errors carry the server status and body with any token occurrence
// redacted, never the raw request URL.
func UpdateDynv6(ctx context.Context, baseURL, zone, token, ipv4, ipv6 string) error {
	if !validDynv6Zone(zone) {
		return fmt.Errorf("not a dynv6.net hostname: %q", zone)
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("missing dynv6 HTTP token for %q (set DYNV6_TOKEN or --token-file)", zone)
	}
	q := url.Values{}
	q.Set("hostname", strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), ".")))
	q.Set("token", token)
	if ipv4 != "" {
		q.Set("ipv4", ipv4)
	}
	if ipv6 != "" {
		q.Set("ipv6", ipv6)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Transport errors (*url.Error) embed the credential-bearing
		// request URL, so the message is classified — never quoted.
		return fmt.Errorf("dynv6 update for %q failed: %s", zone, sanitizeDynv6Error(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := redactToken(strings.TrimSpace(string(body)), token)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("dynv6 update for %q refused: HTTP %d: %s", zone, resp.StatusCode, msg)
	}
	return nil
}
