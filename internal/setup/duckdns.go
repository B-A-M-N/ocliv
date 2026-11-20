package setup

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DuckDNSUpdateEndpoint is DuckDNS's HTTPS address-update API.
const DuckDNSUpdateEndpoint = "https://www.duckdns.org/update"

// IsDuckDNSZone reports whether zone is a valid <label>.duckdns.org hostname.
func IsDuckDNSZone(zone string) bool {
	z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if !strings.HasSuffix(z, ".duckdns.org") {
		return false
	}
	label := strings.TrimSuffix(z, ".duckdns.org")
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

// UpdateDuckDNS updates a <label>.duckdns.org record via DuckDNS HTTPS API.
// Cross-origin redirects are refused and the token is redacted from all errors.
func UpdateDuckDNS(ctx context.Context, baseURL, zone, token, ipv4, ipv6 string) error {
	if !IsDuckDNSZone(zone) {
		return fmt.Errorf("not a duckdns.org hostname: %q", zone)
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("missing DuckDNS token for %q (set DUCKDNS_TOKEN or --token-file)", zone)
	}
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), ".")), ".duckdns.org")
	q := url.Values{}
	q.Set("domains", domain)
	q.Set("token", token)
	if ipv4 != "" {
		q.Set("ip", ipv4)
	}
	if ipv6 != "" {
		q.Set("ipv6", ipv6)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("duckdns update for %q failed: %s", zone, sanitizeDynv6Error(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := redactToken(strings.TrimSpace(string(body)), token)
	if resp.StatusCode < 200 || resp.StatusCode > 299 || !strings.HasPrefix(msg, "OK") {
		return fmt.Errorf("duckdns update for %q refused: HTTP %d: %s", zone, resp.StatusCode, msg)
	}
	return nil
}

// RefreshDuckDNS observes current egress IPv4/IPv6 using the shared
// network-safety policy (refusing CGNAT/no-egress and skipping unchanged DNS)
// and updates DuckDNS only when the address actually changed (P1-7).
func RefreshDuckDNS(ctx context.Context, baseURL, zone, token, echoV4, echoV6 string) (bool, error) {
	return refreshDynamicDNS(ctx, zone, echoV4, echoV6, func(v4, v6 string) error {
		return UpdateDuckDNS(ctx, baseURL, zone, token, v4, v6)
	})
}
