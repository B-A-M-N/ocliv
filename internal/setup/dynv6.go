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
		return fmt.Errorf("dynv6 update for %q failed: %v", zone, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := strings.TrimSpace(string(body))
	msg = strings.ReplaceAll(msg, token, "***")
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("dynv6 update for %q refused: HTTP %d: %s", zone, resp.StatusCode, msg)
	}
	return nil
}
