package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
)

// catalogEntry is the unified authoritative MCP URL record shared by
// `mcp url`, `mcp check`, and `service` diagnostics.
type catalogEntry struct {
	Name            string `json:"name"`
	Profile         string `json:"profile"`
	RouteID         string `json:"route_id,omitempty"`
	URL             string `json:"url,omitempty"`
	IngressProfile  string `json:"ingress_profile,omitempty"`
	AuthMethod      string `json:"auth_method,omitempty"`
	Freshness       string `json:"freshness"` // "AUTHORITATIVE" | "CACHED_UNVERIFIED" | "REVOKED" | "MISSING"
	RelayState      string `json:"relay_state,omitempty"`
	DesiredEnabled  bool   `json:"desired_enabled,omitempty"`
	SessionLive     bool   `json:"session_live,omitempty"`
	FailureReason   string `json:"failure_reason,omitempty"`
	StateGeneration int64  `json:"state_generation,omitempty"`
}

func relayProfileToAuthMode(ingressProfile string) (string, error) {
	switch strings.TrimSpace(ingressProfile) {
	case "managed-oauth":
		return "ocliv-managed", nil
	case "upstream-oauth":
		return "upstream-oauth", nil
	case "ocliv-managed":
		return "ocliv-managed", nil
	default:
		return "", fmt.Errorf("unknown relay ingress profile %q", ingressProfile)
	}
}

func copyToClipboard(text string) error {
	candidates := [][]string{
		{"wl-copy"},
		{"xclip", "-selection", "clipboard"},
		{"xsel", "--clipboard", "--input"},
		{"pbcopy"},
	}
	for _, c := range candidates {
		path, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		cmd := exec.Command(path, c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("clipboard provider unavailable (no wl-copy/xclip/xsel/pbcopy)")
}

// resolveCatalogEntry resolves a publication or service name against the
// authoritative relay inventory first, falling back to local ServiceStore
// records only as CACHED_UNVERIFIED when the relay is unreachable.
func resolveCatalogEntry(name, profile string, ops serviceOps) (catalogEntry, int) {
	if profile == "" {
		profile = config.ActiveProfile()
	}
	var localRec *config.ServiceRecord
	if st, err := openServicesForProfile(profile); err == nil {
		if rec, ok, gerr := st.Get(name); gerr == nil && ok {
			localRec = &rec
		}
	}
	k, keyID, kerr := loadKeyForProfile(profile)
	if kerr != nil {
		if localRec != nil && localRec.PublicURL != "" {
			return catalogEntry{
				Name:          name,
				Profile:       profile,
				RouteID:       localRec.PublicationID,
				URL:           localRec.PublicURL,
				AuthMethod:    localRec.Auth,
				Freshness:     "CACHED_UNVERIFIED",
				FailureReason: "not enrolled in profile " + profile,
			}, apperr.ExitOK
		}
		return catalogEntry{Name: name, Profile: profile, Freshness: "MISSING", FailureReason: "not enrolled in profile " + profile}, apperr.ExitAuth
	}
	relayURL := ""
	if localRec != nil && localRec.RelayURL != "" {
		relayURL = localRec.RelayURL
	} else {
		relayURL = agentRelayURLForProfile(profile)
	}
	stCode, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
	if callErr != nil || stCode != http.StatusOK {
		reason := "relay unreachable"
		if callErr != nil {
			reason = callErr.Error()
		} else {
			reason = fmt.Sprintf("relay returned HTTP %d", stCode)
		}
		if localRec != nil && localRec.PublicURL != "" {
			return catalogEntry{
				Name:          name,
				Profile:       profile,
				RouteID:       localRec.PublicationID,
				URL:           localRec.PublicURL,
				AuthMethod:    localRec.Auth,
				Freshness:     "CACHED_UNVERIFIED",
				FailureReason: reason,
			}, apperr.ExitOK
		}
		return catalogEntry{Name: name, Profile: profile, Freshness: "MISSING", FailureReason: reason}, apperr.ExitRelayTLS
	}
	var inv struct {
		Publications []struct {
			RouteID          string  `json:"route_id"`
			Name             string  `json:"pub_name"`
			Profile          string  `json:"profile"`
			URL              *string `json:"url"`
			DesiredEnabled   bool    `json:"desired_enabled"`
			StateGeneration  int64   `json:"state_generation"`
			SessionLive      bool    `json:"session_live"`
			PublicationState string  `json:"publication_state"`
			RevokedAt        *string `json:"revoked_at"`
		} `json:"publications"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		return catalogEntry{Name: name, Profile: profile, Freshness: "MISSING", FailureReason: "unparseable relay inventory"}, apperr.ExitInternal
	}
	var matches []catalogEntry
	for _, p := range inv.Publications {
		if p.Name != name && (localRec == nil || localRec.PublicationID == "" || p.RouteID != localRec.PublicationID) {
			continue
		}
		u := ""
		if p.URL != nil {
			u = *p.URL
		}
		fresh := "AUTHORITATIVE"
		if p.PublicationState == "REVOKED" || p.RevokedAt != nil {
			fresh = "REVOKED"
		}
		authMode, mapErr := relayProfileToAuthMode(p.Profile)
		failReason := ""
		if mapErr != nil {
			failReason = mapErr.Error()
		}
		matches = append(matches, catalogEntry{
			Name:            p.Name,
			Profile:         profile,
			RouteID:         p.RouteID,
			URL:             u,
			IngressProfile:  p.Profile,
			AuthMethod:      authMode,
			Freshness:       fresh,
			RelayState:      p.PublicationState,
			DesiredEnabled:  p.DesiredEnabled,
			SessionLive:     p.SessionLive,
			FailureReason:   failReason,
			StateGeneration: p.StateGeneration,
		})
	}
	if len(matches) == 0 {
		if localRec != nil && localRec.PublicURL != "" {
			return catalogEntry{
				Name:          name,
				Profile:       profile,
				RouteID:       localRec.PublicationID,
				URL:           localRec.PublicURL,
				AuthMethod:    localRec.Auth,
				Freshness:     "CACHED_UNVERIFIED",
				FailureReason: "publication not present in relay inventory",
			}, apperr.ExitOK
		}
		return catalogEntry{Name: name, Profile: profile, Freshness: "MISSING", FailureReason: "unknown publication " + name}, apperr.ExitCLIValidation
	}
	if len(matches) > 1 {
		return catalogEntry{Name: name, Profile: profile, Freshness: "MISSING", FailureReason: fmt.Sprintf("ambiguous name %q (%d matching routes)", name, len(matches))}, apperr.ExitCLIValidation
	}
	return matches[0], apperr.ExitOK
}

type discoveryCheckResult struct {
	Transport       string `json:"transport"` // PASS | FAIL
	Discovery       string `json:"discovery"` // PASS | FAIL | UNKNOWN
	Issuer          string `json:"issuer,omitempty"`
	AuthorizationEP string `json:"authorization_endpoint,omitempty"`
	TokenEP         string `json:"token_endpoint,omitempty"`
	RegistrationEP  string `json:"registration_endpoint,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

func wellKnownMetadataURL(u *url.URL, wellKnownName string) string {
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	if path == "" || path == "/" {
		return u.Scheme + "://" + u.Host + "/.well-known/" + wellKnownName
	}
	return u.Scheme + "://" + u.Host + "/.well-known/" + wellKnownName + path
}

var (
	_, cgnatCIDR, _ = net.ParseCIDR("100.64.0.0/10")
	_, nat64CIDR, _ = net.ParseCIDR("64:ff9b::/96")
)

func validatePublicIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("empty IP address")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		cgnatCIDR.Contains(ip) || nat64CIDR.Contains(ip) {
		return fmt.Errorf("non-public IP %s blocked by egress policy", ip.String())
	}
	return nil
}

func safeDiscoveryURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("unsafe scheme %q (https required)", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("userinfo in URL is forbidden")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("missing hostname")
	}
	return u, nil
}

func safeEgressDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := validatePublicIP(ip); err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses resolved for %q", host)
	}
	for _, ipa := range ips {
		if err := validatePublicIP(ipa.IP); err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func safeEgressHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: safeEgressDialContext,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirects blocked during discovery check")
		},
	}
}

func wrapNoRedirectClient(base *http.Client) *http.Client {
	if base == nil {
		return safeEgressHTTPClient()
	}
	cp := *base
	cp.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("redirects blocked during discovery check")
	}
	return &cp
}

func runReadOnlyDiscoveryCheck(hc *http.Client, pubURL string) discoveryCheckResult {
	return runReadOnlyDiscoveryCheckWithAllowlist(hc, pubURL, nil)
}

func runReadOnlyDiscoveryCheckWithAllowlist(hc *http.Client, pubURL string, trustedIssuerOrigins []string) discoveryCheckResult {
	res := discoveryCheckResult{Transport: "FAIL", Discovery: "FAIL"}
	if pubURL == "" {
		res.Detail = "missing public URL"
		return res
	}
	pubParsed, err := safeDiscoveryURL(pubURL)
	if err != nil {
		res.Detail = "unsafe public URL: " + err.Error()
		return res
	}
	hc = wrapNoRedirectClient(hc)

	req, _ := http.NewRequest(http.MethodPost, pubURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := hc.Do(req)
	if err != nil {
		res.Detail = "endpoint unreachable: " + err.Error()
		return res
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusOK {
		res.Detail = fmt.Sprintf("unexpected MCP status HTTP %d", resp.StatusCode)
		return res
	}
	res.Transport = "PASS"

	prURL := wellKnownMetadataURL(pubParsed, "oauth-protected-resource")
	if _, err := safeDiscoveryURL(prURL); err != nil {
		res.Detail = "unsafe protected-resource URL: " + err.Error()
		return res
	}
	prResp, err := hc.Get(prURL)
	if err != nil {
		res.Detail = "protected-resource metadata unreachable: " + err.Error()
		return res
	}
	prBody, _ := io.ReadAll(io.LimitReader(prResp.Body, 64*1024))
	_ = prResp.Body.Close()
	if prResp.StatusCode != http.StatusOK {
		res.Detail = fmt.Sprintf("protected-resource metadata returned HTTP %d", prResp.StatusCode)
		return res
	}
	var pr struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(prBody, &pr); err != nil || pr.Resource != pubURL || len(pr.AuthorizationServers) == 0 {
		res.Detail = fmt.Sprintf("invalid protected-resource metadata (resource=%q)", pr.Resource)
		return res
	}
	issuer := pr.AuthorizationServers[0]
	issuerParsed, err := safeDiscoveryURL(issuer)
	if err != nil {
		res.Detail = "unsafe authorization_server issuer: " + err.Error()
		return res
	}
	if !strings.EqualFold(issuerParsed.Scheme, pubParsed.Scheme) || !strings.EqualFold(issuerParsed.Host, pubParsed.Host) {
		issuerOrigin := strings.ToLower(issuerParsed.Scheme + "://" + issuerParsed.Host)
		allowed := false
		for _, o := range trustedIssuerOrigins {
			if strings.EqualFold(strings.TrimRight(o, "/"), issuerOrigin) {
				allowed = true
				break
			}
		}
		if !allowed {
			res.Detail = fmt.Sprintf("authorization_server origin %q does not match endpoint origin %q", issuerParsed.Host, pubParsed.Host)
			return res
		}
	}
	res.Issuer = issuer
	asURL := wellKnownMetadataURL(issuerParsed, "oauth-authorization-server")
	if _, err := safeDiscoveryURL(asURL); err != nil {
		res.Detail = "unsafe authorization-server metadata URL: " + err.Error()
		return res
	}
	asResp, err := hc.Get(asURL)
	if err != nil {
		res.Detail = "authorization-server metadata unreachable: " + err.Error()
		return res
	}
	asBody, _ := io.ReadAll(io.LimitReader(asResp.Body, 64*1024))
	_ = asResp.Body.Close()
	if asResp.StatusCode != http.StatusOK {
		res.Detail = fmt.Sprintf("authorization-server metadata returned HTTP %d", asResp.StatusCode)
		return res
	}
	var as struct {
		Issuer              string   `json:"issuer"`
		AuthorizationEP     string   `json:"authorization_endpoint"`
		TokenEP             string   `json:"token_endpoint"`
		RegistrationEP      string   `json:"registration_endpoint"`
		CodeChallengeMethod []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(asBody, &as); err != nil || as.Issuer != issuer || as.AuthorizationEP == "" || as.TokenEP == "" {
		res.Detail = fmt.Sprintf("invalid AS metadata (issuer=%q)", as.Issuer)
		return res
	}
	if _, err := safeDiscoveryURL(as.AuthorizationEP); err != nil {
		res.Detail = "unsafe authorization_endpoint: " + err.Error()
		return res
	}
	if _, err := safeDiscoveryURL(as.TokenEP); err != nil {
		res.Detail = "unsafe token_endpoint: " + err.Error()
		return res
	}
	res.AuthorizationEP = as.AuthorizationEP
	res.TokenEP = as.TokenEP
	if as.RegistrationEP != "" {
		if _, err := safeDiscoveryURL(as.RegistrationEP); err != nil {
			res.Detail = "unsafe registration_endpoint: " + err.Error()
			return res
		}
		res.RegistrationEP = as.RegistrationEP
	}
	hasS256 := false
	for _, m := range as.CodeChallengeMethod {
		if m == "S256" {
			hasS256 = true
		}
	}
	if !hasS256 {
		res.Detail = "AS metadata missing S256 PKCE support"
		return res
	}
	res.Discovery = "PASS"
	return res
}

// cmdMCPURL prints the canonical client-facing URL for a named service or
// publication, supporting --copy, --verify, and --json.
func cmdMCPURL(argv []string) int {
	return cmdMCPURLWithOps(argv, defaultServiceOps(), copyToClipboard, safeEgressHTTPClient())
}

func cmdMCPURLWithOps(argv []string, ops serviceOps, clipper func(string) error, hc *http.Client) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp url NAME [--profile PROFILE] [--copy] [--verify] [--json]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	var profile string
	var doCopy, doVerify, asJSON bool
	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == "--copy":
			doCopy = true
		case argv[i] == "--verify":
			doVerify = true
		case argv[i] == "--json":
			asJSON = true
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}
	entry, code := resolveCatalogEntry(name, profile, ops)
	out := map[string]any{
		"lookup":    entry.Freshness != "MISSING",
		"freshness": entry.Freshness,
		"route_id":  entry.RouteID,
		"url":       entry.URL,
		"transport": "UNKNOWN",
		"discovery": "UNKNOWN",
		"copy":      "SKIPPED",
	}
	if entry.FailureReason != "" {
		out["error"] = entry.FailureReason
	}
	if entry.Freshness == "REVOKED" {
		out["error"] = "publication is REVOKED"
		if asJSON {
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
		} else {
			fmt.Fprintf(os.Stderr, "error: publication %q is REVOKED and unusable\n", name)
		}
		return apperr.ExitAuth
	}
	if entry.URL == "" {
		if asJSON {
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
		} else {
			fmt.Fprintf(os.Stderr, "error: %s\n", entry.FailureReason)
		}
		if code != 0 {
			return code
		}
		return apperr.ExitCLIValidation
	}
	if doVerify {
		if entry.Freshness != "AUTHORITATIVE" {
			out["error"] = "cannot verify cached URL (" + entry.FailureReason + ")"
			if asJSON {
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
			} else {
				fmt.Fprintf(os.Stderr, "error: %s: %s\n", entry.Freshness, entry.FailureReason)
			}
			return apperr.ExitRelayTLS
		}
		disc := runReadOnlyDiscoveryCheck(hc, entry.URL)
		out["transport"] = disc.Transport
		out["discovery"] = disc.Discovery
		if disc.Detail != "" {
			out["error"] = disc.Detail
		}
		if disc.Transport != "PASS" || disc.Discovery != "PASS" {
			if asJSON {
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
			} else {
				fmt.Fprintf(os.Stderr, "verify failed: %s\n", disc.Detail)
			}
			return apperr.ExitRelayTLS
		}
	}
	if doCopy {
		if cerr := clipper(entry.URL); cerr != nil {
			out["copy"] = "FAIL"
			out["error"] = cerr.Error()
			if asJSON {
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
			} else {
				fmt.Fprintf(os.Stderr, "error: %v (URL: %s)\n", cerr, entry.URL)
			}
			return apperr.ExitInternal
		}
		out["copy"] = "PASS"
	}
	if asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	if entry.Freshness == "CACHED_UNVERIFIED" {
		fmt.Fprintf(os.Stderr, "warning: CACHED_UNVERIFIED (%s)\n", entry.FailureReason)
	}
	fmt.Println(entry.URL)
	if doCopy {
		fmt.Fprintln(os.Stderr, "copied URL to clipboard")
	}
	return apperr.ExitOK
}

// cmdMCPURLs prints the authoritative MCP URL catalog for all publications in a profile.
func cmdMCPURLs(argv []string) int {
	return cmdMCPURLsWithOps(argv, defaultServiceOps())
}

func cmdMCPURLsWithOps(argv []string, ops serviceOps) int {
	profile := ""
	copyName := ""
	asJSON := false
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--json":
			asJSON = true
		case argv[i] == "--copy" || strings.HasPrefix(argv[i], "--copy="):
			v, ok := mcpFlagValue(argv, &i, "copy")
			if !ok {
				return apperr.ExitCLIValidation
			}
			copyName = v
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if copyName != "" {
		cargs := []string{copyName, "--copy"}
		if profile != "" {
			cargs = append(cargs, "--profile", profile)
		}
		if asJSON {
			cargs = append(cargs, "--json")
		}
		return cmdMCPURLWithOps(cargs, ops, copyToClipboard, safeEgressHTTPClient())
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}
	k, keyID, err := loadKeyForProfile(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q: run `ocliv login` first\n", profile)
		return apperr.ExitAuth
	}
	relayURL := agentRelayURLForProfile(profile)
	if _, rerr := validateRelayTarget(relayURL); rerr != nil {
		fmt.Fprintf(os.Stderr, "mcp urls: %v\n", rerr)
		return apperr.ExitCLIValidation
	}
	stCode, body, err := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp urls: %v\n", err)
		return apperr.ExitRelayTLS
	}
	if stCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "mcp urls: relay returned HTTP %d\n", stCode)
		return apperr.ExitRelayTLS
	}
	var inv struct {
		Publications []struct {
			RouteID          string  `json:"route_id"`
			Name             string  `json:"pub_name"`
			Profile          string  `json:"profile"`
			URL              *string `json:"url"`
			DesiredEnabled   bool    `json:"desired_enabled"`
			StateGeneration  int64   `json:"state_generation"`
			SessionLive      bool    `json:"session_live"`
			PublicationState string  `json:"publication_state"`
			RevokedAt        *string `json:"revoked_at"`
		} `json:"publications"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		fmt.Fprintf(os.Stderr, "mcp urls: unparseable relay inventory: %v\n", err)
		return apperr.ExitInternal
	}
	entries := make([]catalogEntry, 0, len(inv.Publications))
	for _, p := range inv.Publications {
		fresh := "AUTHORITATIVE"
		if p.PublicationState == "REVOKED" || p.RevokedAt != nil {
			fresh = "REVOKED"
		} else if !p.DesiredEnabled {
			fresh = "DISABLED"
		}
		u := ""
		if p.URL != nil {
			u = *p.URL
		}
		authMode, _ := relayProfileToAuthMode(p.Profile)
		entries = append(entries, catalogEntry{
			Name:            p.Name,
			Profile:         profile,
			RouteID:         p.RouteID,
			URL:             u,
			IngressProfile:  p.Profile,
			AuthMethod:      authMode,
			Freshness:       fresh,
			RelayState:      p.PublicationState,
			DesiredEnabled:  p.DesiredEnabled,
			SessionLive:     p.SessionLive,
			StateGeneration: p.StateGeneration,
		})
	}
	if asJSON {
		b, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	if len(entries) == 0 {
		fmt.Printf("No MCP publications found for profile %q.\n", profile)
		return apperr.ExitOK
	}
	fmt.Printf("%-20s %-12s %-18s %-14s %s\n", "NAME", "STATUS", "AUTH", "FRESHNESS", "URL")
	for _, e := range entries {
		fmt.Printf("%-20s %-12s %-18s %-14s %s\n", e.Name, e.RelayState, e.AuthMethod, e.Freshness, e.URL)
	}
	return apperr.ExitOK
}

// cmdMCPCheck performs read-only registration diagnostics for a named service
// or publication without creating OAuth clients, grants, or credentials.
func cmdMCPCheck(argv []string) int {
	return cmdMCPCheckWithOps(argv, defaultServiceOps(), safeEgressHTTPClient())
}

func cmdMCPCheckWithOps(argv []string, ops serviceOps, hc *http.Client) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp check NAME [--client generic|chatgpt|gemini|google-connected-app] [--trusted-issuer URL] [--token-file PATH] [--profile PROFILE] [--json]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	clientKind := "generic"
	profile := ""
	tokenFile := ""
	var trustedIssuers []string
	asJSON := false
	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == "--json":
			asJSON = true
		case argv[i] == "--client" || strings.HasPrefix(argv[i], "--client="):
			v, ok := mcpFlagValue(argv, &i, "client")
			if !ok {
				return apperr.ExitCLIValidation
			}
			clientKind = strings.ToLower(v)
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		case argv[i] == "--token-file" || strings.HasPrefix(argv[i], "--token-file="):
			v, ok := mcpFlagValue(argv, &i, "token-file")
			if !ok {
				return apperr.ExitCLIValidation
			}
			tokenFile = v
		case argv[i] == "--trusted-issuer" || strings.HasPrefix(argv[i], "--trusted-issuer="):
			v, ok := mcpFlagValue(argv, &i, "trusted-issuer")
			if !ok {
				return apperr.ExitCLIValidation
			}
			trustedIssuers = append(trustedIssuers, v)
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	switch clientKind {
	case "generic", "chatgpt", "gemini", "google-connected-app", "claude":
	default:
		fmt.Fprintf(os.Stderr, "unknown --client %q (want generic|chatgpt|gemini|google-connected-app)\n", clientKind)
		return apperr.ExitCLIValidation
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}
	entry, code := resolveCatalogEntry(name, profile, ops)
	if entry.Freshness != "AUTHORITATIVE" || entry.URL == "" {
		if asJSON {
			b, _ := json.MarshalIndent(map[string]any{
				"endpoint": "FAIL", "oauth_metadata": "FAIL", "freshness": entry.Freshness, "error": entry.FailureReason,
			}, "", "  ")
			fmt.Println(string(b))
		} else {
			fmt.Fprintf(os.Stderr, "mcp check failed (%s): %s\n", entry.Freshness, entry.FailureReason)
		}
		if code != 0 {
			return code
		}
		return apperr.ExitRelayTLS
	}
	disc := runReadOnlyDiscoveryCheckWithAllowlist(hc, entry.URL, trustedIssuers)
	authMCP := "UNKNOWN"
	authMCPDetail := ""
	if tokenFile != "" && disc.Transport == "PASS" {
		tokBytes, terr := os.ReadFile(tokenFile)
		if terr != nil {
			authMCP = "FAIL"
			authMCPDetail = "read --token-file: " + terr.Error()
		} else if tok := strings.TrimSpace(string(tokBytes)); tok == "" {
			authMCP = "FAIL"
			authMCPDetail = "--token-file is empty"
		} else {
			probeMode := "mcp_managed_oauth"
			if entry.AuthMethod == "upstream-oauth" {
				probeMode = "mcp_upstream_oauth"
			}
			out := runMCPProbeWithClient(entry.URL, probeMode, tok, wrapNoRedirectClient(hc))
			if !out.Verified {
				authMCP = "FAIL"
				authMCPDetail = out.Summary
			} else {
				authMCP = "PASS"
				authMCPDetail = out.Summary
				if svcStore, serr := openServicesForProfile(profile); serr == nil {
					if rec, ok, _ := svcStore.Get(entry.Name); ok && entry.StateGeneration > 0 {
						now := time.Now().UTC()
						_, _ = svcStore.UpdateCAS(entry.Name, rec.Revision, func(r *config.ServiceRecord) error {
							r.VerificationEvidence = &config.VerificationEvidence{
								RouteID:         entry.RouteID,
								PublicURL:       entry.URL,
								Issuer:          disc.Issuer,
								Stage:           "MCP_AUTHENTICATED",
								StateGeneration: entry.StateGeneration,
								VerifiedAt:      now.Format(time.RFC3339),
								ExpiresAt:       now.Add(24 * time.Hour).Format(time.RFC3339),
							}
							r.LastVerifiedAt = now.Format(time.RFC3339)
							return nil
						})
					}
				}
			}
		}
	}
	profileCheck := "PASS"
	profileDetail := ""
	domainVerify := "SKIPPED"
	if disc.Discovery == "PASS" {
		switch clientKind {
		case "chatgpt":
			if disc.RegistrationEP == "" {
				profileCheck = "FAIL"
				profileDetail = "chatgpt requires dynamic client registration_endpoint in AS metadata"
			}
		case "google-connected-app":
			parsed, perr := safeDiscoveryURL(entry.URL)
			if perr != nil {
				profileCheck = "FAIL"
				profileDetail = perr.Error()
			} else {
				verifyURL := parsed.Scheme + "://" + parsed.Host + "/.well-known/google-connected-apps"
				vResp, verr := wrapNoRedirectClient(hc).Get(verifyURL)
				if verr != nil {
					profileCheck = "FAIL"
					domainVerify = "FAIL"
					profileDetail = "google-connected-apps verification unreachable: " + verr.Error()
				} else {
					vBody, _ := io.ReadAll(io.LimitReader(vResp.Body, 32*1024))
					_ = vResp.Body.Close()
					if vResp.StatusCode != http.StatusOK {
						profileCheck = "FAIL"
						domainVerify = "FAIL"
						profileDetail = fmt.Sprintf("%s returned HTTP %d (valid JSON 200 required)", verifyURL, vResp.StatusCode)
					} else if verr := ValidateGoogleVerificationDocument(vBody, ""); verr != nil {
						profileCheck = "FAIL"
						domainVerify = "FAIL"
						profileDetail = fmt.Sprintf("%s invalid verification document: %v", verifyURL, verr)
					} else {
						domainVerify = "PASS"
					}
				}
			}
		}
	}
	if asJSON {
		out := map[string]any{
			"url":                 entry.URL,
			"endpoint":            disc.Transport,
			"oauth_metadata":      disc.Discovery,
			"client_profile":      profileCheck,
			"client_registration": "UNKNOWN",
			"authenticated_mcp":   authMCP,
			"external_acceptance": "UNKNOWN",
			"client":              clientKind,
			"detail":              disc.Detail,
		}
		if authMCPDetail != "" {
			out["authenticated_mcp_detail"] = authMCPDetail
		}
		if domainVerify != "SKIPPED" {
			out["google_domain_verification"] = domainVerify
		}
		if profileDetail != "" {
			out["profile_detail"] = profileDetail
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("Endpoint:            %s\n", disc.Transport)
		fmt.Printf("OAuth metadata:      %s\n", disc.Discovery)
		fmt.Printf("Client profile (%s): %s\n", clientKind, profileCheck)
		if domainVerify != "SKIPPED" {
			fmt.Printf("Google verification: %s\n", domainVerify)
		}
		fmt.Printf("Client registration: UNKNOWN (read-only check; no DCR client created)\n")
		if authMCPDetail != "" {
			fmt.Printf("Authenticated MCP:   %s (%s)\n", authMCP, authMCPDetail)
		} else {
			fmt.Printf("Authenticated MCP:   %s\n", authMCP)
		}
		fmt.Printf("External acceptance: UNKNOWN (off-LAN client %s not executed)\n", clientKind)
		if disc.Detail != "" {
			fmt.Printf("Detail:              %s\n", disc.Detail)
		}
		if profileDetail != "" {
			fmt.Printf("Profile detail:      %s\n", profileDetail)
		}
	}
	if disc.Transport != "PASS" || disc.Discovery != "PASS" || profileCheck != "PASS" || authMCP == "FAIL" {
		return apperr.ExitRelayTLS
	}
	return apperr.ExitOK
}

var _ = identity.KeyPair{}
