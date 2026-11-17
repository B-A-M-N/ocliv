package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	AuthMethod      string `json:"auth_method,omitempty"`
	Freshness       string `json:"freshness"` // "AUTHORITATIVE" | "CACHED_UNVERIFIED" | "REVOKED" | "MISSING"
	RelayState      string `json:"relay_state,omitempty"`
	DesiredEnabled  bool   `json:"desired_enabled,omitempty"`
	SessionLive     bool   `json:"session_live,omitempty"`
	FailureReason   string `json:"failure_reason,omitempty"`
	StateGeneration int64  `json:"state_generation,omitempty"`
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
		matches = append(matches, catalogEntry{
			Name:            p.Name,
			Profile:         profile,
			RouteID:         p.RouteID,
			URL:             u,
			AuthMethod:      p.Profile,
			Freshness:       fresh,
			RelayState:      p.PublicationState,
			DesiredEnabled:  p.DesiredEnabled,
			SessionLive:     p.SessionLive,
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
	Transport string `json:"transport"` // PASS | FAIL
	Discovery string `json:"discovery"` // PASS | FAIL | UNKNOWN
	Issuer    string `json:"issuer,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func runReadOnlyDiscoveryCheck(hc *http.Client, pubURL string) discoveryCheckResult {
	res := discoveryCheckResult{Transport: "FAIL", Discovery: "FAIL"}
	if pubURL == "" {
		res.Detail = "missing public URL"
		return res
	}
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

	prURL := strings.Replace(pubURL, "/r/", "/.well-known/oauth-protected-resource/r/", 1)
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
	res.Issuer = issuer
	asURL := strings.Replace(issuer, "/r/", "/.well-known/oauth-authorization-server/r/", 1)
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
		CodeChallengeMethod []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(asBody, &as); err != nil || as.Issuer != issuer || as.AuthorizationEP == "" || as.TokenEP == "" {
		res.Detail = fmt.Sprintf("invalid AS metadata (issuer=%q)", as.Issuer)
		return res
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
	return cmdMCPURLWithOps(argv, defaultServiceOps(), copyToClipboard, &http.Client{Timeout: 5 * time.Second})
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

// cmdMCPCheck performs read-only registration diagnostics for a named service
// or publication without creating OAuth clients, grants, or credentials.
func cmdMCPCheck(argv []string) int {
	return cmdMCPCheckWithOps(argv, defaultServiceOps(), &http.Client{Timeout: 5 * time.Second})
}

func cmdMCPCheckWithOps(argv []string, ops serviceOps, hc *http.Client) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp check NAME [--client chatgpt|gemini|claude|generic] [--profile PROFILE] [--json]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	clientKind := "generic"
	profile := ""
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
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
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
	disc := runReadOnlyDiscoveryCheck(hc, entry.URL)
	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{
			"url":                 entry.URL,
			"endpoint":            disc.Transport,
			"oauth_metadata":      disc.Discovery,
			"client_registration": "UNKNOWN",
			"authenticated_mcp":   "UNKNOWN",
			"external_acceptance": "UNKNOWN",
			"client":              clientKind,
			"detail":              disc.Detail,
		}, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("Endpoint:            %s\n", disc.Transport)
		fmt.Printf("OAuth metadata:      %s\n", disc.Discovery)
		fmt.Printf("Client registration: UNKNOWN (read-only check; no DCR client created)\n")
		fmt.Printf("Authenticated MCP:   UNKNOWN (no bearer credential supplied)\n")
		fmt.Printf("External acceptance: UNKNOWN (off-LAN client %s not executed)\n", clientKind)
		if disc.Detail != "" {
			fmt.Printf("Detail:              %s\n", disc.Detail)
		}
	}
	if disc.Transport != "PASS" || disc.Discovery != "PASS" {
		return apperr.ExitRelayTLS
	}
	return apperr.ExitOK
}

var _ = identity.KeyPair{}
