package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func (ops serviceOps) callMgmtBody(relayURL string, k *identity.KeyPair, keyID, method, path string, reqBody []byte) (int, []byte, error) {
	if ops.mgmtCallBody != nil {
		return ops.mgmtCallBody(relayURL, k, keyID, method, path, reqBody)
	}
	return mgmtCallBody(relayURL, k, keyID, method, path, reqBody)
}

func resolveServiceOrRoute(target, profile string, ops serviceOps) (displayName, routeID, relayURL string, k *identity.KeyPair, keyID string, exitCode int, err error) {
	if profile == "" {
		profile = config.ActiveProfile()
	}
	if store, serr := openServicesForProfile(profile); serr == nil {
		if rec, ok, gerr := store.Get(target); gerr == nil && ok {
			p := rec.Profile
			if p == "" {
				p = profile
			}
			k, keyID, err = loadKeyForProfile(p)
			if err != nil {
				return "", "", "", nil, "", apperr.ExitAuth, fmt.Errorf("not enrolled in profile %q: run `ocliv device add user@this-host` on your relay or `ocliv pair https://YOUR_RELAY` here", p)
			}
			relayURL = rec.RelayURL
			if relayURL == "" {
				relayURL = agentRelayURLForProfile(p)
			}
			pubID := rec.PublicationID
			if pubID == "" {
				foundID, _, found, rerr := resolveRelayPublication(relayURL, k, keyID, rec, ops)
				if rerr != nil || !found {
					return "", "", "", nil, "", apperr.ExitInternal, fmt.Errorf("no publication found for service %q (%v)", target, rerr)
				}
				pubID = foundID
			}
			return rec.Name, pubID, relayURL, k, keyID, apperr.ExitOK, nil
		}
	}
	// Fallback: treat target as a direct route ID owned by the active profile key.
	if strings.ContainsAny(target, " /\t\r\n") || target == "" {
		return "", "", "", nil, "", apperr.ExitCLIValidation, fmt.Errorf("unknown service or route %q", target)
	}
	k, keyID, err = loadKeyForProfile(profile)
	if err != nil {
		return "", "", "", nil, "", apperr.ExitAuth, fmt.Errorf("not enrolled in profile %q: run `ocliv device add user@this-host` on your relay or `ocliv pair https://YOUR_RELAY` here", profile)
	}
	relayURL = agentRelayURLForProfile(profile)
	return target, target, relayURL, k, keyID, apperr.ExitOK, nil
}

func applyTrustPolicyToRoute(relayURL string, k *identity.KeyPair, keyID, routeID, kind string, redirectURIs []string, ops serviceOps) (*authz.ClientTrustPolicy, string, int, error) {
	payload := map[string]any{}
	if kind != "" {
		payload["kind"] = kind
	}
	if len(redirectURIs) > 0 {
		payload["redirect_uris"] = redirectURIs
	}
	reqBody, _ := json.Marshal(payload)
	st, body, callErr := ops.callMgmtBody(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+routeID+"/trust", reqBody)
	if callErr != nil {
		return nil, "", apperr.ExitRelayTLS, callErr
	}
	if st != http.StatusCreated && st != http.StatusOK {
		return nil, "", apperr.ExitAuth, fmt.Errorf("relay returned %d: %s", st, strings.TrimSpace(string(body)))
	}
	var resp struct {
		Policy authz.ClientTrustPolicy `json:"policy"`
		Status string                  `json:"status"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", apperr.ExitInternal, fmt.Errorf("invalid relay trust response: %w", err)
	}
	return &resp.Policy, resp.Status, apperr.ExitOK, nil
}

// cmdTrust configures route-scoped OAuth client trust policies or approves a
// pending client directly over the signed publisher management channel.
//
//	ocliv trust NAME chatgpt
//	ocliv trust NAME --redirect-uri https://...
//	ocliv trust NAME --client CLIENT_ID
//	ocliv trust NAME --list [--json]
func cmdTrust(argv []string) int {
	return cmdTrustWithOps(argv, defaultServiceOps())
}

func cmdTrustWithOps(argv []string, ops serviceOps) int {
	if len(argv) == 0 || argv[0] == "--help" || argv[0] == "-h" {
		fmt.Fprintln(os.Stderr, "usage: ocliv trust NAME PRESET                     (e.g. ocliv trust tools chatgpt)")
		fmt.Fprintln(os.Stderr, "       ocliv trust NAME --redirect-uri HTTPS_URI   (pin exact HTTPS callback)")
		fmt.Fprintln(os.Stderr, "       ocliv trust NAME --client CLIENT_ID         (approve a pending client directly)")
		fmt.Fprintln(os.Stderr, "       ocliv trust NAME --list [--json]            (list active trust policies)")
		if len(argv) == 0 {
			return apperr.ExitCLIValidation
		}
		return apperr.ExitOK
	}
	target := argv[0]
	var preset, clientID, profileFlag string
	var redirectURIs []string
	var listOnly, jsonOut bool

	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--list":
			listOnly = true
		case a == "--json":
			jsonOut = true
		case a == "--client" || strings.HasPrefix(a, "--client="):
			v, ok := mcpFlagValue(argv, &i, "client")
			if !ok {
				return apperr.ExitCLIValidation
			}
			clientID = v
		case a == "--redirect-uri" || strings.HasPrefix(a, "--redirect-uri="):
			v, ok := mcpFlagValue(argv, &i, "redirect-uri")
			if !ok {
				return apperr.ExitCLIValidation
			}
			redirectURIs = append(redirectURIs, v)
		case a == "--profile" || strings.HasPrefix(a, "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profileFlag = v
		case !strings.HasPrefix(a, "-") && preset == "":
			preset = a
		default:
			fmt.Fprintf(os.Stderr, "trust: unknown argument %q\n", a)
			return apperr.ExitCLIValidation
		}
	}

	displayName, routeID, relayURL, k, keyID, code, err := resolveServiceOrRoute(target, profileFlag, ops)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trust: "+err.Error())
		return code
	}

	if listOnly {
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+routeID+"/trust")
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "trust: %v\n", callErr)
			return apperr.ExitRelayTLS
		}
		if st != http.StatusOK {
			fmt.Fprintf(os.Stderr, "trust: relay returned %d: %s\n", st, strings.TrimSpace(string(body)))
			return apperr.ExitAuth
		}
		if jsonOut {
			fmt.Println(string(body))
			return apperr.ExitOK
		}
		var out struct {
			Policies []authz.ClientTrustPolicy `json:"policies"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			fmt.Fprintln(os.Stderr, "trust: invalid relay response")
			return apperr.ExitInternal
		}
		if len(out.Policies) == 0 {
			fmt.Printf("no trusted client policies for %s\n", displayName)
			return apperr.ExitOK
		}
		for _, p := range out.Policies {
			fmt.Printf("%s  kind=%s  redirects=%s\n", p.ID, p.Kind, strings.Join(p.RedirectURIs, ","))
		}
		return apperr.ExitOK
	}

	if clientID != "" {
		if preset != "" || len(redirectURIs) > 0 {
			fmt.Fprintln(os.Stderr, "trust: --client cannot be combined with a preset or --redirect-uri")
			return apperr.ExitCLIValidation
		}
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+routeID+"/authz/approve-direct/"+clientID)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "trust: %v\n", callErr)
			return apperr.ExitRelayTLS
		}
		if st != http.StatusOK {
			fmt.Fprintf(os.Stderr, "trust: relay returned %d: %s\n", st, strings.TrimSpace(string(body)))
			return apperr.ExitAuth
		}
		if jsonOut {
			fmt.Println(string(body))
			return apperr.ExitOK
		}
		fmt.Printf("✓ trusted client %s for %s (route=%s, direct)\n", clientID, displayName, routeID)
		return apperr.ExitOK
	}

	if preset == "" && len(redirectURIs) == 0 {
		fmt.Fprintln(os.Stderr, "trust: specify a preset (e.g. `chatgpt`), --redirect-uri HTTPS_URI, --client CLIENT_ID, or --list")
		return apperr.ExitCLIValidation
	}
	if preset != "" && len(redirectURIs) > 0 {
		fmt.Fprintln(os.Stderr, "trust: specify either a preset or --redirect-uri, not both")
		return apperr.ExitCLIValidation
	}
	if preset != "" {
		if _, ok := authz.LookupTrustPreset(preset); !ok {
			fmt.Fprintf(os.Stderr, "trust: unknown preset %q (available: chatgpt)\n", preset)
			return apperr.ExitCLIValidation
		}
	} else {
		if _, verr := authz.ValidateTrustRedirectURIs(redirectURIs); verr != nil {
			fmt.Fprintf(os.Stderr, "trust: %v\n", verr)
			return apperr.ExitCLIValidation
		}
	}

	pol, status, pcode, perr := applyTrustPolicyToRoute(relayURL, k, keyID, routeID, preset, redirectURIs, ops)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "trust: %v\n", perr)
		return pcode
	}
	if jsonOut {
		b, _ := json.MarshalIndent(map[string]any{"route_id": routeID, "status": status, "policy": pol}, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	fmt.Printf("✓ %s now trusts %s (policy=%s)\n", displayName, pol.DisplayLabel(), pol.ID)
	for _, u := range pol.RedirectURIs {
		fmt.Printf("  redirect: %s\n", u)
	}
	return apperr.ExitOK
}

// cmdUntrust revokes a route-scoped trust policy by preset name or policy ID.
func cmdUntrust(argv []string) int {
	return cmdUntrustWithOps(argv, defaultServiceOps())
}

func cmdUntrustWithOps(argv []string, ops serviceOps) int {
	if len(argv) < 2 || argv[0] == "--help" || argv[0] == "-h" {
		fmt.Fprintln(os.Stderr, "usage: ocliv untrust NAME PRESET_OR_POLICY_ID [--profile NAME]")
		if len(argv) > 0 && (argv[0] == "--help" || argv[0] == "-h") {
			return apperr.ExitOK
		}
		return apperr.ExitCLIValidation
	}
	target := argv[0]
	policyTarget := argv[1]
	var profileFlag string
	for i := 2; i < len(argv); i++ {
		if argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile=") {
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profileFlag = v
		} else {
			fmt.Fprintf(os.Stderr, "untrust: unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}

	displayName, routeID, relayURL, k, keyID, code, err := resolveServiceOrRoute(target, profileFlag, ops)
	if err != nil {
		fmt.Fprintln(os.Stderr, "untrust: "+err.Error())
		return code
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodDelete, "/v1/agent/mcp-routes/"+routeID+"/trust/"+policyTarget)
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "untrust: %v\n", callErr)
		return apperr.ExitRelayTLS
	}
	if st != http.StatusOK {
		fmt.Fprintf(os.Stderr, "untrust: relay returned %d: %s\n", st, strings.TrimSpace(string(body)))
		return apperr.ExitAuth
	}
	fmt.Printf("✓ removed trust policy %q from %s\n", policyTarget, displayName)
	return apperr.ExitOK
}

// cmdRevoke revokes an OAuth client across a service/route:
//
//	ocliv revoke client CLIENT_ID [--service NAME | --route ROUTE_ID] [--profile NAME]
func cmdRevoke(argv []string) int {
	return cmdRevokeWithOps(argv, defaultServiceOps())
}

func cmdRevokeWithOps(argv []string, ops serviceOps) int {
	if len(argv) < 2 || argv[0] == "--help" || argv[0] == "-h" {
		fmt.Fprintln(os.Stderr, "usage: ocliv revoke client CLIENT_ID [--service NAME | --route ROUTE_ID] [--profile NAME]")
		if len(argv) > 0 && (argv[0] == "--help" || argv[0] == "-h") {
			return apperr.ExitOK
		}
		return apperr.ExitCLIValidation
	}
	if argv[0] != "client" {
		fmt.Fprintf(os.Stderr, "revoke: unknown target %q (supported: client)\n", argv[0])
		return apperr.ExitCLIValidation
	}
	clientID := argv[1]
	var target, profileFlag string
	for i := 2; i < len(argv); i++ {
		switch {
		case argv[i] == "--service" || strings.HasPrefix(argv[i], "--service="):
			v, ok := mcpFlagValue(argv, &i, "service")
			if !ok {
				return apperr.ExitCLIValidation
			}
			target = v
		case argv[i] == "--route" || strings.HasPrefix(argv[i], "--route="):
			v, ok := mcpFlagValue(argv, &i, "route")
			if !ok {
				return apperr.ExitCLIValidation
			}
			target = v
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profileFlag = v
		default:
			fmt.Fprintf(os.Stderr, "revoke client: unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if profileFlag == "" {
		profileFlag = config.ActiveProfile()
	}
	if target == "" {
		if store, serr := openServicesForProfile(profileFlag); serr == nil {
			if svcs, lerr := store.List(); lerr == nil {
				var mcpSvcs []config.ServiceRecord
				for _, s := range svcs {
					if s.Type == "mcp" && s.PublicationID != "" {
						mcpSvcs = append(mcpSvcs, s)
					}
				}
				if len(mcpSvcs) == 1 {
					target = mcpSvcs[0].Name
				}
			}
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "revoke client: specify --service NAME or --route ROUTE_ID")
		return apperr.ExitCLIValidation
	}
	displayName, routeID, relayURL, k, keyID, code, err := resolveServiceOrRoute(target, profileFlag, ops)
	if err != nil {
		fmt.Fprintln(os.Stderr, "revoke client: "+err.Error())
		return code
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+routeID+"/authz/revoke/"+clientID)
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "revoke client: %v\n", callErr)
		return apperr.ExitRelayTLS
	}
	if st != http.StatusOK {
		fmt.Fprintf(os.Stderr, "revoke client: relay returned %d: %s\n", st, strings.TrimSpace(string(body)))
		return apperr.ExitAuth
	}
	fmt.Printf("✓ revoked client %s on %s (route=%s)\n", clientID, displayName, routeID)
	return apperr.ExitOK
}
