package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

// OCL-012/013 Agent-Facing MCP Control Plane tool catalog (closed set by construction:
// no shell, exec, or arbitrary command tool exists and none can be added by callers).
type mcpManageToolSpec struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
}

var (
	mcpServiceNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`)
	mcpSafeIDRe      = regexp.MustCompile(`^[A-Za-z0-9._:-]{3,128}$`)
)

var ocl012ManageToolSpecs = []mcpManageToolSpec{
	// Discovery & URL retrieval
	{
		Name:        "get_status",
		Description: "Return relay connectivity, publisher enrollment, binary version, and capabilities.",
		Properties:  map[string]any{},
	},
	{
		Name:        "list_services",
		Description: "List configured local services permitted for this agent principal, including disabled and unpublished services.",
		Properties:  map[string]any{},
	},
	{
		Name:        "get_service",
		Description: "Retrieve complete service configuration and observed multi-layer state by service name.",
		Properties:  map[string]any{"service": map[string]any{"type": "string", "description": "Human-readable service name"}},
		Required:    []string{"service"},
	},
	{
		Name:        "get_url",
		Description: "Return the persistent canonical HTTPS URL and observed reachability for a service in one call.",
		Properties:  map[string]any{"service": map[string]any{"type": "string", "description": "Human-readable service name"}},
		Required:    []string{"service"},
	},
	// Deployment & lifecycle
	{
		Name:        "deploy_service",
		Description: "Idempotently create and activate a protected publication for an operator-permitted local service. Returns CONFIGURATION_CONFLICT if an existing service differs.",
		Properties: map[string]any{
			"name":           map[string]any{"type": "string"},
			"port":           map[string]any{"type": "integer"},
			"path":           map[string]any{"type": "string"},
			"type":           map[string]any{"type": "string", "enum": []string{"mcp", "http"}},
			"authentication": map[string]any{"type": "string", "enum": []string{"ocliv-managed", "upstream-oauth"}},
			"persistent":     map[string]any{"type": "boolean"},
		},
		Required: []string{"name", "port"},
	},
	{
		Name:        "enable_service",
		Description: "Activate or resume an existing publication without changing its canonical URL or grants.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "disable_service",
		Description: "Disable public exposure while preserving canonical URL and OAuth grants. Reports UNCONFIRMED if relay denial cannot be confirmed.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "restart_service",
		Description: "Recover or rebind the tunnel without destroying service identity or URL.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "reconcile_service",
		Description: "Atomically repair stale publication bindings and confirm healthy convergence.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "remove_service",
		Description: "Permanently retire a hosted service and its publication. Preserves local record if remote revocation fails.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	// Authentication & access management
	{
		Name:        "get_auth_status",
		Description: "Inspect authentication mode, enforcement, and pending authorization counts.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "list_pending_authorizations",
		Description: "Retrieve pending native OAuth authorization transactions for a service.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "decide_authorization",
		Description: "Approve or deny one exact pending OAuth transaction by challenge ID (requires independent authorize_visitor permission).",
		Properties: map[string]any{
			"service":   map[string]any{"type": "string"},
			"challenge": map[string]any{"type": "string"},
			"decision":  map[string]any{"type": "string", "enum": []string{"approve", "deny"}},
		},
		Required: []string{"service", "challenge", "decision"},
	},
	{
		Name:        "list_authorized_clients",
		Description: "Retrieve the authoritative OAuth client grant inventory for a service from the relay.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "revoke_client",
		Description: "Immediately revoke OAuth access for one specific client ID on a service (requires independent revoke_client permission).",
		Properties: map[string]any{
			"service":  map[string]any{"type": "string"},
			"clientId": map[string]any{"type": "string"},
		},
		Required: []string{"service", "clientId"},
	},
	{
		Name:        "get_auth_policy",
		Description: "Inspect route-scoped trust policies and visitor authentication mode.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "set_auth_policy",
		Description: "Configure route-scoped OAuth trust preset (chatgpt) or exact HTTPS redirect URI (requires independent manage_auth_policy permission).",
		Properties: map[string]any{
			"service":     map[string]any{"type": "string"},
			"preset":      map[string]any{"type": "string", "enum": []string{"chatgpt"}},
			"redirectUri": map[string]any{"type": "string"},
		},
		Required: []string{"service"},
	},
	// Diagnostics & verification
	{
		Name:        "verify_service",
		Description: "Run canonical native transport, OAuth discovery, and MCP verification checks with explicit per-stage results.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "diagnose_service",
		Description: "Identify the exact failing operational layer using native multi-layer diagnostics.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "verify_events",
		Description: "Report canonical MCP Events verification stages honestly (unexercised stages remain UNKNOWN).",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
}

func mcpToolStringArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func mcpToolIntArg(args map[string]any, key string) (int, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	default:
		return 0, false
	}
}

func mcpToolBoolArg(args map[string]any, key string, defaultVal bool) (bool, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return defaultVal, true
	}
	b, ok := v.(bool)
	return b, ok
}

func validateMCPServiceName(name string) error {
	if !mcpServiceNameRe.MatchString(name) {
		return fmt.Errorf("invalid service name %q", name)
	}
	return nil
}

func validateMCPSafeID(id, label string) error {
	if !mcpSafeIDRe.MatchString(id) {
		return fmt.Errorf("invalid %s", label)
	}
	return nil
}

func sanitizeMCPError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	// Strip potential bearer tokens or query credentials from error strings.
	for _, kw := range []string{"Bearer ", "pairing_secret", "client_secret", "refresh_token", "access_token", "private_key"} {
		if idx := strings.Index(msg, kw); idx >= 0 {
			msg = msg[:idx] + "[redacted]"
		}
	}
	if len(msg) > 240 {
		msg = msg[:240] + "…"
	}
	return msg
}

func mcpToolResult(v any) map[string]any {
	b, _ := json.Marshal(v)
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(b)}},
		"structuredContent": v,
	}
}

func safeServiceSummary(rec config.ServiceRecord) map[string]any {
	svcID := ""
	if rec.Identity != nil {
		svcID = rec.Identity.ServiceID
	}
	return map[string]any{
		"name":           rec.Name,
		"service_id":     svcID,
		"type":           rec.Type,
		"profile":        rec.Profile,
		"local_url":      rec.LocalURL,
		"publication_id": rec.PublicationID,
		"public_url":     rec.PublicURL,
		"desired_state":  rec.DesiredState,
		"authentication": rec.Auth,
	}
}

func safeStatusReport(rep ServiceStatusReport) map[string]any {
	return map[string]any{
		"name":               rep.Name,
		"service_id":         rep.ServiceID,
		"type":               rep.Type,
		"profile":            rep.Profile,
		"desired_state":      rep.DesiredState,
		"observed_state":     rep.State,
		"health":             rep.Health,
		"running_now":        rep.RunningNow,
		"process_state":      rep.ProcessState,
		"relay_state":        rep.RelayState,
		"publication_id":     rep.PublicationID,
		"public_url":         rep.PublicURL,
		"authentication":     rep.AuthProfile,
		"backend_available":  rep.BackendAvailable,
		"public_transport":   rep.PublicTransport,
		"public_verified":    rep.PublicVerified,
		"verification_level": rep.VerificationLevel,
		"layers":             rep.Layers,
		"last_failure":       rep.LastFailure,
	}
}

// handleMCPManageTool dispatches ONLY the 20 advertised OCL-012/013 tools
// against Ocliv's canonical native Go service/lifecycle/authz/verification
// operations while enforcing per-principal durable operator permissions.
func handleMCPManageTool(principal, name string, args map[string]any, relayURL string, k *identity.KeyPair, keyID string, ops serviceOps) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	pol, perr := loadAgentPermissionsPolicy()
	if perr != nil {
		return nil, fmt.Errorf("permissions policy unavailable: %s", sanitizeMCPError(perr))
	}
	store, serr := openServices()
	if serr != nil {
		return nil, fmt.Errorf("service store unavailable: %s", sanitizeMCPError(serr))
	}

	// authorizeAction checks durable permissions first, then single-use operator
	// approvals; if denied, records a durable pending approval request and
	// returns an actionable OPERATOR_AUTHORIZATION_REQUIRED structured payload.
	authorizeAction := func(action, serviceName, serviceID string, port int, authMode string) (map[string]any, bool) {
		if ok, _, _ := pol.check(principal, action, serviceName, serviceID, port, authMode); ok {
			return nil, true
		}
		if consumeSingleUseApproval(principal, action, serviceName, port) {
			return nil, true
		}
		req, _ := createOperatorApprovalRequest(principal, name, action, serviceName, serviceID, port, authMode)
		return map[string]any{
			"ok":                    false,
			"status":                "OPERATOR_AUTHORIZATION_REQUIRED",
			"request_id":            req.RequestID,
			"principal":             principal,
			"action":                name,
			"service":               serviceName,
			"requested_permissions": []string{action},
			"message":               "Review this request in Ocliv Control Center.",
		}, false
	}

	resolveSvc := func(svcName string) (config.ServiceRecord, string, string, *identity.KeyPair, string, error) {
		if err := validateMCPServiceName(svcName); err != nil {
			return config.ServiceRecord{}, "", "", nil, "", err
		}
		rec, ok, err := store.Get(svcName)
		if err != nil || !ok {
			return config.ServiceRecord{}, "", "", nil, "", fmt.Errorf("unknown service %q", svcName)
		}
		svcID := ""
		if rec.Identity != nil {
			svcID = rec.Identity.ServiceID
		}
		rk, rKeyID := k, keyID
		if rec.Profile != "" && rec.Profile != config.ActiveProfile() {
			if pk, pkID, kerr := loadKeyForProfile(rec.Profile); kerr == nil {
				rk, rKeyID = pk, pkID
			}
		}
		rURL := rec.RelayURL
		if rURL == "" {
			if rec.Profile != "" {
				rURL = agentRelayURLForProfile(rec.Profile)
			} else {
				rURL = relayURL
			}
		}
		return rec, svcID, rURL, rk, rKeyID, nil
	}

	switch name {
	case "get_status":
		if denied, ok := authorizeAction("inspect", "", "", 0, ""); !ok {
			return denied, nil
		}
		svcs, _ := store.List()
		visibleCount := 0
		for _, rec := range svcs {
			svcID := ""
			if rec.Identity != nil {
				svcID = rec.Identity.ServiceID
			}
			if pol.canAccessService(principal, rec.Name, svcID) {
				visibleCount++
			}
		}
		pubs, _, pubErr := fetchRelayPublications(relayURL, k, keyID, ops)
		return map[string]any{
			"ok":               true,
			"principal":        principal,
			"relay_url":        relayURL,
			"key_id":           keyID,
			"relay_reachable":  pubErr == nil,
			"publications":     len(pubs),
			"services_count":   visibleCount,
			"version":          buildVersionInfo(),
			"permissions_mode": "operator-controlled",
		}, nil

	case "list_services":
		if denied, ok := authorizeAction("inspect", "", "", 0, ""); !ok {
			return denied, nil
		}
		svcs, err := store.List()
		if err != nil {
			return nil, fmt.Errorf("list services failed")
		}
		items := make([]map[string]any, 0, len(svcs))
		for _, rec := range svcs {
			svcID := ""
			if rec.Identity != nil {
				svcID = rec.Identity.ServiceID
			}
			// Filter discovery strictly by principal service allowlist.
			if !pol.canAccessService(principal, rec.Name, svcID) {
				continue
			}
			items = append(items, safeServiceSummary(rec))
		}
		return map[string]any{"ok": true, "services": items}, nil

	case "get_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("inspect", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		rep := inspectServiceStatus(rec, rk, rKeyID, ops)
		return map[string]any{"ok": true, "service": safeStatusReport(rep)}, nil

	case "get_url":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("get_url", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		rep := inspectServiceStatus(rec, rk, rKeyID, ops)
		entry, _ := resolveCatalogEntry(svcName, rec.Profile, ops)
		pubURL := rep.PublicURL
		if pubURL == "" {
			pubURL = entry.URL
		}
		pubID := rep.PublicationID
		if pubID == "" {
			pubID = entry.RouteID
		}
		if pubURL == "" {
			return nil, fmt.Errorf("no canonical public URL available for service %q", svcName)
		}
		auth := rep.AuthProfile
		if auth == "" {
			auth = entry.AuthMethod
		}
		return map[string]any{
			"service":        svcName,
			"service_id":     svcID,
			"publication_id": pubID,
			"url":            pubURL,
			"enabled":        rec.DesiredState == config.DesiredEnabled,
			"reachable":      rep.State == ServiceStateServing && rep.Health == HealthReady,
			"state":          rep.State,
			"authentication": auth,
		}, nil

	case "deploy_service":
		svcName := mcpToolStringArg(args, "name")
		if err := validateMCPServiceName(svcName); err != nil {
			return nil, err
		}
		port, portOK := mcpToolIntArg(args, "port")
		if !portOK || port < 1 || port > 65535 {
			return nil, fmt.Errorf("port must be an integer between 1 and 65535")
		}
		svcType := mcpToolStringArg(args, "type")
		if svcType == "" {
			svcType = "mcp"
		}
		if svcType != "mcp" && svcType != "http" {
			return nil, fmt.Errorf("type must be mcp or http")
		}
		authMode := mcpToolStringArg(args, "authentication")
		if authMode == "" {
			authMode = "ocliv-managed"
		}
		if authMode != "ocliv-managed" && authMode != "upstream-oauth" {
			return nil, fmt.Errorf("authentication must be ocliv-managed or upstream-oauth")
		}
		localPath := mcpToolStringArg(args, "path")
		if localPath == "" {
			if svcType == "mcp" {
				localPath = "/mcp"
			} else {
				localPath = "/"
			}
		}
		if !strings.HasPrefix(localPath, "/") || strings.Contains(localPath, "..") || strings.ContainsAny(localPath, " \t\r\n") {
			return nil, fmt.Errorf("path must be a clean absolute path")
		}
		persistent, persistOK := mcpToolBoolArg(args, "persistent", true)
		if !persistOK {
			return nil, fmt.Errorf("persistent must be a boolean")
		}
		wantLocalURL := fmt.Sprintf("http://127.0.0.1:%d%s", port, localPath)

		existing, exists, _ := store.Get(svcName)
		existingSvcID := ""
		if exists && existing.Identity != nil {
			existingSvcID = existing.Identity.ServiceID
		}
		if denied, ok := authorizeAction("deployment", svcName, existingSvcID, port, authMode); !ok {
			return denied, nil
		}

		// Exact-match idempotency check: reject differing configurations fail-closed.
		if exists {
			if existing.LocalURL != wantLocalURL || existing.Type != svcType || existing.Auth != authMode {
				return map[string]any{
					"ok":        false,
					"status":    "CONFIGURATION_CONFLICT",
					"operation": "deploy_service",
					"service":   svcName,
					"existing": map[string]any{
						"local_url":      existing.LocalURL,
						"type":           existing.Type,
						"authentication": existing.Auth,
					},
					"requested": map[string]any{
						"local_url":      wantLocalURL,
						"type":           svcType,
						"authentication": authMode,
					},
					"message": "Existing service configuration differs; refusing silent replacement.",
				}, nil
			}
			rep, rerr := reconcileServiceOnce(store, existing.Name, k, keyID, ops, time.Now())
			confirmed := rerr == nil && rep.State == ServiceStateServing && rep.Health == HealthReady
			return map[string]any{
				"ok":             confirmed,
				"operation":      "deploy_service",
				"idempotent":     true,
				"confirmed":      confirmed,
				"service":        svcName,
				"desired_state":  existing.DesiredState,
				"observed_state": rep.State,
				"publication_id": rep.PublicationID,
				"public_url":     rep.PublicURL,
				"detail":         sanitizeMCPError(rerr),
			}, nil
		}

		// Canonical registration + activation through shared native hosted-service workflows.
		rec, _, _, regErr := registerHostedService(serviceAddRequest{
			Name:        svcName,
			Type:        svcType,
			LocalURL:    wantLocalURL,
			Auth:        authMode,
			Profile:     config.ActiveProfile(),
			BackendMode: config.BackendAttached,
		}, ops)
		if regErr != nil {
			return map[string]any{
				"ok":        false,
				"operation": "deploy_service",
				"service":   svcName,
				"confirmed": false,
				"status":    "UNCONFIRMED",
				"detail":    sanitizeMCPError(regErr),
			}, nil
		}
		if !persistent {
			rep := inspectServiceStatus(rec, k, keyID, ops)
			return map[string]any{
				"ok":             true,
				"operation":      "deploy_service",
				"idempotent":     false,
				"confirmed":      true,
				"service":        svcName,
				"desired_state":  rec.DesiredState,
				"observed_state": rep.State,
				"public_url":     rep.PublicURL,
			}, nil
		}
		startOut, _, startErr := startHostedService(serviceStartRequest{Name: svcName}, ops)
		confirmed := startErr == nil && startOut.Status.State == ServiceStateServing && startOut.Status.Health == HealthReady
		status := "CONFIRMED"
		if !confirmed {
			status = "UNCONFIRMED"
		}
		return map[string]any{
			"ok":             confirmed,
			"status":         status,
			"operation":      "deploy_service",
			"idempotent":     false,
			"confirmed":      confirmed,
			"service":        svcName,
			"desired_state":  config.DesiredEnabled,
			"observed_state": startOut.Status.State,
			"publication_id": startOut.Status.PublicationID,
			"public_url":     startOut.Status.PublicURL,
			"detail":         sanitizeMCPError(startErr),
		}, nil

	case "enable_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, _, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("lifecycle", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		out, _, startErr := startHostedService(serviceStartRequest{Name: rec.Name}, ops)
		confirmed := startErr == nil && out.Status.State == ServiceStateServing && out.Status.Health == HealthReady
		status := "CONFIRMED"
		if !confirmed {
			status = "UNCONFIRMED"
		}
		return map[string]any{
			"ok":             confirmed,
			"status":         status,
			"operation":      "enable_service",
			"service":        rec.Name,
			"desired_state":  config.DesiredEnabled,
			"observed_state": out.Status.State,
			"publication_id": out.Status.PublicationID,
			"public_url":     out.Status.PublicURL,
			"confirmed":      confirmed,
			"detail":         sanitizeMCPError(startErr),
		}, nil

	case "disable_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("lifecycle", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		res := stopServiceAuthoritatively(store, rec, rk, rKeyID, ops)
		confirmed := res.Stopped && res.RemoteDisabled
		status := "CONFIRMED"
		if !confirmed {
			status = "UNCONFIRMED"
		}
		return map[string]any{
			"ok":                    confirmed,
			"status":                status,
			"operation":             "disable_service",
			"service":               rec.Name,
			"desired_state":         config.DesiredDisabled,
			"observed_state":        res.State,
			"public_access_blocked": res.RemoteDisabled,
			"url_retained":          res.RetainedURL != "",
			"retained_url":          res.RetainedURL,
			"confirmed":             confirmed,
			"detail":                res.Detail,
		}, nil

	case "restart_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, _, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("lifecycle", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		out, _, restErr := restartHostedServiceInProfile(rec.Profile, rec.Name, ops)
		confirmed := restErr == nil && out.Status.State == ServiceStateServing && out.Status.Health == HealthReady
		status := "CONFIRMED"
		if !confirmed {
			status = "UNCONFIRMED"
		}
		return map[string]any{
			"ok":             confirmed,
			"status":         status,
			"operation":      "restart_service",
			"service":        rec.Name,
			"desired_state":  rec.DesiredState,
			"observed_state": out.Status.State,
			"publication_id": out.Status.PublicationID,
			"public_url":     out.Status.PublicURL,
			"confirmed":      confirmed,
			"detail":         sanitizeMCPError(restErr),
		}, nil

	case "reconcile_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("lifecycle", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		rep, rerr := reconcileServiceOnce(store, rec.Name, rk, rKeyID, ops, time.Now())
		healthy := rerr == nil && rep.Health == HealthReady && (rec.DesiredState != config.DesiredEnabled || rep.State == ServiceStateServing)
		status := "CONFIRMED"
		if !healthy {
			status = "UNCONFIRMED"
		}
		return map[string]any{
			"ok":             healthy,
			"status":         status,
			"operation":      "reconcile_service",
			"service":        rec.Name,
			"desired_state":  rec.DesiredState,
			"observed_state": rep.State,
			"health":         rep.Health,
			"publication_id": rep.PublicationID,
			"public_url":     rep.PublicURL,
			"confirmed":      healthy,
			"detail":         sanitizeMCPError(rerr),
		}, nil

	case "remove_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("remove_publication", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		// Authoritative removal preserves the local record if remote revocation cannot be confirmed.
		pubID, remErr := removeServiceAuthoritatively(store, rec, rk, rKeyID, ops)
		if remErr != nil {
			return map[string]any{
				"ok":             false,
				"status":         "UNCONFIRMED",
				"operation":      "remove_service",
				"service":        rec.Name,
				"confirmed":      false,
				"record_kept":    true,
				"publication_id": rec.PublicationID,
				"detail":         sanitizeMCPError(remErr),
			}, nil
		}
		return map[string]any{
			"ok":             true,
			"status":         "CONFIRMED",
			"operation":      "remove_service",
			"service":        rec.Name,
			"publication_id": pubID,
			"removed":        true,
			"confirmed":      true,
		}, nil

	case "get_auth_status":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, rURL, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("inspect", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		rep := inspectServiceStatus(rec, rk, rKeyID, ops)
		pubID, _, found, rerr := resolveRelayPublication(rURL, rk, rKeyID, rec, ops)
		pendingCount := 0
		pendingTxCount := 0
		if rerr == nil && found && pubID != "" {
			if st, body, cerr := ops.mgmtCall(rURL, rk, rKeyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/pending"); cerr == nil && st == http.StatusOK {
				var p struct {
					Pending             []any `json:"pending"`
					PendingTransactions []any `json:"pending_transactions"`
				}
				if json.Unmarshal(body, &p) == nil {
					pendingCount = len(p.Pending)
					pendingTxCount = len(p.PendingTransactions)
				}
			}
		}
		return map[string]any{
			"ok":                         true,
			"service":                    svcName,
			"publication_id":             pubID,
			"authentication":             rep.AuthProfile,
			"authorization_layer":        rep.Layers.Authorization,
			"pending_clients_count":      pendingCount,
			"pending_transactions_count": pendingTxCount,
		}, nil

	case "list_pending_authorizations":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, rURL, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("inspect", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, rk, rKeyID, rec, ops)
		if rerr != nil {
			return nil, fmt.Errorf("cannot resolve publication: %s", sanitizeMCPError(rerr))
		}
		if !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		st, body, cerr := ops.mgmtCall(rURL, rk, rKeyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/pending")
		if cerr != nil || st != http.StatusOK {
			return nil, fmt.Errorf("relay pending query failed (HTTP %d)", st)
		}
		var out struct {
			Pending []struct {
				ClientID     string `json:"client_id"`
				Name         string `json:"name"`
				RedirectURIs string `json:"redirect_uris"`
				Status       string `json:"status"`
				CreatedAt    string `json:"created_at"`
			} `json:"pending"`
			PendingTransactions []struct {
				Challenge   string `json:"challenge"`
				ClientID    string `json:"client_id"`
				ClientName  string `json:"client_name"`
				RedirectURI string `json:"redirect_uri"`
				Scope       string `json:"scope"`
				ExpiresAt   string `json:"expires_at"`
			} `json:"pending_transactions"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("unparseable relay pending response")
		}
		return map[string]any{
			"ok":                   true,
			"service":              svcName,
			"publication_id":       pubID,
			"pending_clients":      out.Pending,
			"pending_transactions": out.PendingTransactions,
		}, nil

	case "decide_authorization":
		svcName := mcpToolStringArg(args, "service")
		challenge := mcpToolStringArg(args, "challenge")
		decision := mcpToolStringArg(args, "decision")
		if err := validateMCPSafeID(challenge, "challenge"); err != nil {
			return nil, err
		}
		if decision != "approve" && decision != "deny" {
			return nil, fmt.Errorf("decision must be approve or deny")
		}
		rec, svcID, rURL, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("authorize_visitor", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, rk, rKeyID, rec, ops)
		if rerr != nil || !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		path := "/v1/agent/mcp-routes/" + pubID + "/authz/consents/" + challenge + "/" + decision
		st, body, cerr := ops.mgmtCall(rURL, rk, rKeyID, http.MethodPost, path)
		if cerr != nil || (st != http.StatusOK && st != http.StatusCreated) {
			return nil, fmt.Errorf("authorization decision failed (HTTP %d)", st)
		}
		var resp struct {
			Challenge string `json:"challenge"`
			ClientID  string `json:"client_id"`
			Decision  string `json:"decision"`
		}
		_ = json.Unmarshal(body, &resp)
		return map[string]any{
			"ok":             true,
			"service":        svcName,
			"publication_id": pubID,
			"challenge":      resp.Challenge,
			"client_id":      resp.ClientID,
			"decision":       decision,
			"confirmed":      true,
		}, nil

	case "list_authorized_clients":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, rURL, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("inspect", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, rk, rKeyID, rec, ops)
		if rerr != nil || !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		st, body, cerr := ops.mgmtCall(rURL, rk, rKeyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/clients")
		if cerr != nil || st != http.StatusOK {
			return map[string]any{
				"ok":             false,
				"status":         "AUTHORITATIVE_CLIENTS_UNAVAILABLE",
				"service":        svcName,
				"publication_id": pubID,
				"clients":        []any{},
				"detail":         fmt.Sprintf("relay returned HTTP %d for /authz/clients (upgrade relay to inspect authoritative client grants)", st),
			}, nil
		}
		var out struct {
			Clients []struct {
				ClientID      string   `json:"client_id"`
				ClientName    string   `json:"client_name"`
				AuthMethod    string   `json:"auth_method"`
				Status        string   `json:"status"`
				PublicationID string   `json:"publication_id"`
				RedirectURIs  []string `json:"redirect_uris"`
				AuthorizedAt  string   `json:"authorized_at"`
				UpdatedAt     string   `json:"updated_at"`
				RevokedAt     *string  `json:"revoked_at,omitempty"`
				TrustPolicyID string   `json:"trust_policy_id,omitempty"`
			} `json:"clients"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("unparseable relay client inventory")
		}
		return map[string]any{
			"ok":             true,
			"service":        svcName,
			"publication_id": pubID,
			"clients":        out.Clients,
		}, nil

	case "revoke_client":
		svcName := mcpToolStringArg(args, "service")
		clientID := mcpToolStringArg(args, "clientId")
		if err := validateMCPSafeID(clientID, "clientId"); err != nil {
			return nil, err
		}
		rec, svcID, rURL, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("revoke_client", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, rk, rKeyID, rec, ops)
		if rerr != nil || !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		st, _, cerr := ops.mgmtCall(rURL, rk, rKeyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/authz/revoke/"+clientID)
		if cerr != nil || st != http.StatusOK {
			return map[string]any{
				"ok":        false,
				"status":    "UNCONFIRMED",
				"service":   svcName,
				"client_id": clientID,
				"confirmed": false,
				"detail":    fmt.Sprintf("relay revoke failed (HTTP %d)", st),
			}, nil
		}
		return map[string]any{
			"ok":             true,
			"status":         "CONFIRMED",
			"service":        svcName,
			"publication_id": pubID,
			"client_id":      clientID,
			"revoked":        true,
			"confirmed":      true,
		}, nil

	case "get_auth_policy":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, rURL, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("inspect", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, rk, rKeyID, rec, ops)
		if rerr != nil || !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		var trustPolicies []map[string]any
		if st, body, cerr := ops.mgmtCall(rURL, rk, rKeyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/trust"); cerr == nil && st == http.StatusOK {
			var tResp struct {
				Policies []struct {
					ID           string   `json:"id"`
					Kind         string   `json:"kind"`
					RedirectURIs []string `json:"redirect_uris"`
					Enabled      bool     `json:"enabled"`
				} `json:"policies"`
			}
			if json.Unmarshal(body, &tResp) == nil {
				for _, p := range tResp.Policies {
					trustPolicies = append(trustPolicies, map[string]any{
						"id":            p.ID,
						"kind":          p.Kind,
						"redirect_uris": p.RedirectURIs,
						"enabled":       p.Enabled,
					})
				}
			}
		}
		visitorMode := "native"
		if st, body, cerr := ops.mgmtCall(rURL, rk, rKeyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/visitor-auth"); cerr == nil && st == http.StatusOK {
			var vResp struct {
				Policy struct {
					Mode string `json:"mode"`
				} `json:"policy"`
			}
			if json.Unmarshal(body, &vResp) == nil && vResp.Policy.Mode != "" {
				visitorMode = vResp.Policy.Mode
			}
		}
		return map[string]any{
			"ok":             true,
			"service":        svcName,
			"publication_id": pubID,
			"visitor_mode":   visitorMode,
			"trust_policies": trustPolicies,
		}, nil

	case "set_auth_policy":
		svcName := mcpToolStringArg(args, "service")
		preset := mcpToolStringArg(args, "preset")
		redirectURI := mcpToolStringArg(args, "redirectUri")
		rec, svcID, rURL, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		// Strictly independent permission from authorize_visitor.
		if denied, ok := authorizeAction("manage_auth_policy", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, rk, rKeyID, rec, ops)
		if rerr != nil || !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		var redirects []string
		if preset != "" && preset != "chatgpt" {
			return nil, fmt.Errorf("unsupported preset %q", preset)
		}
		if redirectURI != "" {
			if !strings.HasPrefix(redirectURI, "https://") {
				return nil, fmt.Errorf("redirectUri must be an exact https:// URI")
			}
			redirects = []string{redirectURI}
		}
		if preset == "" && len(redirects) == 0 {
			return nil, fmt.Errorf("preset or redirectUri is required")
		}
		polRes, status, _, perr := applyTrustPolicyToRoute(rURL, rk, rKeyID, pubID, preset, redirects, ops)
		if perr != nil {
			return nil, fmt.Errorf("set_auth_policy failed: %s", sanitizeMCPError(perr))
		}
		return map[string]any{
			"ok":             true,
			"service":        svcName,
			"publication_id": pubID,
			"status":         status,
			"policy_id":      polRes.ID,
			"kind":           polRes.Kind,
			"confirmed":      true,
		}, nil

	case "verify_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("verify", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		rep := inspectServiceStatus(rec, rk, rKeyID, ops)
		entry, _ := resolveCatalogEntry(svcName, rec.Profile, ops)
		endpointStage := "FAIL"
		oauthStage := "UNKNOWN"
		if entry.URL != "" {
			d := runReadOnlyDiscoveryCheck(&http.Client{Timeout: 8 * time.Second}, entry.URL)
			endpointStage = d.Transport
			oauthStage = d.Discovery
		}
		authMCPStage := "UNKNOWN"
		externalStage := "UNKNOWN"
		if rep.PublicVerified {
			authMCPStage = "PASS"
		}
		if rep.VerificationEvidence != nil && rep.VerificationEvidence.Stage == "EXTERNAL_CLIENT_VERIFIED" {
			externalStage = "PASS"
		}
		return map[string]any{
			"ok":             endpointStage == "PASS" && oauthStage == "PASS" && rep.Health == HealthReady,
			"service":        svcName,
			"publication_id": rep.PublicationID,
			"url":            entry.URL,
			"stages": map[string]string{
				"public_endpoint_reachable":    endpointStage,
				"oauth_discovery_compatible":   oauthStage,
				"authenticated_mcp_handshake":  authMCPStage,
				"events_advertised":            "UNKNOWN",
				"events_subscription_verified": "UNKNOWN",
				"callback_delivery_verified":   "UNKNOWN",
				"external_client_acceptance":   externalStage,
			},
			"status": safeStatusReport(rep),
		}, nil

	case "diagnose_service":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("inspect", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		rep := inspectServiceStatus(rec, rk, rKeyID, ops)
		layer, classification, errCode := classifyFailureLayer(rep)
		return map[string]any{
			"ok":             true,
			"service":        svcName,
			"failing_layer":  layer,
			"classification": classification,
			"error_code":     errCode,
			"status":         safeStatusReport(rep),
		}, nil

	case "verify_events":
		svcName := mcpToolStringArg(args, "service")
		rec, svcID, _, rk, rKeyID, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if denied, ok := authorizeAction("verify", rec.Name, svcID, 0, ""); !ok {
			return denied, nil
		}
		rep := inspectServiceStatus(rec, rk, rKeyID, ops)
		entry, _ := resolveCatalogEntry(svcName, rec.Profile, ops)
		if entry.URL == "" {
			return nil, fmt.Errorf("no canonical URL available for service %q", svcName)
		}
		d := runReadOnlyDiscoveryCheck(&http.Client{Timeout: 8 * time.Second}, entry.URL)
		// Never misrepresent OAuth metadata discovery as authenticated Events verification.
		return map[string]any{
			"ok":             false,
			"verified":       false,
			"service":        svcName,
			"publication_id": rep.PublicationID,
			"url":            entry.URL,
			"stages": map[string]string{
				"public_endpoint_reachable":    d.Transport,
				"oauth_discovery_compatible":   d.Discovery,
				"authenticated_mcp_handshake":  "UNKNOWN",
				"events_advertised":            "UNKNOWN",
				"events_subscription_verified": "UNKNOWN",
				"callback_delivery_verified":   "UNKNOWN",
				"external_client_acceptance":   "UNKNOWN",
			},
			"detail": "Authenticated Events qualification requires an operator-supplied visitor token via `ocliv mcp check NAME --capability events --token-file PATH` or Ocliv Control Center.",
		}, nil
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}
