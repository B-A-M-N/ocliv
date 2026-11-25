package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

// OCL-012 Agent-Facing MCP Control Plane tool catalog (closed set by construction:
// no shell, exec, or arbitrary command tool exists and none can be added by callers).
type mcpManageToolSpec struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
}

var ocl012ManageToolSpecs = []mcpManageToolSpec{
	// Discovery & URL retrieval
	{
		Name:        "get_status",
		Description: "Return relay connectivity, publisher enrollment, binary version, and capabilities.",
		Properties:  map[string]any{},
	},
	{
		Name:        "list_services",
		Description: "List all configured local services, including disabled and unpublished services.",
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
		Description: "Idempotently create or attach a protected publication for an operator-permitted local service.",
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
		Description: "Disable public exposure while preserving canonical URL and OAuth grants.",
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
		Description: "Atomically repair stale publication bindings and resolve configuration drift.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "remove_service",
		Description: "Permanently retire a hosted service and its publication.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	// Authentication & access management
	{
		Name:        "get_auth_status",
		Description: "Inspect authentication mode, enforcement, trust policies, and pending authorizations.",
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
		Description: "Inspect route-scoped trust policies and provider client bindings.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
	{
		Name:        "revoke_client",
		Description: "Immediately revoke OAuth access for one specific client ID on a service.",
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
		Description: "Configure route-scoped OAuth trust preset (chatgpt) or exact HTTPS redirect URI.",
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
		Description: "Run canonical native transport, OAuth discovery, and MCP verification checks.",
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
		Description: "Verify MCP Events discovery and capability readiness.",
		Properties:  map[string]any{"service": map[string]any{"type": "string"}},
		Required:    []string{"service"},
	},
}

// agentPermissionsPolicy models the operator-controlled 0600 permissions file
// (`~/.config/ocliv/agent-permissions.json`). No MCP tool can modify this file.
type agentPermissionsFlags struct {
	Inspect           bool `json:"inspect"`
	GetURL            bool `json:"get_url"`
	Verify            bool `json:"verify"`
	Lifecycle         bool `json:"lifecycle"`
	Deployment        bool `json:"deployment"`
	AuthorizeVisitor  bool `json:"authorize_visitor"`
	RevokeClient      bool `json:"revoke_client"`
	RemovePublication bool `json:"remove_publication"`
}

type agentPermissionsPolicy struct {
	AgentPermissions agentPermissionsFlags `json:"agent_permissions"`
	AllowedServices  []string              `json:"allowed_services,omitempty"`
	AllowedPorts     []int                 `json:"allowed_ports,omitempty"`
	AllowedAuthModes []string              `json:"allowed_auth_modes,omitempty"`
}

func defaultLocalAgentPermissions() agentPermissionsPolicy {
	// Safe fail-closed default when no operator policy file exists:
	// read-only discovery/URL/verification allowed for local stdio; ALL mutating
	// and sensitive capabilities denied until explicitly granted by the operator.
	return agentPermissionsPolicy{
		AgentPermissions: agentPermissionsFlags{
			Inspect: true,
			GetURL:  true,
			Verify:  true,
		},
		AllowedServices:  []string{"*"},
		AllowedAuthModes: []string{"ocliv-managed"},
	}
}

func loadAgentPermissionsPolicy() (agentPermissionsPolicy, error) {
	path := strings.TrimSpace(os.Getenv("OCLIV_PERMISSIONS_FILE"))
	if path == "" {
		dir, _, _, err := agentFiles()
		if err != nil {
			return defaultLocalAgentPermissions(), nil
		}
		path = filepath.Join(dir, "agent-permissions.json")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultLocalAgentPermissions(), nil
		}
		return agentPermissionsPolicy{}, fmt.Errorf("open agent-permissions.json: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return agentPermissionsPolicy{}, err
	}
	if !fi.Mode().IsRegular() || (fi.Mode().Perm()&0o077) != 0 {
		return agentPermissionsPolicy{}, fmt.Errorf("agent-permissions.json must be a regular 0600 file")
	}
	var pol agentPermissionsPolicy
	if err := json.NewDecoder(f).Decode(&pol); err != nil {
		return agentPermissionsPolicy{}, fmt.Errorf("invalid agent-permissions.json: %w", err)
	}
	if len(pol.AllowedServices) == 0 {
		pol.AllowedServices = []string{"*"}
	}
	if len(pol.AllowedAuthModes) == 0 {
		pol.AllowedAuthModes = []string{"ocliv-managed"}
	}
	return pol, nil
}

func (p agentPermissionsPolicy) check(action, service string, port int, authMode string) error {
	var ok bool
	switch action {
	case "inspect":
		ok = p.AgentPermissions.Inspect
	case "get_url":
		ok = p.AgentPermissions.GetURL
	case "verify":
		ok = p.AgentPermissions.Verify
	case "lifecycle":
		ok = p.AgentPermissions.Lifecycle
	case "deployment":
		ok = p.AgentPermissions.Deployment
	case "authorize_visitor":
		ok = p.AgentPermissions.AuthorizeVisitor
	case "revoke_client":
		ok = p.AgentPermissions.RevokeClient
	case "remove_publication":
		ok = p.AgentPermissions.RemovePublication
	default:
		return fmt.Errorf("unknown permission action %q", action)
	}
	if !ok {
		return fmt.Errorf("permission denied: operator has not granted %q in agent-permissions.json", action)
	}
	if service != "" {
		allowed := false
		for _, s := range p.AllowedServices {
			if s == "*" || s == service {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("permission denied: service %q is outside operator allowed_services", service)
		}
	}
	if action == "deployment" {
		if port > 0 && len(p.AllowedPorts) > 0 {
			portOK := false
			for _, ap := range p.AllowedPorts {
				if ap == port {
					portOK = true
					break
				}
			}
			if !portOK {
				return fmt.Errorf("permission denied: port %d is outside operator allowed_ports", port)
			}
		}
		if authMode != "" {
			modeOK := false
			for _, am := range p.AllowedAuthModes {
				if am == authMode {
					modeOK = true
					break
				}
			}
			if !modeOK {
				return fmt.Errorf("permission denied: auth mode %q is outside operator allowed_auth_modes", authMode)
			}
		}
	}
	return nil
}

func mcpToolStringArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func mcpToolIntArg(args map[string]any, key string) int {
	v, ok := args[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func mcpToolResult(v any) map[string]any {
	b, _ := json.Marshal(v)
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(b)}},
		"structuredContent": v,
	}
}

// handleMCPManageTool dispatches all 20 OCL-012 agent-facing MCP control-plane
// tools directly against Ocliv's canonical native Go service/reconcile/authz/check
// operations while enforcing operator-controlled durable permissions.
func handleMCPManageTool(name string, args map[string]any, relayURL string, k *identity.KeyPair, keyID string, ops serviceOps) (any, error) {
	pol, perr := loadAgentPermissionsPolicy()
	if perr != nil {
		return nil, perr
	}
	store, serr := openServices()
	if serr != nil {
		return nil, serr
	}

	resolveSvc := func(svcName string) (config.ServiceRecord, string, error) {
		if svcName == "" {
			return config.ServiceRecord{}, "", fmt.Errorf("service name is required")
		}
		rec, ok, err := store.Get(svcName)
		if err != nil || !ok {
			return config.ServiceRecord{}, "", fmt.Errorf("unknown service %q", svcName)
		}
		rURL := rec.RelayURL
		if rURL == "" {
			rURL = relayURL
		}
		return rec, rURL, nil
	}

	switch name {
	case "get_status":
		if err := pol.check("inspect", "", 0, ""); err != nil {
			return nil, err
		}
		svcs, _ := store.List()
		pubs, _, pubErr := fetchRelayPublications(relayURL, k, keyID, ops)
		return map[string]any{
			"ok":               true,
			"relay_url":        relayURL,
			"key_id":           keyID,
			"relay_reachable":  pubErr == nil,
			"publications":     len(pubs),
			"services_count":   len(svcs),
			"version":          buildVersionInfo(),
			"permissions_mode": "operator-controlled",
		}, nil

	case "list_services":
		if err := pol.check("inspect", "", 0, ""); err != nil {
			return nil, err
		}
		svcs, err := store.List()
		if err != nil {
			return nil, err
		}
		items := make([]map[string]any, 0, len(svcs))
		for _, rec := range svcs {
			items = append(items, map[string]any{
				"name":           rec.Name,
				"type":           rec.Type,
				"profile":        rec.Profile,
				"local_url":      rec.LocalURL,
				"publication_id": rec.PublicationID,
				"public_url":     rec.PublicURL,
				"desired_state":  rec.DesiredState,
				"authentication": rec.Auth,
			})
		}
		return map[string]any{"ok": true, "services": items}, nil

	case "get_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("inspect", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		rep := inspectServiceStatus(rec, k, keyID, ops)
		return map[string]any{"ok": true, "service": rep}, nil

	case "get_url":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("get_url", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		rep := inspectServiceStatus(rec, k, keyID, ops)
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
			"publication_id": pubID,
			"url":            pubURL,
			"enabled":        rec.DesiredState == config.DesiredEnabled,
			"reachable":      rep.State == ServiceStateServing && rep.Health == HealthReady,
			"state":          rep.State,
			"authentication": auth,
		}, nil

	case "deploy_service":
		svcName := mcpToolStringArg(args, "name")
		port := mcpToolIntArg(args, "port")
		svcType := mcpToolStringArg(args, "type")
		if svcType == "" {
			svcType = "mcp"
		}
		authMode := mcpToolStringArg(args, "authentication")
		if authMode == "" {
			authMode = "ocliv-managed"
		}
		if svcName == "" || port < 1 || port > 65535 {
			return nil, fmt.Errorf("valid name and port (1-65535) are required")
		}
		if err := pol.check("deployment", svcName, port, authMode); err != nil {
			return nil, err
		}
		// Idempotent: if service already exists, reconcile/enable rather than duplicating.
		if rec, exists, gerr := store.Get(svcName); gerr == nil && exists {
			rep, rerr := reconcileServiceOnce(store, rec.Name, k, keyID, ops, time.Now())
			if rerr != nil {
				return nil, rerr
			}
			return map[string]any{"ok": true, "idempotent": true, "service": rep}, nil
		}
		localPath := mcpToolStringArg(args, "path")
		if localPath == "" {
			localPath = "/mcp"
		}
		if err := store.Put(config.ServiceRecord{
			Name:         svcName,
			Type:         svcType,
			LocalURL:     fmt.Sprintf("http://127.0.0.1:%d%s", port, localPath),
			Auth:         authMode,
			Profile:      config.ActiveProfile(),
			RelayURL:     relayURL,
			DesiredState: config.DesiredConfigured,
		}); err != nil {
			return nil, err
		}
		rec, _, _ := store.Get(svcName)
		rep := inspectServiceStatus(rec, k, keyID, ops)
		return map[string]any{"ok": true, "idempotent": false, "service": rep}, nil

	case "enable_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("lifecycle", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr == nil && found && pubID != "" {
			_, _, _ = ops.mgmtCall(rURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/enable")
		}
		if rec.SystemdUnit != "" && ops.systemctl != nil {
			_, _ = ops.systemctl("start", rec.SystemdUnit)
		}
		_, _ = store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.DesiredState = config.DesiredEnabled
			return nil
		})
		rep, rerr := reconcileServiceOnce(store, rec.Name, k, keyID, ops, time.Now())
		return map[string]any{"ok": rerr == nil, "service": rep}, rerr

	case "disable_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("lifecycle", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr == nil && found && pubID != "" {
			_, _, _ = ops.mgmtCall(rURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/disable")
		}
		if rec.SystemdUnit != "" && ops.systemctl != nil {
			_, _ = ops.systemctl("stop", rec.SystemdUnit)
		}
		updated, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.DesiredState = config.DesiredDisabled
			return nil
		})
		if uerr != nil {
			return nil, uerr
		}
		rep := inspectServiceStatus(updated, k, keyID, ops)
		return map[string]any{"ok": true, "service": rep}, nil

	case "restart_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("lifecycle", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		if rec.SystemdUnit != "" && ops.systemctl != nil {
			if out, serr := ops.systemctl("restart", rec.SystemdUnit); serr != nil {
				return nil, fmt.Errorf("restart failed: %v (%s)", serr, strings.TrimSpace(out))
			}
		}
		rep, rerr := reconcileServiceOnce(store, rec.Name, k, keyID, ops, time.Now())
		return map[string]any{"ok": rerr == nil, "service": rep}, rerr

	case "reconcile_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("lifecycle", svcName, 0, ""); err != nil {
			return nil, err
		}
		if _, _, err := resolveSvc(svcName); err != nil {
			return nil, err
		}
		rep, rerr := reconcileServiceOnce(store, svcName, k, keyID, ops, time.Now())
		return map[string]any{"ok": rerr == nil, "service": rep}, rerr

	case "remove_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("remove_publication", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr == nil && found && pubID != "" {
			_, _, _ = ops.mgmtCall(rURL, k, keyID, http.MethodDelete, "/v1/agent/mcp-routes/"+pubID)
		}
		if rec.SystemdUnit != "" && ops.systemctl != nil {
			_, _ = ops.systemctl("stop", rec.SystemdUnit)
		}
		_, _ = store.Delete(rec.Name)
		return map[string]any{"ok": true, "service": svcName, "removed": true}, nil

	case "get_auth_status":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("inspect", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		rep := inspectServiceStatus(rec, k, keyID, ops)
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		var pendingDoc any
		if rerr == nil && found && pubID != "" {
			if st, body, cerr := ops.mgmtCall(rURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/pending"); cerr == nil && st == http.StatusOK {
				_ = json.Unmarshal(body, &pendingDoc)
			}
		}
		return map[string]any{
			"ok":                  true,
			"service":             svcName,
			"publication_id":      pubID,
			"authentication":      rep.AuthProfile,
			"authorization_layer": rep.Layers.Authorization,
			"pending":             pendingDoc,
		}, nil

	case "list_pending_authorizations":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("inspect", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr != nil {
			return nil, rerr
		}
		if !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		st, body, cerr := ops.mgmtCall(rURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/pending")
		if cerr != nil || st != http.StatusOK {
			return nil, fmt.Errorf("relay returned %d (%v)", st, cerr)
		}
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		return map[string]any{"ok": true, "service": svcName, "publication_id": pubID, "pending": doc["pending"], "pending_transactions": doc["pending_transactions"]}, nil

	case "decide_authorization":
		svcName := mcpToolStringArg(args, "service")
		challenge := mcpToolStringArg(args, "challenge")
		decision := mcpToolStringArg(args, "decision")
		if challenge == "" || (decision != "approve" && decision != "deny") {
			return nil, fmt.Errorf("challenge and decision (approve|deny) are required")
		}
		if err := pol.check("authorize_visitor", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr != nil {
			return nil, rerr
		}
		if !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		path := "/v1/agent/mcp-routes/" + pubID + "/authz/consents/" + challenge + "/" + decision
		st, body, cerr := ops.mgmtCall(rURL, k, keyID, http.MethodPost, path)
		if cerr != nil || (st != http.StatusOK && st != http.StatusCreated) {
			return nil, fmt.Errorf("relay returned %d: %s", st, strings.TrimSpace(string(body)))
		}
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		delete(doc, "pairing_secret")
		return map[string]any{"ok": true, "service": svcName, "decision": decision, "result": doc}, nil

	case "list_authorized_clients":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("inspect", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		var trustDoc any
		if rerr == nil && found && pubID != "" {
			if st, body, cerr := ops.mgmtCall(rURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/trust"); cerr == nil && st == http.StatusOK {
				_ = json.Unmarshal(body, &trustDoc)
			}
		}
		return map[string]any{
			"ok":                true,
			"service":           svcName,
			"publication_id":    pubID,
			"trust_policies":    trustDoc,
			"provider_bindings": rec.ProviderBindings,
		}, nil

	case "revoke_client":
		svcName := mcpToolStringArg(args, "service")
		clientID := mcpToolStringArg(args, "clientId")
		if clientID == "" {
			return nil, fmt.Errorf("clientId is required")
		}
		if err := pol.check("revoke_client", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr != nil {
			return nil, rerr
		}
		if !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		st, body, cerr := ops.mgmtCall(rURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/authz/revoke/"+clientID)
		if cerr != nil || st != http.StatusOK {
			return nil, fmt.Errorf("relay returned %d: %s", st, strings.TrimSpace(string(body)))
		}
		return map[string]any{"ok": true, "service": svcName, "client_id": clientID, "revoked": true}, nil

	case "get_auth_policy":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("inspect", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr != nil {
			return nil, rerr
		}
		var trustDoc, visitorDoc any
		if found && pubID != "" {
			if st, body, cerr := ops.mgmtCall(rURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/trust"); cerr == nil && st == http.StatusOK {
				_ = json.Unmarshal(body, &trustDoc)
			}
			if st, body, cerr := ops.mgmtCall(rURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/visitor-auth"); cerr == nil && st == http.StatusOK {
				_ = json.Unmarshal(body, &visitorDoc)
			}
		}
		return map[string]any{"ok": true, "service": svcName, "publication_id": pubID, "trust_policies": trustDoc, "visitor_auth": visitorDoc}, nil

	case "set_auth_policy":
		svcName := mcpToolStringArg(args, "service")
		preset := mcpToolStringArg(args, "preset")
		redirectURI := mcpToolStringArg(args, "redirectUri")
		if err := pol.check("authorize_visitor", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, rURL, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		pubID, _, found, rerr := resolveRelayPublication(rURL, k, keyID, rec, ops)
		if rerr != nil {
			return nil, rerr
		}
		if !found {
			return nil, fmt.Errorf("no publication found for service %q", svcName)
		}
		var redirects []string
		if redirectURI != "" {
			if !strings.HasPrefix(redirectURI, "https://") {
				return nil, fmt.Errorf("redirectUri must be an exact https:// URI")
			}
			redirects = []string{redirectURI}
		}
		polRes, status, _, perr := applyTrustPolicyToRoute(rURL, k, keyID, pubID, preset, redirects, ops)
		if perr != nil {
			return nil, perr
		}
		return map[string]any{"ok": true, "service": svcName, "status": status, "policy": polRes}, nil

	case "verify_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("verify", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		rep := inspectServiceStatus(rec, k, keyID, ops)
		entry, _ := resolveCatalogEntry(svcName, rec.Profile, ops)
		var disc *discoveryCheckResult
		if entry.URL != "" {
			d := runReadOnlyDiscoveryCheck(&http.Client{Timeout: 8 * time.Second}, entry.URL)
			disc = &d
		}
		return map[string]any{
			"ok":        rep.Health == HealthReady && (disc == nil || (disc.Transport == "PASS" && disc.Discovery == "PASS")),
			"service":   svcName,
			"status":    rep,
			"discovery": disc,
		}, nil

	case "diagnose_service":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("inspect", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		rep := inspectServiceStatus(rec, k, keyID, ops)
		layer, classification, errCode := classifyFailureLayer(rep)
		return map[string]any{
			"ok":             true,
			"service":        svcName,
			"status":         rep,
			"failing_layer":  layer,
			"classification": classification,
			"error_code":     errCode,
		}, nil

	case "verify_events":
		svcName := mcpToolStringArg(args, "service")
		if err := pol.check("verify", svcName, 0, ""); err != nil {
			return nil, err
		}
		rec, _, err := resolveSvc(svcName)
		if err != nil {
			return nil, err
		}
		entry, _ := resolveCatalogEntry(svcName, rec.Profile, ops)
		if entry.URL == "" {
			return nil, fmt.Errorf("no canonical URL available for service %q", svcName)
		}
		disc := runReadOnlyDiscoveryCheck(&http.Client{Timeout: 8 * time.Second}, entry.URL)
		return map[string]any{
			"ok":        disc.Transport == "PASS" && disc.Discovery == "PASS",
			"service":   svcName,
			"url":       entry.URL,
			"discovery": disc,
			"note":      "Events subscription delivery requires an explicit visitor token via CLI `ocliv mcp check NAME --capability events --token-file PATH`",
		}, nil
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}
