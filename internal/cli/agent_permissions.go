package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// AgentPermissionsFlags defines the 9 independent capabilities that an
// operator can grant to an authenticated agent principal.
// Sensitive operations (authorize_visitor, manage_auth_policy, revoke_client,
// remove_publication, deployment) are strictly separated.
type AgentPermissionsFlags struct {
	Inspect           bool `json:"inspect"`
	GetURL            bool `json:"get_url"`
	Verify            bool `json:"verify"`
	Lifecycle         bool `json:"lifecycle"`
	Deployment        bool `json:"deployment"`
	AuthorizeVisitor  bool `json:"authorize_visitor"`
	ManageAuthPolicy  bool `json:"manage_auth_policy"`
	RevokeClient      bool `json:"revoke_client"`
	RemovePublication bool `json:"remove_publication"`
}

// AgentPermissionRule scopes capabilities to explicit service names/immutable
// service IDs, permitted deployment ports, and permitted authentication modes.
// Fail-closed: empty AllowedServices + empty AllowedServiceIDs authorizes NO
// services; empty AllowedPorts authorizes NO deployment ports.
type AgentPermissionRule struct {
	AgentPermissions  AgentPermissionsFlags `json:"agent_permissions"`
	AllowedServices   []string              `json:"allowed_services,omitempty"`
	AllowedServiceIDs []string              `json:"allowed_service_ids,omitempty"`
	AllowedPorts      []int                 `json:"allowed_ports,omitempty"`
	AllowedAuthModes  []string              `json:"allowed_auth_modes,omitempty"`
}

// AgentPermissionsPolicy is persisted by the operator in
// `~/.config/ocliv/agent-permissions.json` (0600, regular file, owner-UID).
// No MCP tool can modify this file.
type AgentPermissionsPolicy struct {
	AgentPermissions  *AgentPermissionsFlags         `json:"agent_permissions,omitempty"`
	AllowedServices   []string                       `json:"allowed_services,omitempty"`
	AllowedServiceIDs []string                       `json:"allowed_service_ids,omitempty"`
	AllowedPorts      []int                          `json:"allowed_ports,omitempty"`
	AllowedAuthModes  []string                       `json:"allowed_auth_modes,omitempty"`
	Agents            map[string]AgentPermissionRule `json:"agents,omitempty"`
}

// OperatorApprovalRequest represents an agent's pending request for an
// operation outside its current durable permissions. Only the authenticated
// human operator (via Ocliv Control Center or CLI) can approve or deny it.
type OperatorApprovalRequest struct {
	RequestID            string   `json:"request_id"`
	Principal            string   `json:"principal"`
	Action               string   `json:"action"`
	Permission           string   `json:"permission"`
	Service              string   `json:"service,omitempty"`
	ServiceID            string   `json:"service_id,omitempty"`
	Port                 int      `json:"port,omitempty"`
	AuthMode             string   `json:"auth_mode,omitempty"`
	RequestedPermissions []string `json:"requested_permissions"`
	Status               string   `json:"status"` // PENDING | APPROVED_ONCE | APPROVED_PERSISTENT | DENIED | CONSUMED | EXPIRED
	CreatedAt            string   `json:"created_at"`
	ExpiresAt            string   `json:"expires_at"`
	DecidedAt            string   `json:"decided_at,omitempty"`
}

var approvalStoreMu sync.Mutex

func agentPermissionsFilePath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("OCLIV_PERMISSIONS_FILE")); p != "" {
		return p, nil
	}
	dir, _, _, err := agentFiles()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent-permissions.json"), nil
}

func approvalRequestsFilePath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("OCLIV_APPROVAL_REQUESTS_FILE")); p != "" {
		return p, nil
	}
	dir, _, _, err := agentFiles()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "approval-requests.json"), nil
}

// defaultLocalAgentPermissionsPolicy returns the fail-closed default used only
// when no operator policy file exists yet: read-only inspect/get_url/verify for
// the local-stdio principal across configured services, with ALL mutating and
// sensitive actions denied until explicitly granted by the operator.
func defaultLocalAgentPermissionsPolicy() AgentPermissionsPolicy {
	return AgentPermissionsPolicy{
		Agents: map[string]AgentPermissionRule{
			"local-stdio": {
				AgentPermissions: AgentPermissionsFlags{
					Inspect: true,
					GetURL:  true,
					Verify:  true,
				},
				AllowedServices:  []string{"*"},
				AllowedAuthModes: []string{"ocliv-managed"},
			},
		},
	}
}

func openRegularOwnerOnly0600(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() || (fi.Mode().Perm()&0o077) != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%s must be a regular 0600 file", filepath.Base(path))
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		_ = f.Close()
		return nil, fmt.Errorf("%s must be owned by current operator UID", filepath.Base(path))
	}
	return f, nil
}

func atomicWriteOwnerOnly0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ocliv-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func loadAgentPermissionsPolicy() (AgentPermissionsPolicy, error) {
	path, err := agentPermissionsFilePath()
	if err != nil {
		return defaultLocalAgentPermissionsPolicy(), nil
	}
	f, err := openRegularOwnerOnly0600(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultLocalAgentPermissionsPolicy(), nil
		}
		return AgentPermissionsPolicy{}, fmt.Errorf("load agent-permissions.json: %w", err)
	}
	defer f.Close()
	var pol AgentPermissionsPolicy
	if err := json.NewDecoder(f).Decode(&pol); err != nil {
		return AgentPermissionsPolicy{}, fmt.Errorf("invalid agent-permissions.json: %w", err)
	}
	if pol.Agents == nil {
		pol.Agents = map[string]AgentPermissionRule{}
	}
	return pol, nil
}

// saveAgentPermissionsPolicy atomically persists operator-edited permissions
// with 0600 mode. Callable ONLY from operator-authenticated Control Center / CLI,
// NEVER from an MCP tool handler.
func saveAgentPermissionsPolicy(pol AgentPermissionsPolicy) error {
	path, err := agentPermissionsFilePath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteOwnerOnly0600(path, append(b, '\n'))
}

func (p AgentPermissionsPolicy) ruleFor(principal string) (AgentPermissionRule, bool) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return AgentPermissionRule{}, false
	}
	if p.Agents != nil {
		if r, ok := p.Agents[principal]; ok {
			return r, true
		}
	}
	if p.AgentPermissions != nil {
		return AgentPermissionRule{
			AgentPermissions:  *p.AgentPermissions,
			AllowedServices:   p.AllowedServices,
			AllowedServiceIDs: p.AllowedServiceIDs,
			AllowedPorts:      p.AllowedPorts,
			AllowedAuthModes:  p.AllowedAuthModes,
		}, true
	}
	return AgentPermissionRule{}, false
}

func (r AgentPermissionRule) canAccessService(serviceName, serviceID string) bool {
	// Fail-closed: omitted/empty allowlists authorize NO services.
	for _, s := range r.AllowedServices {
		if s == "*" || (serviceName != "" && s == serviceName) {
			return true
		}
	}
	if serviceID != "" {
		for _, id := range r.AllowedServiceIDs {
			if id == serviceID {
				return true
			}
		}
	}
	return false
}

func (p AgentPermissionsPolicy) canAccessService(principal, serviceName, serviceID string) bool {
	rule, ok := p.ruleFor(principal)
	if !ok {
		return false
	}
	return rule.canAccessService(serviceName, serviceID)
}

func (r AgentPermissionRule) hasAction(action string) bool {
	switch action {
	case "inspect":
		return r.AgentPermissions.Inspect
	case "get_url":
		return r.AgentPermissions.GetURL
	case "verify":
		return r.AgentPermissions.Verify
	case "lifecycle":
		return r.AgentPermissions.Lifecycle
	case "deployment":
		return r.AgentPermissions.Deployment
	case "authorize_visitor":
		return r.AgentPermissions.AuthorizeVisitor
	case "manage_auth_policy":
		return r.AgentPermissions.ManageAuthPolicy
	case "revoke_client":
		return r.AgentPermissions.RevokeClient
	case "remove_publication":
		return r.AgentPermissions.RemovePublication
	default:
		return false
	}
}

// check evaluates durable permissions first, then single-use operator approvals.
// Returns (allowed, reasonCode, detail).
func (p AgentPermissionsPolicy) check(principal, action, serviceName, serviceID string, port int, authMode string) (bool, string, string) {
	rule, ok := p.ruleFor(principal)
	if !ok {
		return false, "NO_PRINCIPAL_POLICY", fmt.Sprintf("principal %q has no operator-granted permissions", principal)
	}
	if !rule.hasAction(action) {
		return false, "PERMISSION_NOT_GRANTED", fmt.Sprintf("operator has not granted %q to %q", action, principal)
	}
	if serviceName != "" || serviceID != "" {
		if !rule.canAccessService(serviceName, serviceID) {
			return false, "FORBIDDEN_TARGET", fmt.Sprintf("service %q is outside operator allowed_services for %q", serviceName, principal)
		}
	}
	if action == "deployment" {
		if len(rule.AllowedPorts) == 0 {
			return false, "FORBIDDEN_PORT", fmt.Sprintf("no deployment ports are allowlisted for %q", principal)
		}
		if port > 0 {
			portOK := false
			for _, ap := range rule.AllowedPorts {
				if ap == port {
					portOK = true
					break
				}
			}
			if !portOK {
				return false, "FORBIDDEN_PORT", fmt.Sprintf("port %d is outside operator allowed_ports", port)
			}
		}
		modes := rule.AllowedAuthModes
		if len(modes) == 0 {
			modes = []string{"ocliv-managed"}
		}
		if authMode != "" {
			modeOK := false
			for _, am := range modes {
				if am == authMode {
					modeOK = true
					break
				}
			}
			if !modeOK {
				return false, "FORBIDDEN_AUTH_MODE", fmt.Sprintf("auth mode %q is outside operator allowed_auth_modes", authMode)
			}
		}
	}
	return true, "", ""
}

func loadApprovalRequestsLocked() ([]OperatorApprovalRequest, error) {
	path, err := approvalRequestsFilePath()
	if err != nil {
		return nil, err
	}
	f, err := openRegularOwnerOnly0600(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []OperatorApprovalRequest{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var list []OperatorApprovalRequest
	if err := json.NewDecoder(f).Decode(&list); err != nil {
		return []OperatorApprovalRequest{}, nil
	}
	return list, nil
}

func saveApprovalRequestsLocked(list []OperatorApprovalRequest) error {
	path, err := approvalRequestsFilePath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteOwnerOnly0600(path, append(b, '\n'))
}

func listOperatorApprovalRequests() ([]OperatorApprovalRequest, error) {
	approvalStoreMu.Lock()
	defer approvalStoreMu.Unlock()
	list, err := loadApprovalRequestsLocked()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	changed := false
	for i := range list {
		if list[i].Status == "PENDING" || list[i].Status == "APPROVED_ONCE" {
			if exp, perr := time.Parse(time.RFC3339, list[i].ExpiresAt); perr == nil && now.After(exp) {
				list[i].Status = "EXPIRED"
				changed = true
			}
		}
	}
	if changed {
		_ = saveApprovalRequestsLocked(list)
	}
	return list, nil
}

func createOperatorApprovalRequest(principal, toolName, permission, service, serviceID string, port int, authMode string) (OperatorApprovalRequest, error) {
	approvalStoreMu.Lock()
	defer approvalStoreMu.Unlock()
	list, err := loadApprovalRequestsLocked()
	if err != nil {
		return OperatorApprovalRequest{}, err
	}
	now := time.Now().UTC()
	// Deduplicate an existing live PENDING request for the exact same tuple.
	for _, r := range list {
		if r.Status == "PENDING" && r.Principal == principal && r.Action == toolName && r.Permission == permission && r.Service == service && r.Port == port {
			if exp, perr := time.Parse(time.RFC3339, r.ExpiresAt); perr == nil && now.Before(exp) {
				return r, nil
			}
		}
	}
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	req := OperatorApprovalRequest{
		RequestID:            "req_" + base64.RawURLEncoding.EncodeToString(rnd[:]),
		Principal:            principal,
		Action:               toolName,
		Permission:           permission,
		Service:              service,
		ServiceID:            serviceID,
		Port:                 port,
		AuthMode:             authMode,
		RequestedPermissions: []string{permission},
		Status:               "PENDING",
		CreatedAt:            now.Format(time.RFC3339),
		ExpiresAt:            now.Add(15 * time.Minute).Format(time.RFC3339),
	}
	// Keep queue bounded to last 128 requests.
	if len(list) >= 128 {
		list = list[len(list)-127:]
	}
	list = append(list, req)
	if err := saveApprovalRequestsLocked(list); err != nil {
		return OperatorApprovalRequest{}, err
	}
	return req, nil
}

func consumeSingleUseApproval(principal, permission, service string, port int) bool {
	approvalStoreMu.Lock()
	defer approvalStoreMu.Unlock()
	list, err := loadApprovalRequestsLocked()
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	for i := range list {
		r := &list[i]
		if r.Status != "APPROVED_ONCE" {
			continue
		}
		if exp, perr := time.Parse(time.RFC3339, r.ExpiresAt); perr == nil && now.After(exp) {
			r.Status = "EXPIRED"
			continue
		}
		if r.Principal == principal && r.Permission == permission && (r.Service == "" || r.Service == service) && (r.Port == 0 || r.Port == port) {
			r.Status = "CONSUMED"
			_ = saveApprovalRequestsLocked(list)
			return true
		}
	}
	return false
}

// decideOperatorApprovalRequest is callable ONLY from the operator-authenticated
// Control Center (never from MCP tools). Supports: "allow_once", "allow_persistent", "deny".
func decideOperatorApprovalRequest(requestID, decision string) (OperatorApprovalRequest, error) {
	approvalStoreMu.Lock()
	defer approvalStoreMu.Unlock()
	list, err := loadApprovalRequestsLocked()
	if err != nil {
		return OperatorApprovalRequest{}, err
	}
	now := time.Now().UTC()
	for i := range list {
		if list[i].RequestID != requestID {
			continue
		}
		if list[i].Status != "PENDING" {
			return list[i], fmt.Errorf("request %s is already %s", requestID, list[i].Status)
		}
		if exp, perr := time.Parse(time.RFC3339, list[i].ExpiresAt); perr == nil && now.After(exp) {
			list[i].Status = "EXPIRED"
			_ = saveApprovalRequestsLocked(list)
			return list[i], fmt.Errorf("request %s has expired", requestID)
		}
		switch decision {
		case "allow_once":
			list[i].Status = "APPROVED_ONCE"
		case "allow_persistent":
			list[i].Status = "APPROVED_PERSISTENT"
			if err := grantPersistentPermissionFromRequest(list[i]); err != nil {
				return list[i], err
			}
		case "deny":
			list[i].Status = "DENIED"
		default:
			return list[i], fmt.Errorf("invalid decision %q (want allow_once|allow_persistent|deny)", decision)
		}
		list[i].DecidedAt = now.Format(time.RFC3339)
		if err := saveApprovalRequestsLocked(list); err != nil {
			return list[i], err
		}
		return list[i], nil
	}
	return OperatorApprovalRequest{}, fmt.Errorf("unknown approval request %q", requestID)
}

func grantPersistentPermissionFromRequest(req OperatorApprovalRequest) error {
	pol, err := loadAgentPermissionsPolicy()
	if err != nil {
		pol = defaultLocalAgentPermissionsPolicy()
	}
	if pol.Agents == nil {
		pol.Agents = map[string]AgentPermissionRule{}
	}
	rule, ok := pol.Agents[req.Principal]
	if !ok {
		rule = AgentPermissionRule{AllowedAuthModes: []string{"ocliv-managed"}}
	}
	switch req.Permission {
	case "inspect":
		rule.AgentPermissions.Inspect = true
	case "get_url":
		rule.AgentPermissions.GetURL = true
	case "verify":
		rule.AgentPermissions.Verify = true
	case "lifecycle":
		rule.AgentPermissions.Lifecycle = true
	case "deployment":
		rule.AgentPermissions.Deployment = true
	case "authorize_visitor":
		rule.AgentPermissions.AuthorizeVisitor = true
	case "manage_auth_policy":
		rule.AgentPermissions.ManageAuthPolicy = true
	case "revoke_client":
		rule.AgentPermissions.RevokeClient = true
	case "remove_publication":
		rule.AgentPermissions.RemovePublication = true
	}
	if req.Service != "" && !rule.canAccessService(req.Service, req.ServiceID) {
		rule.AllowedServices = append(rule.AllowedServices, req.Service)
	}
	if req.ServiceID != "" {
		foundID := false
		for _, id := range rule.AllowedServiceIDs {
			if id == req.ServiceID {
				foundID = true
				break
			}
		}
		if !foundID {
			rule.AllowedServiceIDs = append(rule.AllowedServiceIDs, req.ServiceID)
		}
	}
	if req.Port > 0 {
		foundPort := false
		for _, p := range rule.AllowedPorts {
			if p == req.Port {
				foundPort = true
				break
			}
		}
		if !foundPort {
			rule.AllowedPorts = append(rule.AllowedPorts, req.Port)
		}
	}
	pol.Agents[req.Principal] = rule
	return saveAgentPermissionsPolicy(pol)
}
