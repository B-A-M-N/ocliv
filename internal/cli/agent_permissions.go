package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	maxPendingPerPrincipal = 16
	maxTotalApprovalStore  = 256
)

var (
	// ErrPolicyConflict indicates a CAS revision mismatch while saving agent permissions.
	ErrPolicyConflict = errors.New("agent permissions policy revision conflict; reload and retry")
)

// ServiceGrant explicitly binds a set of permitted actions to ONE specific
// service (by immutable service_id and/or service_name), preventing
// cross-product permission escalation across unrelated services (OCL-014.3).
type ServiceGrant struct {
	ServiceID        string   `json:"service_id,omitempty"`
	ServiceName      string   `json:"service_name,omitempty"`
	Actions          []string `json:"actions"`
	AllowedPorts     []int    `json:"allowed_ports,omitempty"`
	AllowedAuthModes []string `json:"allowed_auth_modes,omitempty"`
}

// AgentPermissionsFlags is retained strictly for conservative one-way migration
// of pre-OCL-014 policies and UI checkbox rendering for a single service grant.
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

// AgentPermissionRule defines an authenticated principal's explicit grants.
// Legacy flat fields (AgentPermissions/AllowedServices/AllowedPorts) are
// migrated conservatively on load and never allowed to widen authority.
type AgentPermissionRule struct {
	Grants []ServiceGrant `json:"grants,omitempty"`

	// Legacy fields (read-only migration input from pre-OCL-014 files).
	AgentPermissions  *AgentPermissionsFlags `json:"agent_permissions,omitempty"`
	AllowedServices   []string               `json:"allowed_services,omitempty"`
	AllowedServiceIDs []string               `json:"allowed_service_ids,omitempty"`
	AllowedPorts      []int                  `json:"allowed_ports,omitempty"`
	AllowedAuthModes  []string               `json:"allowed_auth_modes,omitempty"`
}

// AgentPermissionsPolicy is persisted by the operator in
// `~/.config/ocliv/agent-permissions.json` (0600, regular file, owner-UID,
// revision-controlled). No MCP tool can modify this file.
type AgentPermissionsPolicy struct {
	SchemaVersion int                            `json:"schema_version,omitempty"`
	Revision      int64                          `json:"revision"`
	Agents        map[string]AgentPermissionRule `json:"agents"`

	// Legacy top-level fields (read-only migration input).
	AgentPermissions  *AgentPermissionsFlags `json:"agent_permissions,omitempty"`
	AllowedServices   []string               `json:"allowed_services,omitempty"`
	AllowedServiceIDs []string               `json:"allowed_service_ids,omitempty"`
	AllowedPorts      []int                  `json:"allowed_ports,omitempty"`
	AllowedAuthModes  []string               `json:"allowed_auth_modes,omitempty"`
}

// AuthorizationIntent is an immutable, normalized description of ONE exact
// operation that a single-use approval authorizes (OCL-014.1).
type AuthorizationIntent struct {
	Operation     string         `json:"operation"`
	Permission    string         `json:"permission"`
	Principal     string         `json:"principal"`
	ServiceID     string         `json:"service_id,omitempty"`
	ServiceName   string         `json:"service_name,omitempty"`
	PublicationID string         `json:"publication_id,omitempty"`
	Revision      int64          `json:"revision,omitempty"`
	Arguments     map[string]any `json:"arguments,omitempty"`
}

// Digest returns the deterministic SHA-256 hex digest ("sha256:...") of the
// canonical JSON encoding of the exact AuthorizationIntent.
func (in AuthorizationIntent) Digest() string {
	// Normalize Arguments keys via Go's encoding/json map key sorting.
	b, _ := json.Marshal(in)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// OperatorApprovalRequest represents an agent's pending request for ONE exact
// operation intent outside its durable grants. Stored under cross-process flock.
type OperatorApprovalRequest struct {
	RequestID            string              `json:"request_id"`
	Principal            string              `json:"principal"`
	Action               string              `json:"action"`
	Permission           string              `json:"permission"`
	Service              string              `json:"service,omitempty"`
	ServiceID            string              `json:"service_id,omitempty"`
	PublicationID        string              `json:"publication_id,omitempty"`
	Port                 int                 `json:"port,omitempty"`
	AuthMode             string              `json:"auth_mode,omitempty"`
	Intent               AuthorizationIntent `json:"intent"`
	IntentDigest         string              `json:"intent_digest"`
	RequestedPermissions []string            `json:"requested_permissions"`
	Status               string              `json:"status"` // PENDING | APPROVED_ONCE | APPROVED_PERSISTENT | DENIED | CONSUMED | EXPIRED
	CreatedAt            string              `json:"created_at"`
	ExpiresAt            string              `json:"expires_at"`
	DecidedAt            string              `json:"decided_at,omitempty"`
	ConsumedAt           string              `json:"consumed_at,omitempty"`
}

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

// withFileLock acquires an exclusive OS-level advisory lock (flock) on
// `<targetPath>.lock` (0600) so separate processes (Control Center, MCP manage,
// CLI) serialize transactional reads and writes safely (OCL-014.2).
func withFileLock(targetPath string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return fmt.Errorf("create lock dir: %w", err)
	}
	lockPath := targetPath + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire flock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func defaultLocalAgentPermissionsPolicy() AgentPermissionsPolicy {
	return AgentPermissionsPolicy{
		SchemaVersion: 2,
		Revision:      0,
		Agents: map[string]AgentPermissionRule{
			"local-stdio": {
				Grants: []ServiceGrant{
					{
						ServiceName:      "*",
						Actions:          []string{"inspect", "get_url", "verify"},
						AllowedAuthModes: []string{"ocliv-managed"},
					},
				},
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

func flagsToActions(f *AgentPermissionsFlags) []string {
	if f == nil {
		return nil
	}
	var out []string
	if f.Inspect {
		out = append(out, "inspect")
	}
	if f.GetURL {
		out = append(out, "get_url")
	}
	if f.Verify {
		out = append(out, "verify")
	}
	if f.Lifecycle {
		out = append(out, "lifecycle")
	}
	if f.Deployment {
		out = append(out, "deployment")
	}
	if f.AuthorizeVisitor {
		out = append(out, "authorize_visitor")
	}
	if f.ManageAuthPolicy {
		out = append(out, "manage_auth_policy")
	}
	if f.RevokeClient {
		out = append(out, "revoke_client")
	}
	if f.RemovePublication {
		out = append(out, "remove_publication")
	}
	return out
}

// migrateLegacyRule conservatively converts legacy flat fields into explicit
// per-service ServiceGrants without ever widening authority (OCL-014.3).
func migrateLegacyRule(r AgentPermissionRule) AgentPermissionRule {
	if len(r.Grants) > 0 || r.AgentPermissions == nil {
		return r
	}
	actions := flagsToActions(r.AgentPermissions)
	if len(actions) == 0 {
		return AgentPermissionRule{}
	}
	modes := r.AllowedAuthModes
	if len(modes) == 0 {
		modes = []string{"ocliv-managed"}
	}
	var grants []ServiceGrant
	for _, svc := range r.AllowedServices {
		svc = strings.TrimSpace(svc)
		if svc == "" {
			continue
		}
		grants = append(grants, ServiceGrant{
			ServiceName:      svc,
			Actions:          slices.Clone(actions),
			AllowedPorts:     slices.Clone(r.AllowedPorts),
			AllowedAuthModes: slices.Clone(modes),
		})
	}
	for _, id := range r.AllowedServiceIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		grants = append(grants, ServiceGrant{
			ServiceID:        id,
			Actions:          slices.Clone(actions),
			AllowedPorts:     slices.Clone(r.AllowedPorts),
			AllowedAuthModes: slices.Clone(modes),
		})
	}
	return AgentPermissionRule{Grants: grants}
}

func normalizePolicy(pol AgentPermissionsPolicy) AgentPermissionsPolicy {
	if pol.Agents == nil {
		pol.Agents = map[string]AgentPermissionRule{}
	}
	if pol.AgentPermissions != nil {
		if _, exists := pol.Agents["local-stdio"]; !exists {
			pol.Agents["local-stdio"] = migrateLegacyRule(AgentPermissionRule{
				AgentPermissions:  pol.AgentPermissions,
				AllowedServices:   pol.AllowedServices,
				AllowedServiceIDs: pol.AllowedServiceIDs,
				AllowedPorts:      pol.AllowedPorts,
				AllowedAuthModes:  pol.AllowedAuthModes,
			})
		}
		pol.AgentPermissions = nil
		pol.AllowedServices = nil
		pol.AllowedServiceIDs = nil
		pol.AllowedPorts = nil
		pol.AllowedAuthModes = nil
	}
	for k, r := range pol.Agents {
		pol.Agents[k] = migrateLegacyRule(r)
	}
	pol.SchemaVersion = 2
	return pol
}

// loadAgentPermissionsPolicy loads and validates the operator permissions policy
// fail-closed. Corrupted or insecure files return an error rather than being
// silently replaced (OCL-014.2).
func loadAgentPermissionsPolicy() (AgentPermissionsPolicy, error) {
	path, err := agentPermissionsFilePath()
	if err != nil {
		return defaultLocalAgentPermissionsPolicy(), nil
	}
	var pol AgentPermissionsPolicy
	err = withFileLock(path, func() error {
		f, oerr := openRegularOwnerOnly0600(path)
		if oerr != nil {
			if os.IsNotExist(oerr) {
				pol = defaultLocalAgentPermissionsPolicy()
				return nil
			}
			return oerr
		}
		defer f.Close()
		if derr := json.NewDecoder(f).Decode(&pol); derr != nil {
			return fmt.Errorf("corrupted agent-permissions.json: %w", derr)
		}
		pol = normalizePolicy(pol)
		return nil
	})
	if err != nil {
		return AgentPermissionsPolicy{}, fmt.Errorf("load agent-permissions.json: %w", err)
	}
	return pol, nil
}

// saveAgentPermissionsPolicyCAS atomically persists operator-edited permissions
// with 0600 mode under cross-process flock and revision CAS check (OCL-014.6).
// When expectedRevision >= 0, fails with ErrPolicyConflict if another window
// modified the policy concurrently.
func saveAgentPermissionsPolicyCAS(pol AgentPermissionsPolicy, expectedRevision int64) (AgentPermissionsPolicy, error) {
	path, err := agentPermissionsFilePath()
	if err != nil {
		return AgentPermissionsPolicy{}, err
	}
	var saved AgentPermissionsPolicy
	err = withFileLock(path, func() error {
		var currentRev int64
		if f, oerr := openRegularOwnerOnly0600(path); oerr == nil {
			var cur AgentPermissionsPolicy
			if derr := json.NewDecoder(f).Decode(&cur); derr != nil {
				_ = f.Close()
				return fmt.Errorf("corrupted agent-permissions.json: %w", derr)
			}
			_ = f.Close()
			currentRev = cur.Revision
		} else if !os.IsNotExist(oerr) {
			return oerr
		}
		if expectedRevision >= 0 && currentRev != expectedRevision {
			return ErrPolicyConflict
		}
		pol = normalizePolicy(pol)
		pol.Revision = currentRev + 1
		b, merr := json.MarshalIndent(pol, "", "  ")
		if merr != nil {
			return merr
		}
		if werr := atomicWriteOwnerOnly0600(path, append(b, '\n')); werr != nil {
			return werr
		}
		saved = pol
		return nil
	})
	return saved, err
}

func saveAgentPermissionsPolicy(pol AgentPermissionsPolicy) error {
	_, err := saveAgentPermissionsPolicyCAS(pol, -1)
	return err
}

func (g ServiceGrant) matchesService(serviceName, serviceID string) bool {
	if g.ServiceName == "*" {
		return true
	}
	if serviceID != "" && g.ServiceID != "" && g.ServiceID == serviceID {
		return true
	}
	if serviceName != "" && g.ServiceName != "" && g.ServiceName == serviceName {
		// If the grant is pinned to a specific immutable service_id and the
		// caller provided a different non-empty service_id, refuse mismatch.
		if g.ServiceID != "" && serviceID != "" && g.ServiceID != serviceID {
			return false
		}
		return true
	}
	return false
}

func (g ServiceGrant) hasAction(action string) bool {
	return slices.Contains(g.Actions, action)
}

func (p AgentPermissionsPolicy) canAccessService(principal, serviceName, serviceID string) bool {
	rule, ok := p.Agents[strings.TrimSpace(principal)]
	if !ok {
		return false
	}
	for _, g := range rule.Grants {
		if g.matchesService(serviceName, serviceID) && len(g.Actions) > 0 {
			return true
		}
	}
	return false
}

// check evaluates explicit per-service action-to-resource grants (OCL-014.3).
// For global read operations (serviceName == "" && serviceID == ""), returns
// true if ANY grant for the principal permits the action.
// For service-scoped operations, ONLY grants matching THAT exact service are
// evaluated — preventing cross-product escalation across services!
func (p AgentPermissionsPolicy) check(principal, action, serviceName, serviceID string, port int, authMode string) (bool, string, string) {
	rule, ok := p.Agents[strings.TrimSpace(principal)]
	if !ok {
		return false, "NO_PRINCIPAL_POLICY", fmt.Sprintf("principal %q has no operator-granted permissions", principal)
	}
	if serviceName == "" && serviceID == "" {
		for _, g := range rule.Grants {
			if g.hasAction(action) {
				return true, "", ""
			}
		}
		return false, "PERMISSION_NOT_GRANTED", fmt.Sprintf("operator has not granted %q to %q", action, principal)
	}
	for _, g := range rule.Grants {
		if !g.matchesService(serviceName, serviceID) {
			continue
		}
		if !g.hasAction(action) {
			continue
		}
		if action == "deployment" {
			if len(g.AllowedPorts) == 0 || (port > 0 && !slices.Contains(g.AllowedPorts, port)) {
				continue
			}
			modes := g.AllowedAuthModes
			if len(modes) == 0 {
				modes = []string{"ocliv-managed"}
			}
			if authMode != "" && !slices.Contains(modes, authMode) {
				continue
			}
		}
		return true, "", ""
	}
	return false, "PERMISSION_NOT_GRANTED", fmt.Sprintf("operator has not granted %q on service %q to %q", action, serviceName, principal)
}

// ==================== CROSS-PROCESS TRANSACTIONAL APPROVAL STORE (OCL-014.1 + 014.2) ====================

func loadApprovalRequestsFileLocked(path string) ([]OperatorApprovalRequest, error) {
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
		// Fail closed on corrupted approval store: never silently overwrite!
		return nil, fmt.Errorf("corrupted approval-requests.json: %w", err)
	}
	return list, nil
}

func saveApprovalRequestsFileLocked(path string, list []OperatorApprovalRequest) error {
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteOwnerOnly0600(path, append(b, '\n'))
}

func listOperatorApprovalRequests() ([]OperatorApprovalRequest, error) {
	path, err := approvalRequestsFilePath()
	if err != nil {
		return nil, err
	}
	var out []OperatorApprovalRequest
	err = withFileLock(path, func() error {
		list, lerr := loadApprovalRequestsFileLocked(path)
		if lerr != nil {
			return lerr
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
			if serr := saveApprovalRequestsFileLocked(path, list); serr != nil {
				return serr
			}
		}
		out = list
		return nil
	})
	return out, err
}

func createOperatorApprovalRequest(intent AuthorizationIntent, port int, authMode string) (OperatorApprovalRequest, error) {
	path, err := approvalRequestsFilePath()
	if err != nil {
		return OperatorApprovalRequest{}, err
	}
	digest := intent.Digest()
	var created OperatorApprovalRequest
	err = withFileLock(path, func() error {
		list, lerr := loadApprovalRequestsFileLocked(path)
		if lerr != nil {
			return lerr
		}
		now := time.Now().UTC()
		pendingForPrincipal := 0
		for i := range list {
			if list[i].Status == "PENDING" {
				if exp, perr := time.Parse(time.RFC3339, list[i].ExpiresAt); perr == nil && now.After(exp) {
					list[i].Status = "EXPIRED"
					continue
				}
				if list[i].Principal == intent.Principal && list[i].IntentDigest == digest {
					created = list[i]
					return nil
				}
				if list[i].Principal == intent.Principal {
					pendingForPrincipal++
				}
			}
		}
		if pendingForPrincipal >= maxPendingPerPrincipal {
			return fmt.Errorf("too many pending approval requests (%d) for principal %q", pendingForPrincipal, intent.Principal)
		}
		var rnd [12]byte
		if _, rerr := rand.Read(rnd[:]); rerr != nil {
			return rerr
		}
		req := OperatorApprovalRequest{
			RequestID:            "req_" + base64.RawURLEncoding.EncodeToString(rnd[:]),
			Principal:            intent.Principal,
			Action:               intent.Operation,
			Permission:           intent.Permission,
			Service:              intent.ServiceName,
			ServiceID:            intent.ServiceID,
			PublicationID:        intent.PublicationID,
			Port:                 port,
			AuthMode:             authMode,
			Intent:               intent,
			IntentDigest:         digest,
			RequestedPermissions: []string{intent.Permission},
			Status:               "PENDING",
			CreatedAt:            now.Format(time.RFC3339),
			ExpiresAt:            now.Add(15 * time.Minute).Format(time.RFC3339),
		}
		if len(list) >= maxTotalApprovalStore {
			list = list[len(list)-(maxTotalApprovalStore-1):]
		}
		list = append(list, req)
		if serr := saveApprovalRequestsFileLocked(path, list); serr != nil {
			return serr
		}
		created = req
		return nil
	})
	return created, err
}

// consumeSingleUseApproval performs a cross-process locked atomic CAS from
// APPROVED_ONCE -> CONSUMED bound strictly to (principal, exact intentDigest).
// Fail-closed: returns (false, err) on any storage error; NEVER considers an
// approval consumed unless the durable write succeeded (OCL-014.1, OCL-014.2).
func consumeSingleUseApproval(principal, intentDigest string) (bool, error) {
	path, err := approvalRequestsFilePath()
	if err != nil {
		return false, err
	}
	consumed := false
	err = withFileLock(path, func() error {
		list, lerr := loadApprovalRequestsFileLocked(path)
		if lerr != nil {
			return lerr
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
			if r.Principal == principal && r.IntentDigest == intentDigest && intentDigest != "" {
				r.Status = "CONSUMED"
				r.ConsumedAt = now.Format(time.RFC3339)
				if serr := saveApprovalRequestsFileLocked(path, list); serr != nil {
					// Fail closed: storage write failed, do NOT authorize execution!
					return serr
				}
				consumed = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return consumed, nil
}

// decideOperatorApprovalRequest is callable ONLY from the operator-authenticated
// Control Center (never from MCP tools). Supports: "allow_once", "allow_persistent", "deny".
func decideOperatorApprovalRequest(requestID, decision string) (OperatorApprovalRequest, error) {
	path, err := approvalRequestsFilePath()
	if err != nil {
		return OperatorApprovalRequest{}, err
	}
	var decided OperatorApprovalRequest
	err = withFileLock(path, func() error {
		list, lerr := loadApprovalRequestsFileLocked(path)
		if lerr != nil {
			return lerr
		}
		now := time.Now().UTC()
		for i := range list {
			if list[i].RequestID != requestID {
				continue
			}
			if list[i].Status != "PENDING" {
				return fmt.Errorf("request %s is already %s", requestID, list[i].Status)
			}
			if exp, perr := time.Parse(time.RFC3339, list[i].ExpiresAt); perr == nil && now.After(exp) {
				list[i].Status = "EXPIRED"
				_ = saveApprovalRequestsFileLocked(path, list)
				return fmt.Errorf("request %s has expired", requestID)
			}
			switch decision {
			case "allow_once":
				list[i].Status = "APPROVED_ONCE"
			case "allow_persistent":
				if gerr := grantPersistentServicePermission(list[i]); gerr != nil {
					return gerr
				}
				list[i].Status = "APPROVED_PERSISTENT"
			case "deny":
				list[i].Status = "DENIED"
			default:
				return fmt.Errorf("invalid decision %q (want allow_once|allow_persistent|deny)", decision)
			}
			list[i].DecidedAt = now.Format(time.RFC3339)
			if serr := saveApprovalRequestsFileLocked(path, list); serr != nil {
				return serr
			}
			decided = list[i]
			return nil
		}
		return fmt.Errorf("unknown approval request %q", requestID)
	})
	return decided, err
}

// grantPersistentServicePermission adds ONLY the exact requested permission
// scoped strictly to the exact requested service (and port/auth mode if
// deployment), NEVER widening permissions on other services (OCL-014.3).
func grantPersistentServicePermission(req OperatorApprovalRequest) error {
	pol, err := loadAgentPermissionsPolicy()
	if err != nil {
		return err
	}
	if pol.Agents == nil {
		pol.Agents = map[string]AgentPermissionRule{}
	}
	rule := pol.Agents[req.Principal]
	idx := -1
	for i, g := range rule.Grants {
		if (req.ServiceID != "" && g.ServiceID == req.ServiceID) ||
			(req.Service != "" && g.ServiceName == req.Service && (g.ServiceID == "" || g.ServiceID == req.ServiceID)) {
			idx = i
			break
		}
	}
	if idx < 0 {
		g := ServiceGrant{
			ServiceID:   req.ServiceID,
			ServiceName: req.Service,
			Actions:     []string{req.Permission},
		}
		if req.Port > 0 {
			g.AllowedPorts = []int{req.Port}
		}
		if req.AuthMode != "" {
			g.AllowedAuthModes = []string{req.AuthMode}
		}
		rule.Grants = append(rule.Grants, g)
	} else {
		g := rule.Grants[idx]
		if g.ServiceID == "" && req.ServiceID != "" {
			g.ServiceID = req.ServiceID
		}
		if !slices.Contains(g.Actions, req.Permission) {
			g.Actions = append(g.Actions, req.Permission)
			sort.Strings(g.Actions)
		}
		if req.Port > 0 && !slices.Contains(g.AllowedPorts, req.Port) {
			g.AllowedPorts = append(g.AllowedPorts, req.Port)
		}
		if req.AuthMode != "" && !slices.Contains(g.AllowedAuthModes, req.AuthMode) {
			g.AllowedAuthModes = append(g.AllowedAuthModes, req.AuthMode)
		}
		rule.Grants[idx] = g
	}
	pol.Agents[req.Principal] = rule
	_, err = saveAgentPermissionsPolicyCAS(pol, pol.Revision)
	return err
}
