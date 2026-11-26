// Package cli implements Ocliv's command dispatch and terminal UX.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/protocol"
	"github.com/B-A-M-N/ocliv/internal/store"
)

// BuildCommit, BuildTime, and BuildDirty can be overridden at link time via -ldflags.
var (
	BuildCommit = ""
	BuildTime   = ""
	BuildDirty  = ""
)

// BinaryVersion is the client/relay build version reported by
// `ocliv version` alongside the wire-protocol range. Bump together
// with protocol.MinVersion/MaxVersion when the wire changes.
const BinaryVersion = "1.0.0"

// BuildInfo is the single authoritative build-provenance representation used
// by `ocliv version --json`, `runtime.json`, release manifests, and diagnostics (A10).
type BuildInfo struct {
	Version                string `json:"version"`
	BuildCommit            string `json:"build_commit"`
	BuildTime              string `json:"build_time"`
	Dirty                  bool   `json:"dirty"`
	OS                     string `json:"os"`
	Arch                   string `json:"arch"`
	GoVersion              string `json:"go_version"`
	StoreSchemaVersion     int    `json:"store_schema_version"`
	ProtocolVersion        string `json:"protocol_version"`
	SupportedProtocolRange string `json:"supported_protocol_range"`
}

// GetBuildInfo returns unified build provenance. Explicit linker-provided
// BuildCommit/BuildTime/BuildDirty always take precedence; Go debug build info
// is fallback only (A10).
func GetBuildInfo() BuildInfo {
	commit := strings.TrimSpace(BuildCommit)
	buildTime := strings.TrimSpace(BuildTime)
	dirtySet := false
	dirty := false
	if d := strings.TrimSpace(strings.ToLower(BuildDirty)); d != "" {
		dirtySet = true
		dirty = d == "true" || d == "1" || d == "yes"
	}
	if info, ok := debug.ReadBuildInfo(); ok && info != nil {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if commit == "" {
					commit = s.Value
				}
			case "vcs.time":
				if buildTime == "" {
					buildTime = s.Value
				}
			case "vcs.modified":
				if !dirtySet {
					dirty = s.Value == "true"
				}
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}
	return BuildInfo{
		Version:                BinaryVersion,
		BuildCommit:            commit,
		BuildTime:              buildTime,
		Dirty:                  dirty,
		OS:                     runtime.GOOS,
		Arch:                   runtime.GOARCH,
		GoVersion:              runtime.Version(),
		StoreSchemaVersion:     store.SchemaVersion,
		ProtocolVersion:        protocol.Version,
		SupportedProtocolRange: protocol.MinVersion + "-" + protocol.MaxVersion,
	}
}

// versionString renders the build and wire-protocol identity from the
// single-source constants, never hardcoded literals that can drift.
func versionString() string {
	return fmt.Sprintf("ocliv %s (protocol %s, supported %s-%s)",
		BinaryVersion, protocol.Version, protocol.MinVersion, protocol.MaxVersion)
}

func buildVersionInfo() map[string]any {
	bi := GetBuildInfo()
	return map[string]any{
		"version":             bi.Version,
		"commit":              bi.BuildCommit,
		"build_commit":        bi.BuildCommit,
		"build_time":          bi.BuildTime,
		"dirty":               bi.Dirty,
		"os":                  bi.OS,
		"arch":                bi.Arch,
		"go_version":          bi.GoVersion,
		"schema_version":      bi.StoreSchemaVersion,
		"protocol_version":    bi.ProtocolVersion,
		"supported_protocols": bi.SupportedProtocolRange,
		"capabilities": []string{
			"mcp_managed_oauth",
			"appended_as_discovery",
			"direct_grant_v13",
			"confidential_refresh_v14",
			"cors_mcp_headers",
			"persistent_named_leases",
			"mgmt_body_sig_v2",
			"native_tx_authz",
			"optional_federated_oidc",
			"mcp_events_qualification",
			"host_observations",
			"mcp_control_plane_v1",
			"control_center_ui",
			"exact_intent_approvals",
			"ingress_auth_v2",
		},
	}
}

func cmdVersion(argv []string) int {
	asJSON := false
	for _, a := range argv {
		if a == "--json" {
			asJSON = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown version flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	if asJSON {
		b, _ := json.MarshalIndent(buildVersionInfo(), "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	fmt.Println(versionString())
	return apperr.ExitOK
}

// Run dispatches argv. Exit codes follow the spec contract.
func Run(argv []string) int {
	if len(argv) == 0 {
		return usage(apperr.ExitCLIValidation)
	}
	switch argv[0] {
	case "version", "--version", "-V":
		return cmdVersion(argv[1:])
	case "help", "--help", "-h":
		return usage(apperr.ExitOK)
	case "login":
		return cmdLogin(argv[1:])
	case "logout":
		return cmdLogout(argv[1:])
	case "key":
		return cmdKey(argv[1:])
	case "runtime":
		return cmdRuntime(argv[1:])
	case "status":
		return cmdStatus(argv[1:])
	case "doctor":
		return cmdDoctor(argv[1:])
	case "relay":
		return cmdRelay(argv[1:])
	case "setup":
		return cmdSetup(argv[1:])
	case "device":
		return cmdDevice(argv[1:])
	case "trust":
		if err := requireUserContext("trust", false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdTrust(argv[1:])
	case "untrust":
		if err := requireUserContext("untrust", false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdUntrust(argv[1:])
	case "revoke":
		if err := requireUserContext("revoke", false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdRevoke(argv[1:])
	case "update":
		return cmdUpdate(argv[1:])
	case "access":
		return cmdAccess(argv[1:])
	case "mcp":
		return cmdMCP(argv[1:])
	case "authz":
		return cmdAuthz(argv[1:])
	case "profile":
		return cmdProfile(argv[1:])
	case "service":
		return cmdService(argv[1:])
	case "google":
		return cmdGoogle(argv[1:])
	case "connect":
		return cmdConnect(argv[1:])
	case "pair":
		return cmdPair(argv[1:])
	case "install":
		return cmdInstall(argv[1:])
	case "host":
		return cmdHost(argv[1:])
	case "start", "enable":
		if err := requireUserContext(argv[0], false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdServiceStart(argv[1:], defaultServiceOps())
	case "restart":
		if err := requireUserContext("restart", false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdServiceRestart(argv[1:], defaultServiceOps())
	case "stop", "disable":
		if err := requireUserContext(argv[0], false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdServiceStop(argv[1:], defaultServiceOps())
	case "remove":
		if err := requireUserContext("remove", false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdServiceRemove(argv[1:], defaultServiceOps())
	case "ui", "control-center":
		if err := requireUserContext("ui", false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		return cmdUI(argv[1:])
	case "logs":
		return cmdServiceLogs(argv[1:])
	case "share":
		return cmdShare(argv[1:])
	default:
		if strings.HasPrefix(argv[0], "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q; see `ocliv help`\n", argv[0])
			return apperr.ExitCLIValidation
		}
		return cmdTunnel(argv)
	}
}

func usage(code int) int {
	fmt.Print(`Ocliv — secure instant HTTPS & MCP hosting.

Getting Started:
  sudo ocliv setup [--edge wildcard|single-host|tunnel]   set up this relay host (TLS + systemd)
  ocliv device add USER@HOST [--install]                  enroll a publisher machine over SSH
  ocliv host mcp PORT --name NAME --trust chatgpt         host an MCP server with ChatGPT trusted

Everyday Commands:
  ocliv ui [--install-shortcut]                            launch the local Ocliv Control Center graphical interface
  ocliv host [http|mcp] PORT [--name N] [--trust PRESET]   persistently host HTTP or MCP (systemd + reboot-safe)
  ocliv status [NAME] [--json]                             show relay, services, trusted clients, and pending approvals
  ocliv start|enable NAME                                  enable/start a hosted service (preserves URL & identity)
  ocliv stop|disable NAME [--json]                         immediately disable public access, retain identity
  ocliv restart NAME                                       non-destructive restart/rebind (preserves URL & sessions)
  ocliv trust NAME PRESET|--redirect-uri URI|--client ID   manage route-scoped client policies & federated OIDC auth
  ocliv untrust NAME PRESET_OR_ID|--visitor-auth           revoke a route trust or federated visitor auth policy
  ocliv revoke client CLIENT_ID [--service NAME]           revoke an OAuth client's access
  ocliv remove NAME [--yes]                                permanently retire a hosted service
  ocliv update [--check] [--yes]                           check for or install signed client updates from relay
  ocliv doctor [NAME|--all]                                diagnose key, relay, local service, and DNS/TLS
  ocliv mcp url|check NAME [--capability events]           inspect canonical MCP URL, OAuth discovery & Events
  ocliv PORT                                               share localhost:PORT over protected HTTPS (ephemeral)

Device Management (on relay host):
  ocliv device add USER@HOST [--tenant default] [--install]   enroll a remote machine over SSH (default)
  ocliv device add --local [--tenant default]                 enroll current non-root user on the relay host
  ocliv device add --local-user USER [--tenant default]       enroll a local unprivileged user on the relay host
  ocliv device list [--data DIR]                              list enrolled devices/keys
  ocliv device revoke KEY_ID [--data DIR]                     revoke an enrolled device key

Advanced / Plumbing:
  ocliv pair RELAY_URL | pair resume                          manual pairing fallback when SSH is unavailable
  ocliv login --relay URL --code-file PATH | logout           headless code enrollment / sign-out
  ocliv service ...                                           low-level service management
  ocliv authz ...                                             low-level relay OAuth administration
  ocliv relay ...                                             low-level relay serve/init/backup/restore/approve
  ocliv install --relay URL [--dir DIR] [--yes]               explicit signed release installer
  ocliv profile create|use|list                               separate enrollment profiles
  ocliv access share|rotate|revoke [LEASE]                    ephemeral share-link credentials
  ocliv mcp expose|manage|publish|serve                       low-level MCP publisher commands
  ocliv connect ... | google ...                              legacy client/connector helpers
  ocliv version
`)
	return code
}

// agentFiles resolves key/config/lease paths.
