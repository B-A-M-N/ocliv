// Package cli implements Ocliv's command dispatch and terminal UX.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"ocliv/internal/apperr"
	"ocliv/internal/protocol"
	"ocliv/internal/store"
)

// BuildCommit and BuildTime can be overridden at link time via -ldflags.
var (
	BuildCommit = ""
	BuildTime   = ""
)

// BinaryVersion is the client/relay build version reported by
// `ocliv version` alongside the wire-protocol range. Bump together
// with protocol.MinVersion/MaxVersion when the wire changes.
const BinaryVersion = "1.0.0"

// versionString renders the build and wire-protocol identity from the
// single-source constants, never hardcoded literals that can drift.
func versionString() string {
	return fmt.Sprintf("ocliv %s (protocol %s, supported %s-%s)",
		BinaryVersion, protocol.Version, protocol.MinVersion, protocol.MaxVersion)
}

func buildVersionInfo() map[string]any {
	commit := BuildCommit
	buildTime := BuildTime
	if info, ok := debug.ReadBuildInfo(); ok {
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
			}
		}
	}
	return map[string]any{
		"version":             BinaryVersion,
		"commit":              commit,
		"build_time":          buildTime,
		"os":                  runtime.GOOS,
		"arch":                runtime.GOARCH,
		"go_version":          runtime.Version(),
		"schema_version":      store.SchemaVersion,
		"protocol_version":    protocol.Version,
		"supported_protocols": protocol.MinVersion + "-" + protocol.MaxVersion,
		"capabilities": []string{
			"mcp_managed_oauth",
			"appended_as_discovery",
			"direct_grant_v13",
			"confidential_refresh_v14",
			"cors_mcp_headers",
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
	case "status":
		return cmdStatus(argv[1:])
	case "doctor":
		return cmdDoctor(argv[1:])
	case "relay":
		return cmdRelay(argv[1:])
	case "setup":
		return cmdSetup(argv[1:])
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
	case "host":
		return cmdHost(argv[1:])
	default:
		if strings.HasPrefix(argv[0], "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q; see `ocliv help`\n", argv[0])
			return apperr.ExitCLIValidation
		}
		return cmdTunnel(argv)
	}
}

func usage(code int) int {
	fmt.Print(`Ocliv — secure instant HTTPS hosting.

Everyday:
  ocliv PORT                  share localhost:PORT over protected HTTPS
  ocliv mcp PORT [--name N]   publish the MCP server on localhost:PORT (OAuth enforced)
  ocliv status [--json]       tunnel state with the next action when unhealthy
  ocliv doctor                diagnose key, relay, local service, and DNS/TLS
  ocliv login --relay URL --code-file PATH   enroll this machine once
  ocliv profile create NAME | use NAME|default | list   separate enrollments

Advanced:
  ocliv PORT [--public] [--ipv6] [--name NAME] [--ttl 2h] [--upstream-host H] [--json] [--no-share-link] [--share-link-file PATH]
  ocliv logout
  ocliv access share|rotate|revoke [LEASE]
  ocliv relay init --domain DOMAIN | relay serve --domain DOMAIN [--mcp-host HOST] [--mcp-port PORT] [--relay-host HOST] | relay doctor | relay issue-enroll
  ocliv mcp expose -- COMMAND [ARGS...]
  ocliv mcp manage
  ocliv mcp publish (--local URL | --stdio -- CMD [ARGS...]) --auth upstream-oauth|ocliv-managed [--relay URL] [--name N] [--ttl D] ...
  ocliv mcp serve --local URL --auth upstream-oauth|fixture-anonymous [--relay URL] ...
  ocliv mcp doctor [--lease ID] [--name LABEL]
  ocliv mcp list|unpublish ...
  ocliv profile create NAME | use NAME|default | list
  ocliv setup --auto [--edge single-host|tunnel|wildcard] [--json] [--hostname ZONE.dynv6.net] [--acme-email ADDR] [--token-file PATH] [--dry-run] [--data-dir DIR] [--out DIR] [--refresh-dns] [--provider oracle ...] | setup --check ...
  ocliv version
`)
	return code
}

// agentFiles resolves key/config/lease paths.
