package cli

// Focused MCP lifecycle orchestration: `mcp publish`, `mcp serve`, and
// `mcp doctor` (P1). One typed config selects the local MCP source and
// the authorization profile; the service then owns process and tunnel
// lifecycle without a daemon manager, shell, or second state authority.
//
//   - publish --local URL --auth A: tunnel to an already-listening
//     loopback MCP server in mode A, register-or-rebind the durable
//     publication, print the stable endpoint, run until Ctrl+C, then
//     close the lease and RETAIN the publication (offline until the
//     next authorized republish rebinds it). Permanent removal is
//     explicit via `mcp unpublish` (P1-A).
//   - publish --stdio: per-client Streamable HTTP sessions backed by
//     isolated stdio children; managed authorization only.
//   - serve: lifecycle only (tunnel, no route registration) — for
//     wildcard-namespace use or pre-publish verification.
//   - doctor: read-only diagnostics; never prints secrets.
//
// `mcp expose` and `mcp manage` are untouched. There is no --public
// flag: MCP leases are never public, and generic tunnels stay protected
// by default.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/mcp"
)

// mcpAuthProfiles maps the operator-facing --auth values to the signed
// path segments the relay enforces (P0-B). The relay owns the binding;
// the CLI never invents profile names.
var mcpAuthProfiles = map[string]string{
	"upstream-oauth":    "upstream-oauth",
	"fixture-anonymous": "fixture-anonymous",
	"ocliv-managed":     "managed-oauth",
}

// mcpPublishConfig is the single typed publish/serve configuration
// parsed once from argv and handed to the lifecycle service.
type mcpPublishConfig struct {
	localURL string
	stdio    bool
	auth     string
	name     string
	ttl      string
	dir      string
	env      []string
	cmd      []string
	serve    bool // serve: lifecycle without route registration
	// freshPublication asks for a NEW publication identity even when
	// the service already has one. Without it, publishing the same
	// service again reuses the durable identity derived from the
	// service, so the public URL survives restarts (P1).
	freshPublication bool
	// strictDiscovery refuses to enter steady state when OAuth
	// resource discovery is unproven (P0-B). Discovery verification
	// is the default for publish: strict deletes the route and fails
	// closed so an unverified binding never serves. --strict-discovery
	// is accepted for back-compat and means the same as the default.
	strictDiscovery bool
	// devAllowUnverified is a discovery-only relaxation for
	// development/diagnostic use (P0-B item 2): the route registers and
	// serves when OAuth discovery is unreachable, but is marked NOT
	// VERIFIED and must never be registered with ChatGPT.
	devAllowUnverified bool
	// acceptUnverifiedUpstreamAuth permits publication after protocol
	// validity is proven when the upstream does not reject absent and
	// invalid bearer credentials. Such a route remains visibly UNVERIFIED.
	acceptUnverifiedUpstreamAuth bool
	// resourceFile is the publisher-owned binding handoff: after route
	// registration the publisher atomically writes the canonical public
	// route URL here so a local MCP server (e.g. mcp-auth-fixture via
	// MCP_RESOURCE_FILE) can advertise exactly that resource before
	// strict discovery probes it. Empty means no handoff; strict
	// discovery then only passes if the server was preconfigured.
	resourceFile string
	// relay is the explicit --relay target. Empty means "not named on
	// the command line", in which case the ordinary resolution applies
	// (OCLIV_RELAY_URL > agent config file > built-in default). A
	// non-empty value wins over every other source and is used for
	// BOTH the relay management API calls and the agent tunnel, so the
	// two halves of a publication can never target different relays.
	relay string
}

// writeResourceBinding atomically publishes the canonical route URL to
// the operator-chosen binding path (0600, tmp+rename). The content is a
// public URL, not a secret, but the write must be atomic so a concurrent
// metadata reader never observes a truncation.
func writeResourceBinding(path, routeURL string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".resource-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(routeURL + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// activatePublishedRoute marks a registered publication verified after
// the publisher completes discovery verification (P0-A). The relay
// CAS-gates the transition on ownership, live binding, and unrevoked
// status; a non-200 here means the route must be abandoned, never
// advertised. Returns the relay status and body.
func activatePublishedRoute(relayURL string, k *identity.KeyPair, keyID, routeLeaseID, routeID string) (int, string) {
	st, body, err := mgmtCall(relayURL, k, keyID, "POST",
		"/v1/agent/lease/"+routeLeaseID+"/mcp-route/"+routeID+"/activate")
	if err != nil {
		return 0, "transport failure: " + err.Error()
	}
	return st, string(body)
}

// abandonPublishedRoute removes only an identity created by the failing
// run. If registration rebound an existing publication, it CAS-detaches
// this failed lease and preserves the stable route and its grants.
func abandonPublishedRoute(call func(method, path string) (int, string), routeLeaseID, routeID string, created bool) (int, string) {
	method, suffix := http.MethodPost, "/detach"
	if created {
		method, suffix = http.MethodDelete, ""
	}
	path := "/v1/agent/lease/" + routeLeaseID + "/mcp-route/" + routeID + suffix
	status, body := call(method, path)
	return status, shortDetail(body)
}

// errActivationFailed marks a readiness failure in the activation
// step (as opposed to discovery). Callers switch on it to report
// which half of proveRouteReady failed.
var errActivationFailed = errors.New("route activation failed")

// proveRouteReady is the single readiness decision for publication
// (P0-A): run discovery verification (unless dev-allow excuses an
// unreachable endpoint), then activate the registered route. The
// public URL is advertised only when this returns nil. verify is
// tried first; activate runs only when verification passes or is
// explicitly excused — a fatal verification error never activates,
// and a failed activation is always fatal. Returns devOnly=true when
// discovery was excused (activation still required).
func proveRouteReady(cfg mcpPublishConfig, verify func() error, activate func() (int, string)) (bool, error) {
	if verr := verify(); verr != nil {
		if !discoveryFailureFatal(cfg, verr) {
			devOnly := true
			if st, body := activate(); st != http.StatusOK {
				return false, fmt.Errorf("%w: relay status %d: %s", errActivationFailed, st, shortDetail(body))
			}
			return devOnly, nil
		}
		return false, verr
	}
	if st, body := activate(); st != http.StatusOK {
		return false, fmt.Errorf("%w: relay status %d: %s", errActivationFailed, st, shortDetail(body))
	}
	return false, nil
}

// publicationRecovery re-verifies a durable publication whenever the relay
// reclaims its named lease onto a new attachment. Same-lease resumptions do
// not clear verification; a changed lease must prove readiness and activate
// before its stable route can serve again.
type publicationRecovery struct {
	relayURL   string
	k          *identity.KeyPair
	keyID      string
	cfg        mcpPublishConfig
	routeID    string
	routeURL   string
	boundLease string
}

func (r *publicationRecovery) onReattach(ra agent.Attached) {
	if ra.LeaseID == "" || ra.LeaseID == r.boundLease {
		return
	}
	verify := func() error {
		if r.cfg.auth == "ocliv-managed" {
			return nil // relay-managed OAuth has no upstream discovery document
		}
		durl, err := mcpRouteDiscoveryURL(r.routeURL, r.routeID)
		if err != nil {
			return err
		}
		client, err := mgmtHTTPClient(15 * time.Second)
		if err != nil {
			return fmt.Errorf("%w: unreadable OCLIV_CACERT bundle: %v", errDiscoveryUnreachable, err)
		}
		if err := validateMCPResourceMetadata(client, durl, r.routeURL); err != nil {
			return err
		}
		aurl, err := mcpRouteASDiscoveryURL(r.routeURL, r.routeID)
		if err != nil {
			return err
		}
		expectIssuer := strings.TrimSuffix(r.routeURL, "/mcp") + "/oauth"
		return validateMCPASMetadata(client, aurl, expectIssuer)
	}
	_, err := proveRouteReady(r.cfg, verify, func() (int, string) {
		return activatePublishedRoute(r.relayURL, r.k, r.keyID, ra.LeaseID, r.routeID)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: publication re-activation on lease %s failed; stable route remains unverified: %v\n", ra.LeaseID, err)
		return
	}
	r.boundLease = ra.LeaseID
	fmt.Fprintf(os.Stderr, "✓ Re-activated publication %s on reclaimed lease %s\n", r.routeID, ra.LeaseID)
}

// discoveryFailureFatal reports whether a discovery error must abort
// publication (P0-B): invalid bindings always abort; unreachable
// discovery aborts by default, where an unproven binding must never
// serve. Only explicit --dev-allow-unverified-discovery warns and
// continues, and then only for development/diagnostic use.
func discoveryFailureFatal(cfg mcpPublishConfig, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errDiscoveryUnreachable) {
		return !cfg.devAllowUnverified
	}
	return true
}

// mcpFlagValue accepts both `--flag value` (house style for `ocliv PORT`
// and the target publish UX) and `--flag=value` (house style for the
// existing `mcp` subcommands). A missing value fails closed.
func mcpFlagValue(argv []string, i *int, name string) (string, bool) {
	a := argv[*i]
	if a == "--"+name {
		if *i+1 >= len(argv) {
			fmt.Fprintf(os.Stderr, "flag --%s needs a value\n", name)
			return "", false
		}
		*i++
		return argv[*i], true
	}
	if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
		return v, true
	}
	return "", false
}

func parseMCPPublish(argv []string, serve bool) (mcpPublishConfig, int) {
	var c mcpPublishConfig
	c.serve = serve
	var rest []string
	seenDashDash := false
	bad := func() (mcpPublishConfig, int) {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp publish (--local URL | --stdio -- COMMAND [ARGS...]) --auth upstream-oauth|ocliv-managed [--relay URL] [--name N] [--ttl D] [--strict-discovery] [--resource-file PATH] [--dev-allow-unverified-discovery] [--accept-unverified-upstream-auth]")
		return c, apperr.ExitCLIValidation
	}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !seenDashDash && a == "--" {
			seenDashDash = true
			rest = argv[i+1:]
			break
		}
		if !seenDashDash && (a == "--local" || strings.HasPrefix(a, "--local=")) {
			v, ok := mcpFlagValue(argv, &i, "local")
			if !ok {
				return bad()
			}
			c.localURL = v
		} else if !seenDashDash && a == "--stdio" {
			c.stdio = true
		} else if !seenDashDash && (a == "--auth" || strings.HasPrefix(a, "--auth=")) {
			v, ok := mcpFlagValue(argv, &i, "auth")
			if !ok {
				return bad()
			}
			c.auth = v
		} else if !seenDashDash && (a == "--name" || strings.HasPrefix(a, "--name=")) {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				return bad()
			}
			c.name = v
		} else if !seenDashDash && (a == "--relay" || strings.HasPrefix(a, "--relay=")) {
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return bad()
			}
			c.relay = v
		} else if !seenDashDash && (a == "--ttl" || strings.HasPrefix(a, "--ttl=")) {
			v, ok := mcpFlagValue(argv, &i, "ttl")
			if !ok {
				return bad()
			}
			c.ttl = v
		} else if !seenDashDash && a == "--strict-discovery" {
			c.strictDiscovery = true
		} else if !seenDashDash && a == "--fresh-publication" {
			c.freshPublication = true
		} else if !seenDashDash && a == "--dev-allow-unverified-discovery" {
			c.devAllowUnverified = true
		} else if !seenDashDash && a == "--accept-unverified-upstream-auth" {
			c.acceptUnverifiedUpstreamAuth = true
		} else if !seenDashDash && (a == "--resource-file" || strings.HasPrefix(a, "--resource-file=")) {
			v, ok := mcpFlagValue(argv, &i, "resource-file")
			if !ok {
				return bad()
			}
			c.resourceFile = v
		} else if !seenDashDash && (a == "--dir" || strings.HasPrefix(a, "--dir=")) {
			v, ok := mcpFlagValue(argv, &i, "dir")
			if !ok {
				return bad()
			}
			c.dir = v
		} else if !seenDashDash && (a == "--env" || strings.HasPrefix(a, "--env=")) {
			v, ok := mcpFlagValue(argv, &i, "env")
			if !ok {
				return bad()
			}
			c.env = append(c.env, v)
		} else if !seenDashDash && strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return bad()
		} else {
			rest = argv[i:]
			break
		}
	}
	c.cmd = rest
	// An explicit --relay is validated with the same policy login and
	// the ordinary tunnel parser use (https anywhere; http loopback
	// only) and rejected before any key load, probe, tunnel, or remote
	// call — an invalid target has no partial side effects.
	if c.relay != "" {
		if verr := config.CheckRelayTLS(c.relay); verr != nil {
			fmt.Fprintf(os.Stderr, "invalid --relay: %v\n", verr)
			return bad()
		}
	}
	if _, ok := mcpAuthProfiles[c.auth]; !ok {
		return bad()
	}
	if c.localURL == "" && !c.stdio {
		fmt.Fprintln(os.Stderr, "publish needs --local URL or --stdio")
		return c, apperr.ExitCLIValidation
	}
	if c.localURL != "" && c.stdio {
		fmt.Fprintln(os.Stderr, "pick one of --local or --stdio")
		return c, apperr.ExitCLIValidation
	}
	if c.stdio {
		if serve {
			fmt.Fprintln(os.Stderr, "mcp serve takes no --stdio: serve has no route")
			return c, apperr.ExitCLIValidation
		}
		if len(c.cmd) == 0 {
			fmt.Fprintln(os.Stderr, "mcp publish --stdio needs a command after --")
			return c, apperr.ExitCLIValidation
		}
		if c.auth != "ocliv-managed" {
			fmt.Fprintln(os.Stderr, "mcp publish --stdio requires --auth ocliv-managed")
			return c, apperr.ExitCLIValidation
		}
		if c.name == "" {
			fmt.Fprintln(os.Stderr, "mcp publish --stdio requires an explicit --name so restarts reuse the same route identity")
			return c, apperr.ExitCLIValidation
		}
	}
	// Anonymous fixtures cannot be published (P0-F): the profile
	// cannot bound an arbitrary local server, so it must never back a
	// public route. Local-only lifecycle (serve) and diagnostics keep
	// accepting it; publish requires --auth upstream-oauth.
	if !serve && c.auth == "fixture-anonymous" {
		fmt.Fprintln(os.Stderr, "mcp publish --auth fixture-anonymous is disabled: anonymous fixtures cannot be published; use `mcp serve --auth fixture-anonymous` for local-only fixtures or publish --auth upstream-oauth")
		return c, apperr.ExitCLIValidation
	}
	// Managed authorization is relay-terminated: there is no upstream OAuth
	// discovery to constrain, no resource binding to hand off, and no
	// dev relaxation to grant. Accepting those flags would silently imply an
	// upstream that does not exist, so they are rejected.
	if c.auth == "ocliv-managed" {
		if c.strictDiscovery {
			fmt.Fprintln(os.Stderr, "mcp publish --auth ocliv-managed takes no --strict-discovery: the relay is the Authorization Server, not an upstream")
			return c, apperr.ExitCLIValidation
		}
		if c.devAllowUnverified {
			fmt.Fprintln(os.Stderr, "mcp publish --auth ocliv-managed takes no --dev-allow-unverified-discovery: there is no upstream discovery to verify")
			return c, apperr.ExitCLIValidation
		}
		if c.resourceFile != "" {
			fmt.Fprintln(os.Stderr, "mcp publish --auth ocliv-managed takes no --resource-file: there is no upstream resource binding to hand off")
			return c, apperr.ExitCLIValidation
		}
		if c.acceptUnverifiedUpstreamAuth {
			fmt.Fprintln(os.Stderr, "mcp publish --auth ocliv-managed takes no --accept-unverified-upstream-auth: this flag applies only to upstream OAuth")
			return c, apperr.ExitCLIValidation
		}
	}
	if c.acceptUnverifiedUpstreamAuth && serve {
		fmt.Fprintln(os.Stderr, "mcp serve takes no --accept-unverified-upstream-auth: authorization qualification applies to publish only")
		return c, apperr.ExitCLIValidation
	}
	if c.acceptUnverifiedUpstreamAuth && c.auth != "upstream-oauth" {
		fmt.Fprintln(os.Stderr, "--accept-unverified-upstream-auth requires --auth upstream-oauth")
		return c, apperr.ExitCLIValidation
	}
	// --strict-discovery only constrains route publication; serve has
	// no route and no discovery, so the combination is rejected
	// rather than silently ignored.
	if serve && c.strictDiscovery {
		fmt.Fprintln(os.Stderr, "mcp serve takes no --strict-discovery: discovery qualification applies to publish only")
		return c, apperr.ExitCLIValidation
	}
	if serve && c.devAllowUnverified {
		fmt.Fprintln(os.Stderr, "mcp serve takes no --dev-allow-unverified-discovery: discovery qualification applies to publish only")
		return c, apperr.ExitCLIValidation
	}
	return c, 0
}

// errDiscoveryUnreachable marks an inconclusive OAuth discovery probe:
// the metadata endpoint could not be reached, so its advertised resource
// is NOT VERIFIED (not proven wrong). Callers warn loudly and continue
// instead of failing closed on publisher network position.
var errDiscoveryUnreachable = errors.New("oauth discovery unreachable")

// mcpRouteDiscoveryURL derives the RFC 9728 well-known URL for a
// relay-minted route URL of the exact shape
// https://<host>/r/<route-id>/mcp. The scheme/host/path contract is the
// relay's (serveMCPRouteMutation mints it); anything else fails closed
// rather than probing an attacker-shaped URL.
func mcpRouteDiscoveryURL(routeURL, routeID string) (string, error) {
	u, err := url.Parse(routeURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("route URL is not a valid https URL: %q", routeURL)
	}
	if u.EscapedPath() != "/r/"+routeID+"/mcp" {
		return "", fmt.Errorf("route URL %q does not match route %q", routeURL, routeID)
	}
	return "https://" + u.Host + "/.well-known/oauth-protected-resource/r/" + routeID + "/mcp", nil
}

// validateMCPResourceMetadata fetches an RFC 9728 protected-resource
// metadata document and requires its advertised "resource" to equal the
// published route URL exactly (P0-E). A reachable document naming a
// different resource fails closed: the upstream would authorize tokens
// for the wrong endpoint. Transport failure is inconclusive
// (errDiscoveryUnreachable), never proof of either validity or attack.
func validateMCPResourceMetadata(client *http.Client, discoveryURL, expectResource string) error {
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("%w: %v", errDiscoveryUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("%w: unreadable discovery body", errDiscoveryUnreachable)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth discovery answered %d (want 200 with resource %q)", resp.StatusCode, expectResource)
	}
	var doc struct {
		Resource string `json:"resource"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Resource == "" {
		return fmt.Errorf("oauth discovery is not a resource metadata document")
	}
	if doc.Resource != expectResource {
		return fmt.Errorf("upstream advertises resource %q, published route is %q", doc.Resource, expectResource)
	}
	return nil
}

// mcpRouteASDiscoveryURL derives the RFC 8414 well-known URL for a
// relay-minted route URL of the exact shape https://<host>/r/<route-id>/mcp.
// The issuer for the route is https://<host>/r/<route-id>/oauth, so its
// metadata lives at /.well-known/oauth-authorization-server/r/<route-id>/oauth.
// Same scheme/host/path discipline as mcpRouteDiscoveryURL.
func mcpRouteASDiscoveryURL(routeURL, routeID string) (string, error) {
	u, err := url.Parse(routeURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("route URL is not a valid https URL: %q", routeURL)
	}
	if u.EscapedPath() != "/r/"+routeID+"/mcp" {
		return "", fmt.Errorf("route URL %q does not match route %q", routeURL, routeID)
	}
	return "https://" + u.Host + "/.well-known/oauth-authorization-server/r/" + routeID + "/oauth", nil
}

// validateMCPASMetadata fetches an RFC 8414 authorization-server metadata
// document and requires its "issuer" to equal the route's OAuth issuer
// exactly. Without this check a relay that admits PRM and MCP but rejects
// AS metadata (421) passes strict discovery while OAuth cannot complete.
// Transport failure is inconclusive (errDiscoveryUnreachable); a reachable
// non-200 (including 421) or mismatched issuer is a hard failure.
func validateMCPASMetadata(client *http.Client, discoveryURL, expectIssuer string) error {
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("%w: %v", errDiscoveryUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("%w: unreadable discovery body", errDiscoveryUnreachable)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth authorization-server discovery answered %d (want 200 with issuer %q)", resp.StatusCode, expectIssuer)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Issuer == "" {
		return fmt.Errorf("oauth authorization-server discovery is not a metadata document")
	}
	if doc.Issuer != expectIssuer {
		return fmt.Errorf("upstream advertises issuer %q, published route expects %q", doc.Issuer, expectIssuer)
	}
	return nil
}

// publishLocalProbeOK is the publish local-target gate: a usable MCP
// tools/list reply is mandatory. Upstream OAuth also requires a separately
// verified rejection of absent and invalid bearer credentials, unless the
// operator explicitly accepts that facet as unverified.
func publishLocalProbeOK(out mcpProbeOutcome, auth string, acceptUnverifiedAuth bool) bool {
	if !out.Verified {
		return false
	}
	if auth == "upstream-oauth" {
		return out.AuthEnforced || acceptUnverifiedAuth
	}
	return true
}

func publishInitialProbeOK(out mcpProbeOutcome, cfg mcpPublishConfig) bool {
	if publishLocalProbeOK(out, cfg.auth, cfg.acceptUnverifiedUpstreamAuth) {
		return true
	}
	// A resource-file-bound endpoint cannot complete tools/list until it
	// receives the public URL. Accept only its exact pre-handoff signal;
	// repeat protocol and auth checks after writing the binding, before
	// activating the public route.
	return cfg.auth == "upstream-oauth" && cfg.resourceFile != "" && out.UnboundHandoff
}

// mcpIngressProfile maps the CLI-facing --auth value to the relay-facing
// ingress profile. They differ only for the managed mode, which is exactly
// why a live publish is the only reliable test of this mapping.
func mcpIngressProfile(auth string) string {
	return mcpAuthProfiles[auth]
}

// mcpAccessMode maps the --auth profile to the lease access mode born
// at allocation (P1). The strings duplicate relay constants by design:
// the CLI submits its intent and the relay validates it authoritatively.
func mcpAccessMode(auth string) string {
	if auth == "fixture-anonymous" {
		return "mcp_anonymous_fixture"
	}
	if auth == "ocliv-managed" {
		return "mcp_managed_oauth"
	}
	return "mcp_upstream_oauth"
}

// parseMCPLocalURL validates a --local value: http on a loopback host
// with an explicit port, serving exactly /mcp (the only backend path a
// route forwards). Userinfo, query, and fragments have no publishing
// semantics and are rejected rather than silently dropped. The loopback
// family is reported so the probe and tunnel honor an IPv6-only server
// instead of failing against 127.0.0.1 (P2-1). Anything else fails
// before any tunnel or route exists.
func parseMCPLocalURL(raw string) (port int, v6 bool, err error) {
	u, perr := url.Parse(raw)
	if perr != nil {
		return 0, false, fmt.Errorf("invalid --local URL: %v", perr)
	}
	if u.Scheme != "http" {
		return 0, false, fmt.Errorf("--local must be http (loopback): %q", raw)
	}
	if u.User != nil {
		return 0, false, fmt.Errorf("--local must not carry userinfo: %q", raw)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return 0, false, fmt.Errorf("--local must not carry a query string: %q", raw)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return 0, false, fmt.Errorf("--local must not carry a fragment: %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "127.0.0.1", "localhost":
	case "::1":
		v6 = true
	default:
		return 0, false, fmt.Errorf("--local must be loopback, got host %q", u.Hostname())
	}
	p := strings.TrimSuffix(u.Path, "/")
	if p != "/mcp" {
		return 0, false, fmt.Errorf("--local path must be /mcp (the route forwards exactly /mcp), got %q", u.Path)
	}
	portStr := u.Port()
	if portStr == "" {
		return 0, false, fmt.Errorf("--local needs an explicit port: %q", raw)
	}
	n, cerr := strconv.Atoi(portStr)
	if cerr != nil || n <= 0 || n > 65535 {
		return 0, false, fmt.Errorf("invalid --local port: %q", raw)
	}
	return n, v6, nil
}

// mcpTunnelOptions reuses the ordinary tunnel flag parser (config file,
// env, and defaults precedence included) with the MCP port and mode
// applied. `ocliv PORT` never sets AccessMode; only publish/serve do.
func mcpTunnelOptions(port int, v6 bool, c mcpPublishConfig) (tunnelOptions, int) {
	argv := []string{strconv.Itoa(port)}
	if v6 {
		argv = append(argv, "--ipv6")
	}
	// Forward the explicit --relay as a tunnel flag. parseTunnelOptions
	// already owns --relay and its precedence (flag > env > config file
	// > default), so the tunnel target is the exact relay named for the
	// management API calls instead of a second, possibly different
	// resolution. Absent --relay, nothing is forwarded and the
	// historical precedence stands unchanged.
	if c.relay != "" {
		argv = append(argv, "--relay="+c.relay)
	}
	// The publication identity (P1): an explicit --name always wins;
	// otherwise the name is DERIVED from the service, so publishing the
	// same service again rebinds the same durable route instead of
	// minting a second one with a different URL. A --fresh-publication
	// request deliberately asks for a NEW identity, so it appends a
	// distinguishing suffix rather than reusing the derived one.
	name := c.name
	if name == "" {
		name = defaultPublicationName(port, c.localURL, c.auth)
	}
	if c.freshPublication {
		name = freshPublicationName(name)
	}
	if name != "" {
		argv = append(argv, "--name="+name)
	}
	if c.ttl != "" {
		argv = append(argv, "--ttl="+c.ttl)
	}
	opts, code := parseTunnelOptions(argv)
	if code != 0 {
		return opts, code
	}
	opts.cfg.AccessMode = mcpAccessMode(c.auth)
	// Bounded default lease TTL (P1-8): an MCP publication without an
	// explicit --ttl (or config default_ttl) expires after 12h, so a
	// failed remote close cannot leave an indefinite exposure window.
	// Pass --ttl explicitly for longer-lived hosting.
	if opts.cfg.TTLSeconds == 0 {
		opts.cfg.TTLSeconds = 12 * 3600
	}
	if !c.serve && opts.cfg.TTLSeconds < 60 {
		fmt.Fprintln(os.Stderr, "mcp publish requires --ttl of at least 60s for supervised lease renewal")
		return opts, apperr.ExitCLIValidation
	}
	return opts, 0
}

func cmdMCPPublish(argv []string) int {
	return runMCPPublish(argv, false)
}

// resolveMCPRelay applies the publish/serve relay precedence: explicit
// --relay > OCLIV_RELAY_URL > agent config file relay_url > built-in
// default. agentRelayURL already implements the last three in that
// order, so the explicit flag only has to win over all of them.
func resolveMCPRelay(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return agentRelayURL()
}

func cmdMCPServe(argv []string) int {
	return runMCPPublish(argv, true)
}

// cmdMCPList reports every publication owned by the enrolled key (P0-D):
// identity first, leases second. A row is a routing hint only —
// liveness comes from the relay's admission path, not this table. An
// optional --name filters to one publication label.
func cmdMCPList(argv []string) int {
	name := ""
	profile := ""
	usage := "usage: ocliv mcp list [--profile NAME] [--name LABEL]"
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--profile" || strings.HasPrefix(a, "--profile=") {
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok || v != "default" && !config.ValidProfileName(v) {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			profile = v
		} else if a == "--name" || strings.HasPrefix(a, "--name=") {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			name = v
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q (%s)\n", a, usage)
			return apperr.ExitCLIValidation
		}
	}
	if profile != "" {
		old, had := os.LookupEnv("OCLIV_PROFILE")
		if err := os.Setenv("OCLIV_PROFILE", profile); err != nil {
			fmt.Fprintf(os.Stderr, "mcp list: select profile: %v\n", err)
			return apperr.ExitInternal
		}
		defer func() {
			if had {
				_ = os.Setenv("OCLIV_PROFILE", old)
			} else {
				_ = os.Unsetenv("OCLIV_PROFILE")
			}
		}()
	}
	k, keyID, err := loadKey()
	if err != nil {
		if profile != "" {
			fmt.Fprintf(os.Stderr, "mcp list: profile %q is unavailable or not enrolled; create it with `ocliv profile create %s`, then enroll with `ocliv profile use %s` and `ocliv login --relay URL --code-file PATH`\n", profile, profile, profile)
		} else {
			fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		}
		return apperr.ExitAuth
	}
	relayURL := agentRelayURL()
	code, body, callErr := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/mcp-routes")
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "mcp list: relay transport failed: %v\n", callErr)
		return apperr.ExitRelayTLS
	}
	if code != http.StatusOK {
		if code == http.StatusForbidden {
			fmt.Fprintf(os.Stderr, "mcp list: relay denied this profile's management key (403); this is an authentication/authorization failure, not an empty inventory. Relay: %s. Check the selected profile's relay, key enrollment, tenant, and authorization status.\n", config.RedactedURL(relayURL))
		} else {
			fmt.Fprintf(os.Stderr, "mcp list: relay status %d: %s\n", code, shortDetail(string(body)))
		}
		return apperr.ExitAuth
	}
	var list struct {
		Publications []struct {
			RouteID          string  `json:"route_id"`
			Host             string  `json:"external_host"`
			URL              *string `json:"url"`
			Profile          string  `json:"profile"`
			Name             string  `json:"pub_name"`
			LeaseID          *string `json:"lease_id"`
			CreatedAt        string  `json:"created_at"`
			RevokedAt        *string `json:"revoked_at"`
			VerifiedAt       *string `json:"verified_at"`
			PublicationState string  `json:"publication_state"`
			LeaseState       *string `json:"lease_state"`
			SessionLive      *bool   `json:"session_live"`
			HostBinding      string  `json:"host_binding"`
			Admission        string  `json:"admission"`
			AdmissionReason  string  `json:"admission_reason"`
		} `json:"publications"`
	}
	if err := json.Unmarshal(body, &list); err != nil || list.Publications == nil {
		fmt.Fprintln(os.Stderr, "mcp list: relay reply unparseable")
		return apperr.ExitInternal
	}
	fmt.Printf("%-24s %-14s %-12s %-10s %-8s %-9s %-10s %-26s %s\n", "ROUTE ID", "PROFILE", "NAME", "PUBLICATION", "LEASE", "SESSION", "HOST", "ADMISSION", "URL")
	shown := 0
	for _, p := range list.Publications {
		if name != "" && p.Name != name {
			continue
		}
		pubState := p.PublicationState
		if pubState == "" {
			// An older relay does not provide the state fields required
			// to distinguish publication health. Do not infer success.
			pubState = "UNKNOWN"
		}
		lease := "UNKNOWN"
		if p.LeaseState != nil {
			lease = *p.LeaseState
		} else if p.LeaseID == nil {
			lease = "MISSING"
		}
		session := "UNKNOWN"
		if p.SessionLive != nil {
			if *p.SessionLive {
				session = "ONLINE"
			} else {
				session = "OFFLINE"
			}
		}
		hostBinding := p.HostBinding
		if hostBinding == "" {
			hostBinding = "UNKNOWN"
		}
		admission := p.AdmissionReason
		if p.Admission != "" && p.Admission != "READY" {
			admission = p.Admission + ":" + admission
		}
		if admission == "" {
			admission = "UNKNOWN"
		}
		publicURL := "unavailable"
		if p.URL != nil && *p.URL != "" {
			publicURL = *p.URL
		}
		if p.PublicationState == "" || p.HostBinding == "" {
			fmt.Fprintf(os.Stderr, "mcp list: relay upgrade required for authoritative publication and admission state; row %s is diagnostic only\n", p.RouteID)
		}
		if p.LeaseID == nil {
			lease = "MISSING"
		} else if p.LeaseState == nil && p.PublicationState != "" {
			lease = "UNKNOWN"
		}
		fmt.Printf("%-24s %-14s %-12s %-10s %-8s %-9s %-10s %-26s %s\n",
			p.RouteID, p.Profile, p.Name, pubState, lease, session, hostBinding, admission, publicURL)
		shown++
	}
	if shown == 0 {
		if name != "" {
			fmt.Fprintf(os.Stderr, "mcp list: no publication named %q\n", name)
			return apperr.ExitInternal
		}
		fmt.Println("no publications")
	}
	return apperr.ExitOK
}

// cmdMCPUnpublish permanently removes a publication: every path route
// bound to the selected lease is deleted, then the lease is closed,
// each with an independently recorded outcome (P1-A). Unlike SIGINT
// shutdown — which retains the publication offline for stable-URL
// restarts — unpublish is the explicit end of a public endpoint.
// A route already gone (404) counts as removed: the end state is what
// matters. The lease close must still confirm, or the exit is nonzero.
func cmdMCPUnpublish(argv []string) int {
	leaseID := ""
	name := ""
	routeID := ""
	usage := "usage: ocliv mcp unpublish [--publication-id ID] [--lease ID] [--name LABEL]"
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--lease" || strings.HasPrefix(a, "--lease=") {
			v, ok := mcpFlagValue(argv, &i, "lease")
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			leaseID = v
		} else if a == "--name" || strings.HasPrefix(a, "--name=") {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			name = v
		} else if a == "--publication-id" || strings.HasPrefix(a, "--publication-id=") ||
			a == "--route" || strings.HasPrefix(a, "--route=") {
			key := "publication-id"
			if strings.HasPrefix(strings.TrimPrefix(a, "--"), "route") {
				key = "route"
			}
			v, ok := mcpFlagValue(argv, &i, key)
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			routeID = v
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q (%s)\n", a, usage)
			return apperr.ExitCLIValidation
		}
	}
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	relayURL := agentRelayURL()
	// A stable publication name is resolved from the authenticated durable
	// inventory, not the local lease cache: shutdown deliberately removes
	// that cache while retaining the publication for a later resume/revoke.
	if routeID == "" && name != "" && leaseID == "" {
		lstatus, lbody, lerr := mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "mcp revoke: publication lookup failed: %v\n", lerr)
			return apperr.ExitRelayTLS
		}
		if lstatus != http.StatusOK {
			fmt.Fprintf(os.Stderr, "mcp revoke: publication lookup failed (relay status %d): %s\n", lstatus, shortDetail(string(lbody)))
			return apperr.ExitAuth
		}
		var inventory struct {
			Publications []struct {
				RouteID string `json:"route_id"`
				Name    string `json:"pub_name"`
			} `json:"publications"`
		}
		if err := json.Unmarshal(lbody, &inventory); err != nil || inventory.Publications == nil {
			fmt.Fprintln(os.Stderr, "mcp revoke: publication inventory unparseable")
			return apperr.ExitInternal
		}
		var matches []string
		for _, p := range inventory.Publications {
			if p.Name == name && p.RouteID != "" {
				matches = append(matches, p.RouteID)
			}
		}
		if len(matches) == 0 {
			fmt.Fprintf(os.Stderr, "mcp revoke: no publication named %q belongs to this key\n", name)
			return apperr.ExitCLIValidation
		}
		if len(matches) != 1 {
			fmt.Fprintf(os.Stderr, "mcp revoke: publication name %q is ambiguous across %d routes; use --publication-id ID\n", name, len(matches))
			return apperr.ExitCLIValidation
		}
		routeID = matches[0]
		name = "" // now operating on the exact durable publication ID
	}
	// Publication-identity path (P0-D): revoke exactly one owned
	// publication by route ID. No lease resolution, no lease close —
	// the publication outlives leases by design, and sibling
	// publications are never touched.
	if routeID != "" {
		if leaseID != "" || name != "" {
			fmt.Fprintln(os.Stderr, "mcp unpublish: --publication-id cannot be combined with --lease or --name")
			return apperr.ExitCLIValidation
		}
		dstatus, dbody, callErr := mgmtCall(relayURL, k, keyID, "DELETE", "/v1/agent/mcp-routes/"+routeID)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "mcp unpublish: route delete transport failed: %v\n", callErr)
			return apperr.ExitRelayTLS
		}
		switch dstatus {
		case http.StatusOK:
			fmt.Printf("✓ MCP publication removed: %s\n", routeID)
			return apperr.ExitOK
		case http.StatusNotFound:
			// The relay deliberately does not disclose whether the route
			// exists but belongs to another key, so a 404 is ambiguous
			// between "already gone" and "not owned". Report that
			// honestly with a distinct nonzero exit: a 404 is NOT a
			// confirmed deletion and must never print success.
			fmt.Fprintf(os.Stderr, "mcp unpublish: publication %s not found or not owned by this key (the relay does not disclose ownership)\n", routeID)
			return apperr.ExitAuth
		default:
			fmt.Fprintf(os.Stderr, "mcp unpublish: route %s delete reported status %d (%s)\n",
				routeID, dstatus, shortDetail(string(dbody)))
			return apperr.ExitInternal
		}
	}
	dir, _, _, _ := agentFiles()
	leaseID, msg, code := selectDoctorLeaseID(dir, name, leaseID)
	if code != 0 {
		fmt.Fprint(os.Stderr, msg)
		return code
	}
	ready := tunnelReady{
		opts:  tunnelOptions{cfg: config.Agent{RelayURL: relayURL}},
		dir:   dir,
		key:   k,
		keyID: keyID,
	}
	failed := false
	lcode, lbody, callErr := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/lease/"+leaseID+"/mcp-route")
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "mcp unpublish: route list transport failed: %v\n", callErr)
		return apperr.ExitRelayTLS
	}
	if lcode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "mcp unpublish: route list failed (relay status %d): %s\n",
			lcode, shortDetail(string(lbody)))
		return apperr.ExitAuth
	}
	var list struct {
		Routes []struct {
			RouteID string `json:"route_id"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(lbody, &list); err != nil {
		fmt.Fprintln(os.Stderr, "mcp unpublish: relay route reply unparseable")
		return apperr.ExitInternal
	}
	for _, rt := range list.Routes {
		dstatus, dbody, callErr := mgmtCall(relayURL, k, keyID, "DELETE",
			"/v1/agent/lease/"+leaseID+"/mcp-route/"+rt.RouteID)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "mcp unpublish: route %s delete transport failed: %v\n", rt.RouteID, callErr)
			failed = true
			continue
		}
		// 404 is the desired end state (already gone), not a failure.
		if dstatus != http.StatusOK && dstatus != http.StatusNotFound {
			fmt.Fprintf(os.Stderr, "mcp unpublish: route %s delete reported status %d (%s)\n",
				rt.RouteID, dstatus, shortDetail(string(dbody)))
			failed = true
			continue
		}
		fmt.Printf("✓ MCP route removed: %s\n", rt.RouteID)
	}
	lr := closeLeaseWith(defaultLeaseCloser, ready, leaseID)
	if msg := lr.Report(); msg != "" {
		fmt.Fprint(os.Stderr, msg)
	}
	if !lr.RemoteConfirmed() || failed {
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}

// runMCPPublish owns the full lifecycle: optional local adapter, tunnel in
// the requested mode, optional route registration, steady state, and
// ordered cleanup with independently recorded outcomes.
func runMCPPublish(argv []string, serve bool) int {
	cfg, code := parseMCPPublish(argv, serve)
	if code != 0 {
		return code
	}
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	relayURL := resolveMCPRelay(cfg.relay)

	// 1. Local source: validate and start before any tunnel or route, so
	// a bad local target fails with nothing registered remotely.
	port := 0
	v6 := false
	if cfg.stdio {
		// The stdio adapter is started here, before any tunnel or route,
		// and torn down with this process. Its child was pinned by local
		// argv in parseMCPPublish; no request content can change it.
		a, err := mcp.New(mcp.Options{
			Command:             cfg.cmd[0],
			Args:                cfg.cmd[1:],
			Dir:                 cfg.dir,
			Env:                 cfg.env,
			MultiClientSessions: true,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp publish --stdio: %v\n", err)
			return apperr.ExitCLIValidation
		}
		actx, astop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		if err := a.Start(actx); err != nil {
			fmt.Fprintf(os.Stderr, "mcp publish --stdio: %v\n", err)
			return apperr.ExitAuth
		}
		defer a.Close()
		defer astop()
		host, pstr, err := net.SplitHostPort(a.Addr().String())
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp publish --stdio: adapter address: %v\n", err)
			return apperr.ExitInternal
		}
		n, err := strconv.Atoi(pstr)
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "mcp publish --stdio: bad adapter port %q\n", pstr)
			return apperr.ExitInternal
		}
		port, v6 = n, host == "::1"
		fmt.Printf("stdio adapter: %v on http://%s:%d (loopback only)\n", cfg.cmd, host, port)
	} else {
		var perr error
		port, v6, perr = parseMCPLocalURL(cfg.localURL)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "mcp publish: %v\n", perr)
			return apperr.ExitCLIValidation
		}
	}
	target := config.LoopbackTarget(port, v6)
	if perr := agent.ProbeLocal(target, 3*time.Second); perr != nil {
		fmt.Fprintf(os.Stderr, "local MCP unreachable at %s: %v\n", target, perr)
		return apperr.ExitLocalTarget
	}
	var upstreamBearer string
	if cfg.auth == "upstream-oauth" {
		upstreamBearer = os.Getenv("OCLIV_UPSTREAM_MCP_TOKEN")
	}
	// The local endpoint must speak MCP before a public route is
	// activated for it. For upstream OAuth, the optional operator token
	// lets the probe verify tools/list behind the server's auth boundary.
	pout := runMCPProbeWithBearer(target, mcpAccessMode(cfg.auth), upstreamBearer)
	upstreamAuthUnverified := false
	if !pout.Verified && !publishInitialProbeOK(pout, cfg) {
		fmt.Fprintf(os.Stderr, "local MCP %s failed protocol check: %s\n", target, pout.Summary)
		if cfg.auth == "upstream-oauth" && pout.Auth == "AUTH_REQUIRED" {
			fmt.Fprintln(os.Stderr, "set OCLIV_UPSTREAM_MCP_TOKEN to a valid local upstream bearer so publish can verify tools/list")
		}
		return apperr.ExitLocalTarget
	}
	if pout.Verified && cfg.auth == "upstream-oauth" {
		pout.AuthEnforced = verifyUpstreamAuthEnforcement(target)
		if !publishLocalProbeOK(pout, cfg.auth, cfg.acceptUnverifiedUpstreamAuth) {
			fmt.Fprintln(os.Stderr, "local MCP protocol is valid, but upstream OAuth enforcement is UNVERIFIED: the server did not reject both missing and invalid bearer credentials")
			fmt.Fprintln(os.Stderr, "fix upstream bearer enforcement or explicitly pass --accept-unverified-upstream-auth; this route will remain marked NOT VERIFIED")
			return apperr.ExitLocalTarget
		}
		upstreamAuthUnverified = !pout.AuthEnforced
	}
	fmt.Printf("local MCP: %s\n", pout.Summary)

	// 2. Tunnel in the requested mode.
	opts, tcode := mcpTunnelOptions(port, v6, cfg)
	if tcode != 0 {
		return tcode
	}
	ready, pcode := prepareTunnel(opts)
	if pcode != 0 {
		return pcode
	}
	// MCP publish supervises a durable route and renews its lease. Ordinary
	// tunnels retain terminal TTL semantics, including --ttl expiry.
	if !serve {
		ready.runner.Cfg.RenewLease = true
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, live, rcode, ok := runTunnel(ctx, ready)
	if !ok {
		return rcode
	}
	if a.AccessMode != mcpAccessMode(cfg.auth) {
		fmt.Fprintf(os.Stderr, "mcp publish: relay allocated mode %q, want %q; refusing to publish\n",
			a.AccessMode, mcpAccessMode(cfg.auth))
		return closeTunnel(ready, a, apperr.ExitAuth)
	}
	renderTunnelAttached(ready, a)

	// 3. Route registration (publish only): after attachment, so the
	// printed endpoint is live, never speculative.
	var routeID, routeURL, routeLeaseID string
	var routeCreated bool
	if !serve {
		// The route's ingress profile is the relay-facing name, not the
		// CLI-facing --auth value: `ocliv-managed` maps to `managed-oauth`.
		// The other two names happen to coincide, which is why this only
		// broke for the managed mode.
		profile := mcpIngressProfile(cfg.auth)
		// The route is owned by the lease that exists at registration
		// time; runSteadyState may re-assign a to a newer attachment, so
		// the DELETE below must use this ID, not the updated a.LeaseID.
		routeLeaseID = a.LeaseID
		rstatus, rbody, callErr := mgmtCall(relayURL, k, keyID, "POST",
			"/v1/agent/lease/"+routeLeaseID+"/mcp-route/"+profile)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "mcp publish: route registration transport failed (relay %s): %v\n", relayURL, callErr)
			return closeTunnel(ready, a, apperr.ExitRelayTLS)
		}
		if rstatus != http.StatusOK {
			// Name the relay that was tried: with several relays in
			// play (env override, HOME-scoped config, explicit
			// --relay), a bare status code leaves the operator
			// unable to tell WHICH relay answered or refused.
			fmt.Fprintf(os.Stderr, "mcp publish: route registration failed (relay %s status %d): %s\n",
				relayURL, rstatus, strings.TrimSpace(string(rbody)))
			return closeTunnel(ready, a, apperr.ExitAuth)
		}
		var rr struct {
			RouteID string `json:"route_id"`
			URL     string `json:"url"`
			Auth    string `json:"auth"`
			Created bool   `json:"created"`
		}
		if jerr := json.Unmarshal(rbody, &rr); jerr != nil || rr.RouteID == "" || rr.URL == "" {
			fmt.Fprintln(os.Stderr, "mcp publish: relay route reply unparseable")
			return closeTunnel(ready, a, apperr.ExitInternal)
		}
		routeID, routeURL, routeCreated = rr.RouteID, rr.URL, rr.Created
		ready.runner.SetRenewalPublication(routeID)
		// No URL is printed yet (P0-B item 3): registration is not
		// readiness. The URL is advertised only after the required
		// security checks complete below.
		// P0 binding handoff: hand the canonical public URL to the
		// local MCP server before strict discovery probes it, so the
		// server's advertised resource can match exactly. A failed
		// handoff abandons the route: serving with an unbound
		// resource would fail (or worse, misverify) discovery.
		if cfg.resourceFile != "" {
			if werr := writeResourceBinding(cfg.resourceFile, routeURL); werr != nil {
				fmt.Fprintf(os.Stderr, "mcp publish: resource binding write failed: %v\n", werr)
				del := func(method, path string) (int, string) {
					st, body, err := mgmtCall(relayURL, k, keyID, method, path)
					if err != nil {
						return 0, "transport failure: " + err.Error()
					}
					return st, string(body)
				}
				if dstatus, ddetail := abandonPublishedRoute(del, routeLeaseID, routeID, routeCreated); dstatus != http.StatusOK {
					if dstatus == 0 {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete transport failed (%s)\n", ddetail)
					} else {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete reported status %d (%s)\n", dstatus, ddetail)
					}
				}
				routeID = ""
				return closeTunnel(ready, a, apperr.ExitInternal)
			}
			fmt.Println("✓ resource binding written (" + cfg.resourceFile + ")")
			// A resource-file server may have returned its exact pre-handoff
			// 503 above. Once bound, require a real tools/list exchange and
			// repeat the missing/invalid bearer checks before activation.
			pout = runMCPProbeWithBearer(target, mcpAccessMode(cfg.auth), upstreamBearer)
			if !pout.Verified {
				fmt.Fprintf(os.Stderr, "mcp publish: bound local server failed MCP protocol verification: %s\n", pout.Summary)
				deleteRoute := func(method, path string) (int, string) {
					st, body, err := mgmtCall(relayURL, k, keyID, method, path)
					if err != nil {
						return 0, "transport failure: " + err.Error()
					}
					return st, string(body)
				}
				if dstatus, detail := abandonPublishedRoute(deleteRoute, routeLeaseID, routeID, routeCreated); dstatus != http.StatusOK {
					fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete status %d (%s)\n", dstatus, detail)
				}
				routeID = ""
				return closeTunnel(ready, a, apperr.ExitLocalTarget)
			}
			if cfg.auth == "upstream-oauth" {
				pout.AuthEnforced = verifyUpstreamAuthEnforcement(target)
				if !publishLocalProbeOK(pout, cfg.auth, cfg.acceptUnverifiedUpstreamAuth) {
					fmt.Fprintln(os.Stderr, "mcp publish: bound server does not prove upstream OAuth enforcement; refusing to activate")
					deleteRoute := func(method, path string) (int, string) {
						st, body, err := mgmtCall(relayURL, k, keyID, method, path)
						if err != nil {
							return 0, "transport failure: " + err.Error()
						}
						return st, string(body)
					}
					if dstatus, detail := abandonPublishedRoute(deleteRoute, routeLeaseID, routeID, routeCreated); dstatus != http.StatusOK {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete status %d (%s)\n", dstatus, detail)
					}
					routeID = ""
					return closeTunnel(ready, a, apperr.ExitLocalTarget)
				}
				upstreamAuthUnverified = !pout.AuthEnforced
			}
			fmt.Printf("local MCP after resource binding: %s\n", pout.Summary)
		}
		// P0-E: for upstream-oauth publications, prove the upstream's
		// advertised OAuth resource is exactly this route before
		// serving it. The discovery document is fetched through the
		// live tunnel via the public path, so this also exercises
		// the route end to end. A mismatch fails closed (delete the
		// route, close the lease); an unreachable endpoint is
		// inconclusive and warns loudly instead of blocking on
		// publisher network position.
		if cfg.auth == "ocliv-managed" {
			// Managed authorization has no upstream OAuth to verify: the
			// relay is the Authorization Server for this route, so there is
			// no upstream discovery document to match. The route is live as
			// soon as it is registered; access is gated by operator approval
			// at admission, never by an unauthenticated fallback.
			fmt.Println("✓ route registered (managed authorization: the relay is the Authorization Server)")
			fmt.Println("  clients register via OAuth DCR, then an operator approves them:")
			fmt.Println("    ocliv authz pending --data <relay-data>")
			fmt.Println("    ocliv authz approve --data <relay-data> --client <id> --tenant <t> --route " + routeID)
		} else if cfg.auth == "upstream-oauth" {
			durl, derr := mcpRouteDiscoveryURL(routeURL, routeID)
			if derr != nil {
				fmt.Fprintf(os.Stderr, "mcp publish: bad route URL from relay: %v\n", derr)
				del := func(method, path string) (int, string) {
					st, body, err := mgmtCall(relayURL, k, keyID, method, path)
					if err != nil {
						return 0, "transport failure: " + err.Error()
					}
					return st, string(body)
				}
				if dstatus, ddetail := abandonPublishedRoute(del, routeLeaseID, routeID, routeCreated); dstatus != http.StatusOK {
					if dstatus == 0 {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete transport failed (%s)\n", ddetail)
					} else {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete reported status %d (%s)\n", dstatus, ddetail)
					}
				}
				routeID = ""
				return closeTunnel(ready, a, apperr.ExitInternal)
			}
			dclient, derr := mgmtHTTPClient(15 * time.Second)
			if derr != nil {
				derr = fmt.Errorf("%w: unreadable OCLIV_CACERT bundle: %v", errDiscoveryUnreachable, derr)
			} else {
				derr = validateMCPResourceMetadata(dclient, durl, routeURL)
			}
			// proveRouteReady is the readiness decision (P0-A): verify
			// OAuth discovery (unless dev-allow excuses an unreachable
			// endpoint), then activate. The URL is advertised only when
			// this returns nil.
			devOnly, verr := proveRouteReady(cfg,
				func() error {
					if derr != nil {
						return derr
					}
					if err := validateMCPResourceMetadata(dclient, durl, routeURL); err != nil {
						return err
					}
					// PRM alone is insufficient: a relay admitting PRM
					// but 421ing AS metadata would pass while OAuth
					// cannot complete. Require AS metadata 200 with
					// the exact route issuer as well.
					aurl, aerr := mcpRouteASDiscoveryURL(routeURL, routeID)
					if aerr != nil {
						return aerr
					}
					expectIssuer := strings.TrimSuffix(routeURL, "/mcp") + "/oauth"
					return validateMCPASMetadata(dclient, aurl, expectIssuer)
				},
				func() (int, string) {
					return activatePublishedRoute(relayURL, k, keyID, routeLeaseID, routeID)
				})
			if verr != nil {
				if errors.Is(verr, errDiscoveryUnreachable) {
					fmt.Fprintf(os.Stderr, "mcp publish: OAuth discovery unreachable and --strict-discovery set: refusing unproven binding: %v\n", verr)
				} else if errors.Is(verr, errActivationFailed) {
					fmt.Fprintf(os.Stderr, "mcp publish: route activation failed: %v\n", verr)
				} else {
					fmt.Fprintf(os.Stderr, "mcp publish: OAuth discovery invalid: %v\n", verr)
				}
				del := func(method, path string) (int, string) {
					st, body, err := mgmtCall(relayURL, k, keyID, method, path)
					if err != nil {
						return 0, "transport failure: " + err.Error()
					}
					return st, string(body)
				}
				if dstatus, ddetail := abandonPublishedRoute(del, routeLeaseID, routeID, routeCreated); dstatus != http.StatusOK {
					if dstatus == 0 {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete transport failed (%s)\n", ddetail)
					} else {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete reported status %d (%s)\n", dstatus, ddetail)
					}
				}
				routeID = ""
				return closeTunnel(ready, a, apperr.ExitAuth)
			}
			if devOnly || upstreamAuthUnverified {
				if upstreamAuthUnverified {
					fmt.Fprintln(os.Stderr, "warning: mcp publish: upstream bearer enforcement NOT VERIFIED by missing/invalid-token probes")
				}
				if devOnly {
					fmt.Fprintln(os.Stderr, "warning: mcp publish: OAuth discovery unreachable; activating WITHOUT verified discovery (dev only)")
				}
				status := "NOT VERIFIED"
				if devOnly {
					status += " OAuth discovery"
				}
				if upstreamAuthUnverified {
					status += " upstream authorization"
				}
				fmt.Printf("\n⚠ MCP route active — %s (do NOT register this URL with ChatGPT; auth: %s):\n%s\n", status, rr.Auth, routeURL)
			} else {
				fmt.Println("✓ OAuth discovery verified (resource matches published URL)")
				fmt.Printf("\n✓ MCP route ready (auth: %s)\n", rr.Auth)
				fmt.Println(routeURL)
			}
		}
	}

	// 4. Steady state, then ordered cleanup with recorded outcomes.
	// The publication is RETAINED on shutdown (P1-A): the stable
	// route stays bound to the closed lease and denies with 503
	// until an authorized republish rebinds it, so ordinary
	// restarts keep the same public URL. Only the lease close is
	// attempted here; permanent removal is explicit via
	// `ocliv mcp unpublish`. The exit code reflects unconfirmed
	// remote cleanup (P1-8).
	var recovery *publicationRecovery
	var onReattach func(agent.Attached)
	if routeID != "" {
		recovery = &publicationRecovery{
			relayURL: relayURL, k: k, keyID: keyID, cfg: cfg,
			routeID: routeID, routeURL: routeURL, boundLease: routeLeaseID,
		}
		onReattach = func(ra agent.Attached) {
			recovery.onReattach(ra)
			if recovery.boundLease == ra.LeaseID {
				routeLeaseID = ra.LeaseID
			}
		}
	}
	a, scode := runSteadyState(ctx, ready, live, a, onReattach)
	res := CleanupResult{RouteDeleteStatus: -1}
	if !serve && routeID != "" {
		fmt.Printf("publication retained (offline until republished): %s\n", routeURL)
		fmt.Printf("permanent removal: ocliv mcp unpublish --lease %s\n", routeLeaseID)
	}
	leaseID := a.LeaseID
	if leaseID == "" {
		// No guessed close from the store's latest record (P1-1): that
		// could revoke another tunnel's lease. Mark the lease
		// unconfirmed so the exit is nonzero via res.ExitCode.
		fmt.Fprintln(os.Stderr, "warning: no live attachment lease ID; remote lease state unconfirmed (no close attempted)")
		res.LeaseCloseStatus = 0
		res.LeaseDetail = "no live attachment lease ID"
	} else {
		lr := closeLeaseWith(defaultLeaseCloser, ready, leaseID)
		res.LeaseID = lr.LeaseID
		res.LeaseCloseStatus = lr.LeaseCloseStatus
		res.LeaseDetail = lr.LeaseDetail
	}
	if msg := res.Report(); msg != "" {
		fmt.Fprint(os.Stderr, msg)
	}
	return res.ExitCode(scode)
}

// selectDoctorLeaseID resolves explicit --lease, named selection, and
// latest-lease fallback, in that order. A named lookup goes through the
// store first so a valid non-latest lease is accepted; the latest
// recorded lease is only a fallback when --name is empty. Mismatch fails
// closed so a diagnosis can never silently report on the wrong tunnel.
// Returns the lease ID, the exact stderr message, and the exit code.
func selectDoctorLeaseID(dir, name, explicitLease string) (string, string, int) {
	leaseID := explicitLease
	// --name selects by lease label and fails closed on mismatch.
	if name != "" {
		store, serr := config.OpenLeaseStore(dir)
		if serr != nil {
			return "", "no recorded lease; start a tunnel first\n", apperr.ExitCLIValidation
		}
		rec, err := store.FindByName(name)
		if err != nil {
			var amb *config.AmbiguousNameError
			if errors.As(err, &amb) {
				return "", fmt.Sprintf("ambiguous lease name %q: matches %s; use --lease ID\n",
					name, strings.Join(amb.Candidates, ", ")), apperr.ExitCLIValidation
			}
			return "", fmt.Sprintf("no recorded lease named %q\n", name), apperr.ExitCLIValidation
		}
		if explicitLease != "" && rec.LeaseID != explicitLease {
			// Explicit --lease wins; --name only cross-checks it.
			return "", fmt.Sprintf("no recorded lease named %q\n", name), apperr.ExitCLIValidation
		}
		leaseID = rec.LeaseID
	}
	if leaseID == "" {
		leaseID = lastLeaseID(dir)
	}
	if leaseID == "" {
		return "", "no recorded lease; start a tunnel first\n", apperr.ExitCLIValidation
	}
	return leaseID, "", 0
}

// doctorLoopbackTarget resolves the exact local probe target for a
// lease: the loopback family recorded at tunnel startup. An unknown
// record keeps the historical IPv4 default rather than probing both
// families and risking a same-port misdiagnosis (P1).
func doctorLoopbackTarget(dir, leaseID string, port int) string {
	if store, serr := config.OpenLeaseStore(dir); serr == nil {
		if rec, ok := store.Load(leaseID); ok && rec.IPv6 {
			return config.LoopbackTarget(port, true)
		}
	}
	return config.LoopbackTarget(port, false)
}

// doctorPublicationTier maps a publication to its operator-facing
// lifecycle tier (P1-D). The relay owns the revoked/active
// distinction; the doctor combines it with the authoritative lease
// status, live attachment, and the local probe. Tiers:
// active (serving), degraded (attached but local MCP unreachable),
// offline (retained, no live serving path), expired, revoked.
// Anything unparseable degrades to offline, never to active.
func doctorPublicationTier(pubState, leaseStatus string, routeLive, localOK bool) string {
	if pubState == "revoked" {
		return "revoked"
	}
	switch leaseStatus {
	case "EXPIRED":
		return "expired"
	case "ACTIVE":
		if !routeLive {
			return "offline"
		}
		if !localOK {
			return "degraded"
		}
		return "active"
	default:
		return "offline"
	}
}

// cmdMCPDoctor reports enrollment, lease, route, local-service, and MCP
// protocol status from the authoritative sources. It prints no secrets:
// the status and route-listing endpoints carry none.
func cmdMCPDoctor(argv []string) int {
	leaseID := ""
	name := ""
	usage := "usage: ocliv mcp doctor [--lease ID] [--name LABEL]"
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--lease" || strings.HasPrefix(a, "--lease=") {
			v, ok := mcpFlagValue(argv, &i, "lease")
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			leaseID = v
		} else if a == "--name" || strings.HasPrefix(a, "--name=") {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			name = v
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q (%s)\n", a, usage)
			return apperr.ExitCLIValidation
		}
	}
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	relayURL := agentRelayURL()
	dir, _, _, _ := agentFiles()
	leaseID, msg, code := selectDoctorLeaseID(dir, name, leaseID)
	if code != 0 {
		fmt.Fprint(os.Stderr, msg)
		return code
	}
	fmt.Println("enrollment: ok")

	scode, sbody, callErr := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/lease/"+leaseID+"/status")
	if callErr != nil {
		fmt.Printf("relay lease status: unreachable (%v)\n", callErr)
		fmt.Println("route status: unknown (relay unreachable)")
		fmt.Println("local service: unknown (no lease port)")
		fmt.Println("mcp protocol: unknown (no lease port)")
		return apperr.ExitRelayTLS
	}
	if scode != http.StatusOK {
		fmt.Printf("relay lease status: unreachable (relay status %d)\n", scode)
		fmt.Println("route status: unknown (relay unreachable)")
		fmt.Println("local service: unknown (no lease port)")
		fmt.Println("mcp protocol: unknown (no lease port)")
		return apperr.ExitRelayTLS
	}
	var st struct {
		Hostname          string `json:"hostname"`
		Port              int    `json:"port"`
		AccessMode        string `json:"access_mode"`
		Status            string `json:"status"`
		Generation        int64  `json:"generation"`
		RouteLive         bool   `json:"route_live"`
		RouteAvailable    bool   `json:"route_available"`
		LeaseExpiresAt    string `json:"lease_expires_at"`
		LastRenewalAt     string `json:"last_renewal_at"`
		LastRenewalResult string `json:"last_renewal_result"`
	}
	if jerr := json.Unmarshal(sbody, &st); jerr != nil {
		fmt.Fprintln(os.Stderr, "relay status reply unparseable")
		return apperr.ExitInternal
	}
	fmt.Printf("lease: %s status=%s mode=%s generation=%d\n", leaseID, st.Status, st.AccessMode, st.Generation)
	fmt.Printf("route live: %v\n", st.RouteLive)
	if st.LeaseExpiresAt == "" {
		fmt.Println("lease expires at: never")
	} else {
		fmt.Printf("lease expires at: %s\n", st.LeaseExpiresAt)
	}
	if st.LastRenewalAt == "" {
		fmt.Println("last renewal: none recorded")
	} else {
		fmt.Printf("last renewal: %s\n", st.LastRenewalAt)
	}
	if st.LastRenewalResult == "" {
		fmt.Println("last renewal result: none recorded")
	} else {
		fmt.Printf("last renewal result: %s\n", st.LastRenewalResult)
	}
	fmt.Printf("current route availability: %v\n", st.RouteAvailable)

	rcode, rbody, callErr := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/lease/"+leaseID+"/mcp-route")
	if callErr != nil {
		fmt.Printf("route status: unreachable (%v)\n", callErr)
		return apperr.ExitRelayTLS
	}
	var rl struct {
		Routes []struct {
			RouteID string `json:"route_id"`
			Auth    string `json:"auth"`
			URL     string `json:"url"`
			State   string `json:"state"`
		} `json:"routes"`
	}
	routesOK := false
	if rcode != http.StatusOK {
		fmt.Printf("routes: unknown (relay status %d)\n", rcode)
	} else {
		if jerr := json.Unmarshal(rbody, &rl); jerr != nil {
			fmt.Fprintln(os.Stderr, "route list reply unparseable")
			return apperr.ExitInternal
		}
		routesOK = true
	}

	localOK := false
	localUnreachable := false
	target := ""
	if st.Port <= 0 {
		fmt.Println("local service: unknown (no lease port)")
		fmt.Println("mcp protocol: unknown (no lease port)")
	} else {
		target = doctorLoopbackTarget(dir, leaseID, st.Port)
		if perr := agent.ProbeLocal(target, 3*time.Second); perr != nil {
			localUnreachable = true
			fmt.Printf("local service: unreachable (%s)\n", target)
			fmt.Println("mcp protocol: unknown (local unreachable)")
		} else {
			localOK = true
			fmt.Printf("local service: responsive (%s)\n", target)
		}
	}
	// Per-publication lifecycle tiers (P1-D): the relay owns the
	// revoked/active distinction; the doctor combines it with lease
	// status, live attachment, and the local probe above. Public
	// readiness is never inferred — see EXTERNAL_UNVERIFIED below.
	if !routesOK {
		// Already reported as unknown.
	} else if len(rl.Routes) == 0 {
		fmt.Println("routes: none")
	} else {
		for _, r := range rl.Routes {
			url := r.URL
			if url == "" {
				url = "(no external host configured)"
			}
			fmt.Printf("route: %s auth=%s publication=%s\n  %s\n",
				r.RouteID, r.Auth, doctorPublicationTier(r.State, st.Status, st.RouteLive, localOK), url)
		}
	}
	if localUnreachable {
		return apperr.ExitLocalTarget
	}
	if !localOK {
		return doctorProtocolExit(st.AccessMode, false)
	}
	out := runMCPProbe(target, st.AccessMode)
	fmt.Printf("mcp protocol: %s\n", out.Summary)
	fmt.Printf("mcp auth: %s\n", doctorAuthLine(st.AccessMode, out.Auth))
	publicOK := true
	if routesOK {
		for _, route := range rl.Routes {
			if route.State != "active" {
				continue
			}
			if st.Status != "ACTIVE" || !st.RouteLive {
				fmt.Printf("public MCP route %s: offline (relay lease/session is not active)\n", route.RouteID)
				publicOK = false
				continue
			}
			if route.URL == "" {
				fmt.Printf("public MCP route %s: unknown (relay did not report a canonical URL)\n", route.RouteID)
				publicOK = false
				continue
			}
			discoveryURL, derr := mcpRouteDiscoveryURL(route.URL, route.RouteID)
			if derr == nil {
				var publicClient *http.Client
				publicClient, derr = mgmtHTTPClient(8 * time.Second)
				if derr == nil {
					derr = validateMCPResourceMetadata(publicClient, discoveryURL, route.URL)
				}
			}
			if derr != nil {
				fmt.Printf("public MCP route %s: not verified from this network (%v); if local Caddy works, check hairpin NAT and verify from off-LAN\n", route.RouteID, derr)
				publicOK = false
			} else {
				fmt.Printf("public MCP route %s: verified_at present; lease ACTIVE/live; protected-resource metadata matches %s\n", route.RouteID, route.URL)
			}
		}
	}
	fmt.Println("chatgpt registration: EXTERNAL_UNVERIFIED (register the exact public URL in ChatGPT after external qualification)")
	if !publicOK {
		return apperr.ExitRelayTLS
	}
	return doctorProtocolExit(st.AccessMode, out.Verified)
}
