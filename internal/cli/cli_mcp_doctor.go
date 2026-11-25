package cli

// MCP doctor probes (P1-2). Transport, protocol, and authentication are
// separate stages with separate verdicts: a reachable TCP port is not a
// working MCP server (TRANSPORT_OK), a tools/list answer is not proof of
// a session (MCP_OK only after initialize + notification + validated
// envelopes), and a locally answering server is not proof of upstream
// OAuth enforcement (AUTH_UNVERIFIED) or ChatGPT registration
// (EXTERNAL_UNVERIFIED, always, until an external client qualifies it).

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
)

// MCPAuthEvidence separates configured authentication mode from observed
// enforcement across local and public surfaces (OCL-001).
type MCPAuthEvidence struct {
	Mode                   string `json:"mode"`
	LocalAccess            string `json:"local_access"`
	PublicMetadata         string `json:"public_metadata,omitempty"`
	PublicEnforcement      string `json:"public_enforcement"`
	AuthenticatedPublicMCP string `json:"authenticated_public_mcp"`
}

// MCPProbeConfig specifies a canonical MCP endpoint and transport options
// for probing either a local loopback server or a public HTTPS publication
// without rewriting scheme, host, port, or resource path (OCL-003).
type MCPProbeConfig struct {
	Endpoint    *url.URL
	AuthMode    string
	BearerToken string
	Client      *http.Client
	IsPublic    bool
}

// mcpProbeOutcome is the staged doctor verdict. Verified means a usable
// MCP connection was proven; every other facet is reported independently
// so success in one stage can never masquerade as success in another.
type mcpProbeOutcome struct {
	Summary            string          // one-line human verdict (back-compat with probeMCPProtocol)
	Verified           bool            // usable MCP connection proven
	Auth               string          // AUTH_NONE | AUTH_REQUIRED | AUTH_UNVERIFIED | RELAY_MANAGED_OAUTH | NOT_APPLICABLE
	AuthEvidence       MCPAuthEvidence // structured auth mode vs observed enforcement (OCL-001)
	AuthEnforced       bool            // upstream rejected both missing and invalid bearer credentials
	UnboundHandoff     bool            // exact resource-file server signal before URL handoff
	Protocol           string          // negotiated protocolVersion, "" when none proven
	ServerCapabilities map[string]any  // raw server capabilities when reported
}

// probeMCPProtocol verifies a usable MCP session against the local
// server, preserving the historical (summary, verified) contract. Use
// runMCPProbe for the full staged verdict.
func probeMCPProtocol(target, mode string) (string, bool) {
	out := runMCPProbe(target, mode)
	return out.Summary, out.Verified
}

// classifyMCPAuth classifies authentication mode separately from observed
// enforcement for both modern (2026-07-28) and legacy (2024-11-05) MCP probe
// paths (OCL-001).
func classifyMCPAuth(mode string, bearerProvided, isPublic bool) (auth, note string, ev MCPAuthEvidence) {
	switch mode {
	case "mcp_anonymous_fixture":
		ev = MCPAuthEvidence{
			Mode:                   "ANONYMOUS_FIXTURE",
			LocalAccess:            "VERIFIED",
			PublicEnforcement:      "NOT_APPLICABLE",
			AuthenticatedPublicMCP: "NOT_APPLICABLE",
		}
		if isPublic {
			ev.LocalAccess = "NOT_TESTED"
		}
		return "AUTH_NONE", "", ev
	case "mcp_managed_oauth":
		ev = MCPAuthEvidence{
			Mode:                   "RELAY_MANAGED_OAUTH",
			LocalAccess:            "VERIFIED",
			PublicEnforcement:      "NOT_TESTED",
			AuthenticatedPublicMCP: "NOT_TESTED",
		}
		if isPublic {
			ev.LocalAccess = "NOT_TESTED"
			if bearerProvided {
				ev.AuthenticatedPublicMCP = "VERIFIED"
				return "RELAY_MANAGED_OAUTH", "; authenticated public MCP verified with bearer", ev
			}
			return "RELAY_MANAGED_OAUTH", "; visitor OAuth is enforced by the relay-managed route", ev
		}
		return "RELAY_MANAGED_OAUTH", "; visitor OAuth is enforced by the relay-managed route", ev
	default: // mcp_upstream_oauth
		ev = MCPAuthEvidence{
			Mode:                   "UPSTREAM_OAUTH",
			LocalAccess:            "VERIFIED",
			PublicEnforcement:      "UNVERIFIED",
			AuthenticatedPublicMCP: "NOT_TESTED",
		}
		if isPublic {
			ev.LocalAccess = "NOT_TESTED"
		}
		if bearerProvided {
			if isPublic {
				ev.AuthenticatedPublicMCP = "VERIFIED"
			}
			ev.PublicEnforcement = "NOT_TESTED"
			return "AUTH_REQUIRED", "; protocol verified with the operator-supplied upstream bearer", ev
		}
		return "AUTH_UNVERIFIED", "; auth unverified (answered without bearer — upstream OAuth enforcement NOT proven)", ev
	}
}

// modernAuthFacet renders the authentication facet for a verified modern
// endpoint via the unified classifier (OCL-001).
func modernAuthFacet(anon, managed, upstreamBearer bool) (auth, note string) {
	mode := "mcp_upstream_oauth"
	if anon {
		mode = "mcp_anonymous_fixture"
	} else if managed {
		mode = "mcp_managed_oauth"
	}
	auth, note, _ = classifyMCPAuth(mode, upstreamBearer, false)
	return auth, note
}

// localMCPEndpoint builds a canonical endpoint URL from either a full HTTP(S)
// URL (preserving exact scheme, host, port, and resource path) or a local
// host:port target (constructing http://<target>/mcp).
func localMCPEndpoint(target string) (*url.URL, error) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return nil, fmt.Errorf("empty MCP probe target")
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid MCP endpoint URL: %w", err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("MCP endpoint URL missing host")
		}
		if u.User != nil {
			return nil, fmt.Errorf("userinfo in MCP endpoint URL is forbidden")
		}
		if u.Path == "" {
			u.Path = "/mcp"
		}
		return u, nil
	}
	u, err := url.Parse("http://" + raw + "/mcp")
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid local MCP target %q", target)
	}
	return u, nil
}

// redactSecret scrubs bearer tokens or credential fragments from diagnostic text.
func redactSecret(msg, secret string) string {
	if secret == "" || msg == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "[REDACTED]")
}

// unboundHandoffSignal is the exact body a resource-file-bound MCP
// server answers with before the publisher writes the handoff (Metis
// `mcp serve-http` before METIS_MCP_RESOURCE_FILE exists:
// `http.Error(w, "resource not configured", 503)`). Matching the signal
// keeps the acceptance narrow: a 503 from an overloaded, unhealthy or
// otherwise broken upstream is NOT an unbound handoff and must not be
// read as authenticating presence.
const unboundHandoffSignal = "resource not configured"

// presenceVerdict renders the probe outcome for a local endpoint that
// answers an upstream-oauth request with authenticating presence instead
// of a usable MCP session: a bearer challenge (401/403), or a 503 whose
// body carries the unbound-handoff signal from a resource-file-bound
// server whose --resource-file handoff the publisher has not written yet.
// Both prove only that the endpoint is alive and will enforce OAuth once
// bound — never tool functionality; the real contract is proven later by
// strict OAuth discovery (proveRouteReady), which fails closed if the
// binding never materializes. Anonymous fixtures can never satisfy a
// challenge or an unbound handoff, so for them a 401/403 keeps the
// historical broken verdict and a 503 the historical unverified
// fallthrough.
//
// The body is required for the 503 case: a bare 503 is ambiguous, and
// treating every 503 as presence would wave a genuinely broken upstream
// through the publish gate.
func presenceVerdict(status int, body []byte, mode string, isPublic, bearerProvided bool) (mcpProbeOutcome, bool) {
	anon := mode == "mcp_anonymous_fixture"
	managed := mode == "mcp_managed_oauth"
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		if anon {
			return mcpProbeOutcome{
				Summary: "protocol: broken (fixture server demands auth it cannot supply)",
				Auth:    "AUTH_REQUIRED",
				AuthEvidence: MCPAuthEvidence{
					Mode:                   "ANONYMOUS_FIXTURE",
					LocalAccess:            "AUTH_CHALLENGED",
					PublicEnforcement:      "NOT_APPLICABLE",
					AuthenticatedPublicMCP: "NOT_APPLICABLE",
				},
			}, true
		}
		if managed {
			ev := MCPAuthEvidence{
				Mode:                   "RELAY_MANAGED_OAUTH",
				LocalAccess:            "AUTH_CHALLENGED",
				PublicEnforcement:      "NOT_TESTED",
				AuthenticatedPublicMCP: "NOT_TESTED",
			}
			if isPublic {
				ev.LocalAccess = "NOT_TESTED"
				if bearerProvided {
					ev.AuthenticatedPublicMCP = "REJECTED"
					return mcpProbeOutcome{
						Summary:      fmt.Sprintf("auth: rejected (HTTP %d; presented bearer was not accepted by the relay-managed route)", status),
						Auth:         "RELAY_MANAGED_OAUTH",
						AuthEvidence: ev,
					}, true
				}
				ev.PublicEnforcement = "ENFORCED"
				return mcpProbeOutcome{
					Summary:      fmt.Sprintf("auth: enforced (HTTP %d; relay-managed route rejected anonymous request)", status),
					Auth:         "RELAY_MANAGED_OAUTH",
					AuthEvidence: ev,
				}, true
			}
			return mcpProbeOutcome{
				Summary:      fmt.Sprintf("auth: local backend returned HTTP %d behind a relay-managed OAuth route", status),
				Auth:         "AUTH_REQUIRED",
				AuthEvidence: ev,
			}, true
		}
		ev := MCPAuthEvidence{
			Mode:                   "UPSTREAM_OAUTH",
			LocalAccess:            "AUTH_CHALLENGED",
			PublicEnforcement:      "ENFORCED",
			AuthenticatedPublicMCP: "NOT_TESTED",
		}
		if isPublic {
			ev.LocalAccess = "NOT_TESTED"
			if bearerProvided {
				ev.AuthenticatedPublicMCP = "REJECTED"
			}
		}
		return mcpProbeOutcome{
			Summary:      "auth: required (server demands bearer; configure the upstream OAuth client)",
			Auth:         "AUTH_REQUIRED",
			AuthEvidence: ev,
		}, true
	case http.StatusServiceUnavailable:
		if anon {
			return mcpProbeOutcome{}, false
		}
		if !strings.Contains(strings.ToLower(string(body)), unboundHandoffSignal) {
			return mcpProbeOutcome{}, false
		}
		return mcpProbeOutcome{
			Summary:        "auth: required (server reports resource not configured; it binds after publish writes the --resource-file handoff)",
			Auth:           "AUTH_REQUIRED",
			UnboundHandoff: true,
			AuthEvidence: MCPAuthEvidence{
				Mode:                   "UPSTREAM_OAUTH",
				LocalAccess:            "UNBOUND_HANDOFF",
				PublicEnforcement:      "NOT_TESTED",
				AuthenticatedPublicMCP: "NOT_TESTED",
			},
		}, true
	}
	return mcpProbeOutcome{}, false
}

// runMCPProbe executes the transport → protocol → authentication stages.
func runMCPProbe(target, mode string) mcpProbeOutcome {
	return runMCPProbeWithBearer(target, mode, "")
}

// runMCPProbeWithBearer verifies MCP protocol behavior using an optional
// operator-supplied upstream bearer. The token is used only in the request
// header and is never included in probe output.
func runMCPProbeWithBearer(target, mode, bearer string) mcpProbeOutcome {
	return runMCPProbeWithClient(target, mode, bearer, &http.Client{Timeout: 5 * time.Second})
}

func runMCPProbeWithClient(target, mode, bearer string, client *http.Client) mcpProbeOutcome {
	ep, err := localMCPEndpoint(target)
	if err != nil {
		return mcpProbeOutcome{Summary: "invalid MCP target (" + err.Error() + ")", Auth: "AUTH_UNVERIFIED"}
	}
	isPublic := strings.EqualFold(ep.Scheme, "https")
	return runMCPProbeWithConfig(MCPProbeConfig{
		Endpoint:    ep,
		AuthMode:    mode,
		BearerToken: bearer,
		Client:      client,
		IsPublic:    isPublic,
	})
}

// runMCPProbeWithConfig executes the staged MCP probe against a canonical
// endpoint URL, preserving scheme, host, port, and exact resource path (OCL-003).
func runMCPProbeWithConfig(cfg MCPProbeConfig) mcpProbeOutcome {
	mode := cfg.AuthMode
	if mode != "mcp_upstream_oauth" && mode != "mcp_anonymous_fixture" && mode != "mcp_managed_oauth" {
		return mcpProbeOutcome{
			Summary:  "not-applicable (not an MCP lease)",
			Verified: true,
			Auth:     "NOT_APPLICABLE",
			AuthEvidence: MCPAuthEvidence{
				Mode:                   "NOT_APPLICABLE",
				LocalAccess:            "NOT_APPLICABLE",
				PublicEnforcement:      "NOT_APPLICABLE",
				AuthenticatedPublicMCP: "NOT_APPLICABLE",
			},
		}
	}
	if cfg.Endpoint == nil || cfg.Endpoint.Host == "" {
		return mcpProbeOutcome{Summary: "invalid MCP endpoint (missing URL)", Auth: "AUTH_UNVERIFIED"}
	}
	if cfg.Endpoint.User != nil {
		return mcpProbeOutcome{Summary: "invalid MCP endpoint (userinfo forbidden)", Auth: "AUTH_UNVERIFIED"}
	}
	endpointURL := cfg.Endpoint.String()
	bearer := cfg.BearerToken
	isPublic := cfg.IsPublic || strings.EqualFold(cfg.Endpoint.Scheme, "https")
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	var sessionID string
	var sessionVersion string
	post := func(body, version string) (*http.Response, []byte, error) {
		req, err := http.NewRequest(http.MethodPost, endpointURL, strings.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("User-Agent", "ocliv-probe/"+BinaryVersion)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if version != "" {
			req.Header.Set("MCP-Protocol-Version", version)
			var envelope struct {
				Method string `json:"method"`
			}
			if json.Unmarshal([]byte(body), &envelope) == nil && envelope.Method != "" {
				req.Header.Set("MCP-Method", envelope.Method)
			}
		}
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		if got := resp.Header.Get("Mcp-Session-Id"); got != "" {
			sessionID = got
		}
		if got := resp.Header.Get("Mcp-Protocol-Version"); got != "" {
			sessionVersion = got
		} else if version != "" {
			sessionVersion = version
		}
		defer resp.Body.Close()
		raw, err := readMCPProbeBody(resp, requestID(body))
		if err != nil {
			return nil, nil, err
		}
		return resp, raw, nil
	}
	defer func() {
		if sessionID == "" {
			return
		}
		req, err := http.NewRequest(http.MethodDelete, endpointURL, nil)
		if err != nil {
			return
		}
		req.Header.Set("Mcp-Session-Id", sessionID)
		req.Header.Set("User-Agent", "ocliv-probe/"+BinaryVersion)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if sessionVersion != "" {
			req.Header.Set("Mcp-Protocol-Version", sessionVersion)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	unreachable := func(step string, err error) mcpProbeOutcome {
		return mcpProbeOutcome{Summary: step + " unreachable (" + redactSecret(err.Error(), bearer) + ")", Auth: "AUTH_UNVERIFIED"}
	}

	// Stage 0 — modern path (MCP 2026-07-28, stateless): try tools/list
	// directly with a versioned request. A valid id-echoed reply proves
	// a working modern endpoint with no handshake. Anything else falls
	// through to the legacy handshake below — including a legacy server
	// that answers tools/list without initialize (its reply carries the
	// wrong id, so it cannot verify here; see
	// TestProbeMCPProtocolRequiresInitialize).
	const modernVersion = "2026-07-28"
	mresp, mraw, merr := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`, modernVersion)
	if merr == nil {
		if v, ok := presenceVerdict(mresp.StatusCode, mraw, mode, isPublic, bearer != ""); ok {
			return v
		}
		if list, err := decodeJSONRPC(mresp, mraw); err == nil {
			if _, err := validateEnvelope(list, 1); err == nil {
				res, _ := list["result"].(map[string]any)
				if tools, ok := res["tools"].([]any); ok {
					auth, authNote, ev := classifyMCPAuth(mode, bearer != "", isPublic)
					return mcpProbeOutcome{
						Summary:      "ok (protocol " + modernVersion + " stateless, tools/list answered; " + strconv.Itoa(len(tools)) + " tools)" + authNote,
						Verified:     true,
						Auth:         auth,
						AuthEvidence: ev,
						Protocol:     modernVersion,
					}
				}
			}
		}
	}

	// Stage 1 — legacy transport: the initialize round-trip. Only a
	// delivery failure (connection refused, timeout) is a transport
	// verdict; any HTTP status proves delivery and moves to protocol
	// semantics.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize",` +
		`"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ocliv-doctor","version":"1"}}}`
	resp, raw, err := post(initBody, "")
	if err != nil {
		if _, ok := err.(*url.Error); ok {
			return unreachable("initialize", err)
		}
		return unreachable("initialize", err)
	}
	if v, ok := presenceVerdict(resp.StatusCode, raw, mode, isPublic, bearer != ""); ok {
		return v
	}
	init, err := decodeJSONRPC(resp, raw)
	if err != nil {
		return mcpProbeOutcome{Summary: "initialize invalid (" + redactSecret(err.Error(), bearer) + ")", Auth: "AUTH_UNVERIFIED"}
	}
	version, err := validateEnvelope(init, 1)
	if err != nil {
		return mcpProbeOutcome{Summary: "initialize invalid (" + redactSecret(err.Error(), bearer) + ")", Auth: "AUTH_UNVERIFIED"}
	}
	if version == "" {
		return mcpProbeOutcome{Summary: "initialize invalid (missing protocolVersion — client cannot bind a transport revision)", Auth: "AUTH_UNVERIFIED"}
	}
	var serverCaps map[string]any
	if initRes, ok := init["result"].(map[string]any); ok {
		if caps, ok := initRes["capabilities"].(map[string]any); ok {
			serverCaps = caps
		}
	}

	// Stage 2 — protocol: the initialized notification (no JSON-RPC
	// reply by definition) and tool discovery, with strict envelope
	// validation: version match, id echo, result/error exclusivity.
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	nresp, _, err := post(notifBody, version)
	if err != nil {
		return unreachable("notifications/initialized", err)
	}
	if nresp.StatusCode < 200 || nresp.StatusCode > 299 {
		return mcpProbeOutcome{Summary: "protocol: broken (initialized notification rejected: http " +
			strconv.Itoa(nresp.StatusCode) + ")", Auth: "AUTH_UNVERIFIED"}
	}
	lresp, lraw, err := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, version)
	if err != nil {
		return unreachable("tools/list", err)
	}
	if v, ok := presenceVerdict(lresp.StatusCode, lraw, mode, isPublic, bearer != ""); ok {
		return v
	}
	list, err := decodeJSONRPC(lresp, lraw)
	if err != nil {
		return mcpProbeOutcome{Summary: "tools/list invalid (" + redactSecret(err.Error(), bearer) + ")", Auth: "AUTH_UNVERIFIED"}
	}
	if _, err := validateEnvelope(list, 2); err != nil {
		return mcpProbeOutcome{Summary: "tools/list invalid (" + redactSecret(err.Error(), bearer) + ")", Auth: "AUTH_UNVERIFIED"}
	}
	res, _ := list["result"].(map[string]any)
	tools, ok := res["tools"].([]any)
	if !ok {
		return mcpProbeOutcome{Summary: "tools/list invalid (no tools array)", Auth: "AUTH_UNVERIFIED"}
	}

	auth, authNote, ev := classifyMCPAuth(mode, bearer != "", isPublic)
	return mcpProbeOutcome{
		Summary:            "ok (protocol " + version + ", tools/list answered; " + strconv.Itoa(len(tools)) + " tools)" + authNote,
		Verified:           true,
		Auth:               auth,
		AuthEvidence:       ev,
		Protocol:           version,
		ServerCapabilities: serverCaps,
	}
}

// verifyUpstreamAuthEnforcement performs two independent MCP probes and
// succeeds only when the upstream rejects both absent and invalid bearer
// credentials. A tools/list response without credentials is explicitly
// unverified, even when OAuth metadata is otherwise correct.
func verifyUpstreamAuthEnforcement(target string) bool {
	var invalidBytes [32]byte
	if _, err := rand.Read(invalidBytes[:]); err != nil {
		return false
	}
	missing := runMCPProbeWithBearer(target, "mcp_upstream_oauth", "")
	invalidToken := "ocliv-invalid-" + hex.EncodeToString(invalidBytes[:])
	invalid := runMCPProbeWithBearer(target, "mcp_upstream_oauth", invalidToken)
	return !missing.Verified && missing.Auth == "AUTH_REQUIRED" &&
		!invalid.Verified && invalid.Auth == "AUTH_REQUIRED"
}

const maxProbeBody = 1 << 20

func requestID(body string) string {
	var req struct {
		ID any `json:"id"`
	}
	if json.Unmarshal([]byte(body), &req) != nil || req.ID == nil {
		return ""
	}
	return fmt.Sprint(req.ID)
}

// readMCPProbeBody returns as soon as a complete SSE event carrying the
// expected JSON-RPC ID arrives. It ignores keepalive comments and unrelated
// notifications, while bounding all bytes read under the HTTP client's
// request deadline. Ordinary JSON responses retain the bounded body path.
func readMCPProbeBody(resp *http.Response, expectedID string) ([]byte, error) {
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") || expectedID == "" {
		return io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), maxProbeBody)
	var total int
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		total += len(line) + 1
		if total > maxProbeBody {
			return nil, fmt.Errorf("SSE response exceeds %d-byte limit", maxProbeBody)
		}
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			if len(data) > 0 {
				event := []byte(strings.Join(data, "\n"))
				var envelope map[string]any
				if json.Unmarshal(event, &envelope) == nil && fmt.Sprint(envelope["id"]) == expectedID {
					return event, nil
				}
				data = data[:0]
			}
		} else if !strings.HasPrefix(line, ":") {
			if value, ok := strings.CutPrefix(line, "data:"); ok {
				data = append(data, strings.TrimPrefix(value, " "))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading SSE response: %w", err)
	}
	return nil, fmt.Errorf("SSE stream ended before JSON-RPC id %s", expectedID)
}

// decodeJSONRPC decodes a plain JSON-RPC body or an SSE stream carrying
// one (first data: line with a JSON object). Anything else is a protocol
// problem, not a transport problem.
func decodeJSONRPC(resp *http.Response, raw []byte) (map[string]any, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, &mcpStatusError{code: resp.StatusCode}
	}
	body := raw
	trimmed := strings.TrimSpace(string(raw))
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") && !strings.HasPrefix(trimmed, "{") {
		body = nil
		for _, line := range strings.Split(string(raw), "\n") {
			if d, ok := strings.CutPrefix(strings.TrimSpace(line), "data:"); ok {
				if t := strings.TrimSpace(d); strings.HasPrefix(t, "{") {
					body = []byte(t)
					break
				}
			}
		}
		if body == nil {
			return nil, &mcpStatusError{message: "SSE response carries no JSON-RPC data"}
		}
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &mcpStatusError{message: "no JSON-RPC reply: " + err.Error()}
	}
	return out, nil
}

// validateEnvelope enforces the protocol contract: version marker, id
// echo, and exactly one of result/error. It returns the negotiated
// protocol version for initialize replies ("" for other methods).
func validateEnvelope(out map[string]any, wantID int) (string, error) {
	if out["jsonrpc"] != "2.0" {
		return "", fmt.Errorf("not a JSON-RPC 2.0 envelope")
	}
	if fmt.Sprint(out["id"]) != strconv.Itoa(wantID) {
		return "", fmt.Errorf("reply id %v does not echo request id %d", out["id"], wantID)
	}
	res, hasRes := out["result"].(map[string]any)
	_, hasErr := out["error"]
	if hasRes == hasErr {
		return "", fmt.Errorf("reply must carry exactly one of result/error")
	}
	if !hasRes {
		return "", fmt.Errorf("server error: %v", out["error"])
	}
	if v, _ := res["protocolVersion"].(string); v != "" {
		return v, nil
	}
	return "", nil
}

// mcpStatusError marks an HTTP-level or body-level probe failure as a
// protocol problem, not a transport problem: the server answered, but
// not with a usable MCP reply.
type mcpStatusError struct {
	code    int
	message string
}

func (e *mcpStatusError) Error() string {
	if e.message != "" {
		return e.message
	}
	return "http " + strconv.Itoa(e.code)
}

// doctorAuthLine renders the authentication facet for the doctor report.
// Configured auth mode is kept separate from observed enforcement (OCL-001):
// managed OAuth must never instruct operators to configure an upstream bearer
// merely because visitor OAuth is enabled at the relay.
func doctorAuthLine(mode, auth string) string {
	switch auth {
	case "RELAY_MANAGED_OAUTH":
		return "RELAY_MANAGED_OAUTH (visitor OAuth enforced by relay-managed route; local backend requires no upstream bearer)"
	case "AUTH_NONE":
		return "AUTH_NONE (anonymous fixture profile)"
	case "AUTH_REQUIRED":
		if mode == "mcp_managed_oauth" {
			return "AUTH_REQUIRED (local backend demanded a bearer behind a relay-managed OAuth route)"
		}
		return "AUTH_REQUIRED (server demands bearer; configure the upstream OAuth client)"
	case "AUTH_UNVERIFIED":
		if mode == "mcp_upstream_oauth" {
			return "AUTH_UNVERIFIED (answered without bearer — upstream OAuth enforcement NOT proven)"
		}
		return "AUTH_UNVERIFIED"
	default:
		return auth
	}
}

// formatMCPAuthEvidence renders the separated authentication evidence lines
// for `ocliv mcp doctor` (OCL-001).
func formatMCPAuthEvidence(ev MCPAuthEvidence) string {
	mode := ev.Mode
	if mode == "" {
		mode = "UNKNOWN"
	}
	localAccess := ev.LocalAccess
	if localAccess == "" {
		localAccess = "NOT_TESTED"
	}
	pubMeta := ev.PublicMetadata
	if pubMeta == "" {
		pubMeta = "NOT_TESTED"
	}
	pubEnf := ev.PublicEnforcement
	if pubEnf == "" {
		pubEnf = "NOT_TESTED"
	}
	authPub := ev.AuthenticatedPublicMCP
	if authPub == "" {
		authPub = "NOT_TESTED"
	}
	return fmt.Sprintf(
		"Authentication mode: %s\nLocal MCP access: %s\nPublic OAuth metadata: %s\nAnonymous access rejection: %s\nAuthenticated public MCP: %s\n",
		mode, localAccess, pubMeta, pubEnf, authPub,
	)
}

// doctorProtocolExit maps the protocol probe to the process exit. A green
// exit must mean a verified usable local connection (or a non-MCP lease
// where the probe does not apply). Unknown, unreachable, or invalid
// protocol health fails the oracle instead of passing it.
func doctorProtocolExit(mode string, verified bool) int {
	if mode != "mcp_upstream_oauth" && mode != "mcp_anonymous_fixture" && mode != "mcp_managed_oauth" {
		return apperr.ExitOK
	}
	if verified {
		return apperr.ExitOK
	}
	return apperr.ExitProtocol
}
