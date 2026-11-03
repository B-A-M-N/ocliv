package cli

// MCP doctor probes (P1-2). Transport, protocol, and authentication are
// separate stages with separate verdicts: a reachable TCP port is not a
// working MCP server (TRANSPORT_OK), a tools/list answer is not proof of
// a session (MCP_OK only after initialize + notification + validated
// envelopes), and a locally answering server is not proof of upstream
// OAuth enforcement (AUTH_UNVERIFIED) or ChatGPT registration
// (EXTERNAL_UNVERIFIED, always, until an external client qualifies it).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ocliv/internal/apperr"
)

// mcpProbeOutcome is the staged doctor verdict. Verified means a usable
// local MCP connection was proven; every other facet is reported
// independently so success in one stage can never masquerade as success
// in another.
type mcpProbeOutcome struct {
	Summary  string // one-line human verdict (back-compat with probeMCPProtocol)
	Verified bool   // usable local connection proven
	Auth     string // AUTH_NONE | AUTH_REQUIRED | AUTH_UNVERIFIED | NOT_APPLICABLE
	Protocol string // negotiated protocolVersion, "" when none proven
}

// probeMCPProtocol verifies a usable MCP session against the local
// server, preserving the historical (summary, verified) contract. Use
// runMCPProbe for the full staged verdict.
func probeMCPProtocol(target, mode string) (string, bool) {
	out := runMCPProbe(target, mode)
	return out.Summary, out.Verified
}

// modernAuthFacet renders the authentication facet for a verified modern
// endpoint. The probe holds no bearer, so usability is proven but upstream
// enforcement never is — except for the anonymous fixture, which is
// anonymous by profile.
func modernAuthFacet(anon bool) (auth, note string) {
	if anon {
		return "AUTH_NONE", ""
	}
	return "AUTH_UNVERIFIED", "; auth unverified (answered without bearer — upstream OAuth enforcement NOT proven)"
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
func presenceVerdict(status int, body []byte, anon bool) (mcpProbeOutcome, bool) {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		if anon {
			return mcpProbeOutcome{Summary: "protocol: broken (fixture server demands auth it cannot supply)", Auth: "AUTH_REQUIRED"}, true
		}
		return mcpProbeOutcome{Summary: "auth: required (server demands bearer; configure the upstream OAuth client)", Auth: "AUTH_REQUIRED"}, true
	case http.StatusServiceUnavailable:
		if anon {
			return mcpProbeOutcome{}, false
		}
		if !strings.Contains(strings.ToLower(string(body)), unboundHandoffSignal) {
			return mcpProbeOutcome{}, false
		}
		return mcpProbeOutcome{Summary: "auth: required (server reports resource not configured; it binds after publish writes the --resource-file handoff)", Auth: "AUTH_REQUIRED"}, true
	}
	return mcpProbeOutcome{}, false
}

// runMCPProbe executes the transport → protocol → authentication stages.
func runMCPProbe(target, mode string) mcpProbeOutcome {
	if mode != "mcp_upstream_oauth" && mode != "mcp_anonymous_fixture" {
		return mcpProbeOutcome{Summary: "not-applicable (not an MCP lease)", Verified: true, Auth: "NOT_APPLICABLE"}
	}
	anon := mode == "mcp_anonymous_fixture"
	client := &http.Client{Timeout: 5 * time.Second}
	post := func(body, version string) (*http.Response, []byte, error) {
		req, err := http.NewRequest(http.MethodPost, "http://"+target+"/mcp", strings.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if version != "" {
			req.Header.Set("MCP-Protocol-Version", version)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, nil, err
		}
		return resp, raw, nil
	}
	unreachable := func(step string, err error) mcpProbeOutcome {
		return mcpProbeOutcome{Summary: step + " unreachable (" + err.Error() + ")", Auth: "AUTH_UNVERIFIED"}
	}

	// Stage 0 — modern path (MCP 2026-07-28, stateless): try tools/list
	// directly with a versioned request. A valid id-echoed reply proves
	// a working modern endpoint with no handshake. Anything else falls
	// through to the legacy handshake below — including a legacy server
	// that answers tools/list without initialize (its reply carries the
	// wrong id, so it cannot verify here; see
	// TestProbeMCPProtocolRequiresInitialize).
	const modernVersion = "2026-07-28"
	mresp, mraw, merr := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, modernVersion)
	if merr == nil {
		if v, ok := presenceVerdict(mresp.StatusCode, mraw, anon); ok {
			return v
		}
		if list, err := decodeJSONRPC(mresp, mraw); err == nil {
			if _, err := validateEnvelope(list, 1); err == nil {
				res, _ := list["result"].(map[string]any)
				if tools, ok := res["tools"].([]any); ok {
					auth, authNote := modernAuthFacet(anon)
					return mcpProbeOutcome{
						Summary:  "ok (protocol " + modernVersion + " stateless, tools/list answered; " + strconv.Itoa(len(tools)) + " tools)" + authNote,
						Verified: true,
						Auth:     auth,
						Protocol: modernVersion,
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
	if v, ok := presenceVerdict(resp.StatusCode, raw, anon); ok {
		return v
	}
	init, err := decodeJSONRPC(resp, raw)
	if err != nil {
		return mcpProbeOutcome{Summary: "initialize invalid (" + err.Error() + ")", Auth: "AUTH_UNVERIFIED"}
	}
	version, err := validateEnvelope(init, 1)
	if err != nil {
		return mcpProbeOutcome{Summary: "initialize invalid (" + err.Error() + ")", Auth: "AUTH_UNVERIFIED"}
	}
	if version == "" {
		return mcpProbeOutcome{Summary: "initialize invalid (missing protocolVersion — client cannot bind a transport revision)", Auth: "AUTH_UNVERIFIED"}
	}

	// Stage 2 — protocol: the initialized notification (no JSON-RPC
	// reply by definition) and tool discovery, with strict envelope
	// validation: version match, id echo, result/error exclusivity.
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	nresp, _, err := post(notifBody, "")
	if err != nil {
		return unreachable("notifications/initialized", err)
	}
	if nresp.StatusCode < 200 || nresp.StatusCode > 299 {
		return mcpProbeOutcome{Summary: "protocol: broken (initialized notification rejected: http " +
			strconv.Itoa(nresp.StatusCode) + ")", Auth: "AUTH_UNVERIFIED"}
	}
	lresp, lraw, err := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "")
	if err != nil {
		return unreachable("tools/list", err)
	}
	if v, ok := presenceVerdict(lresp.StatusCode, lraw, anon); ok {
		return v
	}
	list, err := decodeJSONRPC(lresp, lraw)
	if err != nil {
		return mcpProbeOutcome{Summary: "tools/list invalid (" + err.Error() + ")", Auth: "AUTH_UNVERIFIED"}
	}
	if _, err := validateEnvelope(list, 2); err != nil {
		return mcpProbeOutcome{Summary: "tools/list invalid (" + err.Error() + ")", Auth: "AUTH_UNVERIFIED"}
	}
	res, _ := list["result"].(map[string]any)
	tools, ok := res["tools"].([]any)
	if !ok {
		return mcpProbeOutcome{Summary: "tools/list invalid (no tools array)", Auth: "AUTH_UNVERIFIED"}
	}

	// Stage 3 — authentication facet. The probe holds no bearer, so a
	// 200-only exchange proves usability but never enforcement: an
	// upstream-oauth server that answers anonymously has NOT proven its
	// OAuth contract. Fixture servers are anonymous by profile.
	auth := "AUTH_UNVERIFIED"
	authNote := "; auth unverified (answered without bearer — upstream OAuth enforcement NOT proven, qualify against the real IdP)"
	if anon {
		auth = "AUTH_NONE"
		authNote = ""
	}
	return mcpProbeOutcome{
		Summary:  "ok (protocol " + version + ", tools/list answered; " + strconv.Itoa(len(tools)) + " tools)" + authNote,
		Verified: true,
		Auth:     auth,
		Protocol: version,
	}
}

// decodeJSONRPC decodes a plain JSON-RPC body or an SSE stream carrying
// one (first data: line with a JSON object). Anything else is a protocol
// problem, not a transport problem.
func decodeJSONRPC(resp *http.Response, raw []byte) (map[string]any, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, &mcpStatusError{code: resp.StatusCode}
	}
	body := raw
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
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
// AUTH_UNVERIFIED is the honest steady state for upstream-oauth: the
// local probe holds no bearer, so a 200-only exchange proves usability
// but never upstream OAuth enforcement.
func doctorAuthLine(mode, auth string) string {
	switch auth {
	case "AUTH_NONE":
		return "AUTH_NONE (anonymous fixture profile)"
	case "AUTH_REQUIRED":
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

// doctorProtocolExit maps the protocol probe to the process exit. A green
// exit must mean a verified usable local connection (or a non-MCP lease
// where the probe does not apply). Unknown, unreachable, or invalid
// protocol health fails the oracle instead of passing it.
func doctorProtocolExit(mode string, verified bool) int {
	if mode != "mcp_upstream_oauth" && mode != "mcp_anonymous_fixture" {
		return apperr.ExitOK
	}
	if verified {
		return apperr.ExitOK
	}
	return apperr.ExitProtocol
}
