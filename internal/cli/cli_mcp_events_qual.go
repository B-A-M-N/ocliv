package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/ocliv/internal/authz"
)

// Explicit MCP Events qualification outcomes (OCL-004).
// The first four can be established independently of an external host; the
// final two require real non-synthetic host workflow evidence.
const (
	EventsStageAdvertised               = "EVENTS_ADVERTISED"
	EventsStageListVerified             = "EVENTS_LIST_VERIFIED"
	EventsStageSubscriptionVerified     = "SUBSCRIPTION_VERIFIED"
	EventsStageCallbackDeliveryVerified = "CALLBACK_DELIVERY_VERIFIED"
	EventsStageHostSubscriptionObserved = "HOST_SUBSCRIPTION_OBSERVED"
	EventsStageHostConsumptionVerified  = "HOST_EVENT_CONSUMPTION_VERIFIED"
)

// MCPEventsQualificationConfig configures authenticated MCP Events
// qualification (read-only by default; subscription/callback qualification is
// strictly opt-in).
type MCPEventsQualificationConfig struct {
	PublicEndpoint       *url.URL
	LocalEndpoint        *url.URL // optional local MCP endpoint for catalog consistency comparison
	AuthMode             string
	BearerToken          string
	TrustedIssuerOrigins []string
	Client               *http.Client
	LocalClient          *http.Client
	QualifySubscription  bool          // opt-in mutating qualification (never run in default doctor)
	CallbackURL          string        // optional explicit callback URL; empty starts a controlled loopback receiver
	SubscriptionTTL      time.Duration // bounded subscription lifetime (default 30s)
	CallbackTimeout      time.Duration // max wait for callback delivery (default 3s)
	HostObservations     []authz.HostObservation
}

// MCPEventsQualificationResult separates every stage of MCP Events
// qualification so relay forwarding is never conflated with host consumption.
type MCPEventsQualificationResult struct {
	PublicTransport        string   `json:"public_transport"`        // PASS | FAIL
	ResourceDiscovery      string   `json:"resource_discovery"`      // PASS | FAIL
	AnonymousAuthorization string   `json:"anonymous_authorization"` // PASS | FAIL | SKIPPED
	InvalidTokenRejection  string   `json:"invalid_token_rejection"` // PASS | FAIL | SKIPPED
	MCPNegotiation         string   `json:"mcp_negotiation"`         // PASS | FAIL | SKIPPED
	ServerDiscovery        string   `json:"server_discovery"`        // PASS | UNSUPPORTED | FAIL | SKIPPED
	EventsAdvertised       string   `json:"events_advertised"`       // PASS | FAIL | UNKNOWN | SKIPPED
	EventsList             string   `json:"events_list"`             // PASS | FAIL | SKIPPED
	CapabilityConsistency  string   `json:"capability_consistency"`  // PASS | FAIL | SKIPPED
	Subscription           string   `json:"subscription"`            // PASS | FAIL | NOT_REQUESTED
	CallbackDelivery       string   `json:"callback_delivery"`       // PASS | FAIL | NOT_REQUESTED
	ProtocolVersion        string   `json:"protocol_version,omitempty"`
	PublicEvents           []string `json:"public_events,omitempty"`
	LocalEvents            []string `json:"local_events,omitempty"`
	ObservedOutcomes       []string `json:"observed_outcomes"`
	HostSubscription       string   `json:"host_subscription"`      // OBSERVED | UNVERIFIED
	HostEventConsumption   string   `json:"host_event_consumption"` // UNVERIFIED (requires host-side workflow evidence)
	Detail                 string   `json:"detail,omitempty"`
}

// OK reports whether all required read-only (and, if requested, subscription)
// qualification stages succeeded.
func (r MCPEventsQualificationResult) OK() bool {
	if r.PublicTransport != "PASS" || r.ResourceDiscovery != "PASS" {
		return false
	}
	if r.AnonymousAuthorization == "FAIL" || r.InvalidTokenRejection == "FAIL" {
		return false
	}
	if r.MCPNegotiation != "PASS" {
		return false
	}
	if r.EventsAdvertised != "PASS" || r.EventsList != "PASS" {
		return false
	}
	if r.CapabilityConsistency == "FAIL" {
		return false
	}
	if r.Subscription == "FAIL" || r.CallbackDelivery == "FAIL" {
		return false
	}
	return true
}

// mcpSessionClient runs ordered JSON-RPC calls over Streamable HTTP against a
// canonical MCP endpoint while preserving session headers and cleaning up on Close.
type mcpSessionClient struct {
	endpoint       string
	bearer         string
	client         *http.Client
	sessionID      string
	sessionVersion string
	nextID         int
}

func newMCPSessionClient(endpoint *url.URL, bearer string, client *http.Client) *mcpSessionClient {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &mcpSessionClient{
		endpoint: endpoint.String(),
		bearer:   bearer,
		client:   client,
		nextID:   1,
	}
}

func (c *mcpSessionClient) Close() {
	if c.sessionID == "" {
		return
	}
	req, err := http.NewRequest(http.MethodDelete, c.endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", c.sessionID)
	req.Header.Set("User-Agent", "ocliv-probe/"+BinaryVersion)
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.sessionVersion != "" {
		req.Header.Set("MCP-Protocol-Version", c.sessionVersion)
	}
	if resp, err := c.client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func (c *mcpSessionClient) call(method string, params map[string]any, version string) (int, map[string]any, error) {
	id := c.nextID
	c.nextID++
	if params == nil {
		params = map[string]any{}
	}
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	rawReq, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(rawReq))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "ocliv-probe/"+BinaryVersion)
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
		req.Header.Set("MCP-Method", method)
	}
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s", redactSecret(err.Error(), c.bearer))
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Mcp-Session-Id"); got != "" {
		c.sessionID = got
	}
	if got := resp.Header.Get("Mcp-Protocol-Version"); got != "" {
		c.sessionVersion = got
	} else if version != "" {
		c.sessionVersion = version
	}
	raw, err := readMCPProbeBody(resp, fmt.Sprint(id))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s", redactSecret(err.Error(), c.bearer))
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	env, err := decodeJSONRPC(resp, raw)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, env, nil
}

func (c *mcpSessionClient) notify(method string, params map[string]any, version string) error {
	if params == nil {
		params = map[string]any{}
	}
	rawReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	})
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(rawReq))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "ocliv-probe/"+BinaryVersion)
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
		req.Header.Set("MCP-Method", method)
	}
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func isMethodNotFound(env map[string]any) bool {
	errObj, ok := env["error"].(map[string]any)
	if !ok {
		return false
	}
	if code, ok := errObj["code"].(float64); ok && int(code) == -32601 {
		return true
	}
	if msg, ok := errObj["message"].(string); ok && strings.Contains(strings.ToLower(msg), "method not found") {
		return true
	}
	return false
}

func hasEventsCapability(caps map[string]any) bool {
	if len(caps) == 0 {
		return false
	}
	if ev, ok := caps["events"]; ok && ev != nil {
		if b, isBool := ev.(bool); isBool {
			return b
		}
		return true
	}
	if exp, ok := caps["experimental"].(map[string]any); ok {
		if ev, ok := exp["events"]; ok && ev != nil {
			if b, isBool := ev.(bool); isBool {
				return b
			}
			return true
		}
	}
	return false
}

func extractEventCatalog(res map[string]any) ([]string, bool) {
	rawList, ok := res["events"].([]any)
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(rawList))
	for _, item := range rawList {
		switch v := item.(type) {
		case string:
			if v != "" {
				names = append(names, v)
			}
		case map[string]any:
			for _, key := range []string{"name", "type", "event", "id"} {
				if s, ok := v[key].(string); ok && s != "" {
					names = append(names, s)
					break
				}
			}
		}
	}
	sort.Strings(names)
	return names, true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func probeEventsCatalogOnEndpoint(ep *url.URL, bearer string, hc *http.Client) (protocolVersion string, serverDiscoverStatus string, eventsAdvertised bool, catalog []string, session *mcpSessionClient, err error) {
	sess := newMCPSessionClient(ep, bearer, hc)
	// Try modern stateless discovery first (MCP 2026-07-28): server/discover or tools/list.
	const modernVersion = "2026-07-28"
	modernMeta := map[string]any{
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    modernVersion,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
	}
	if _, env, cerr := sess.call("server/discover", modernMeta, modernVersion); cerr == nil {
		if res, ok := env["result"].(map[string]any); ok {
			protocolVersion = modernVersion
			serverDiscoverStatus = "PASS"
			if pv, ok := res["protocolVersion"].(string); ok && pv != "" {
				protocolVersion = pv
			}
			if caps, ok := res["capabilities"].(map[string]any); ok {
				eventsAdvertised = hasEventsCapability(caps)
			}
		} else if isMethodNotFound(env) {
			serverDiscoverStatus = "UNSUPPORTED"
		}
	}

	if protocolVersion == "" {
		// Try modern stateless tools/list to see if endpoint is modern-only without server/discover.
		if _, env, cerr := sess.call("tools/list", modernMeta, modernVersion); cerr == nil {
			if res, ok := env["result"].(map[string]any); ok {
				if _, hasTools := res["tools"].([]any); hasTools {
					protocolVersion = modernVersion
				}
			}
		}
	}

	if protocolVersion == "" {
		// Fall back to standard initialize -> notifications/initialized handshake.
		_, initEnv, ierr := sess.call("initialize", map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "ocliv-events-qual", "version": BinaryVersion},
		}, "")
		if ierr != nil {
			sess.Close()
			return "", "SKIPPED", false, nil, nil, fmt.Errorf("initialize failed: %w", ierr)
		}
		initRes, ok := initEnv["result"].(map[string]any)
		if !ok {
			sess.Close()
			return "", "SKIPPED", false, nil, nil, fmt.Errorf("initialize returned error: %v", initEnv["error"])
		}
		pv, _ := initRes["protocolVersion"].(string)
		if pv == "" {
			sess.Close()
			return "", "SKIPPED", false, nil, nil, fmt.Errorf("initialize missing protocolVersion")
		}
		protocolVersion = pv
		if caps, ok := initRes["capabilities"].(map[string]any); ok && hasEventsCapability(caps) {
			eventsAdvertised = true
		}
		if nerr := sess.notify("notifications/initialized", map[string]any{}, protocolVersion); nerr != nil {
			sess.Close()
			return "", "SKIPPED", false, nil, nil, fmt.Errorf("notifications/initialized failed: %w", nerr)
		}
		// Optional server/discover under negotiated version if not already verified.
		if serverDiscoverStatus == "" {
			if _, denv, derr := sess.call("server/discover", map[string]any{}, protocolVersion); derr == nil {
				if dres, ok := denv["result"].(map[string]any); ok {
					serverDiscoverStatus = "PASS"
					if caps, ok := dres["capabilities"].(map[string]any); ok && hasEventsCapability(caps) {
						eventsAdvertised = true
					}
				} else if isMethodNotFound(denv) {
					serverDiscoverStatus = "UNSUPPORTED"
				} else {
					serverDiscoverStatus = "FAIL"
				}
			} else {
				serverDiscoverStatus = "UNSUPPORTED"
			}
		}
	}
	if serverDiscoverStatus == "" {
		serverDiscoverStatus = "UNSUPPORTED"
	}

	// Call events/list using negotiated protocol version.
	listParams := map[string]any{}
	if protocolVersion == modernVersion {
		listParams = modernMeta
	}
	_, listEnv, lerr := sess.call("events/list", listParams, protocolVersion)
	if lerr != nil {
		return protocolVersion, serverDiscoverStatus, eventsAdvertised, nil, sess, fmt.Errorf("events/list failed: %w", lerr)
	}
	if _, hasErr := listEnv["error"]; hasErr {
		return protocolVersion, serverDiscoverStatus, eventsAdvertised, nil, sess, fmt.Errorf("events/list error: %v", listEnv["error"])
	}
	listRes, ok := listEnv["result"].(map[string]any)
	if !ok {
		return protocolVersion, serverDiscoverStatus, eventsAdvertised, nil, sess, fmt.Errorf("events/list missing result object")
	}
	events, ok := extractEventCatalog(listRes)
	if !ok {
		return protocolVersion, serverDiscoverStatus, eventsAdvertised, nil, sess, fmt.Errorf("events/list missing events array")
	}
	return protocolVersion, serverDiscoverStatus, eventsAdvertised, events, sess, nil
}

// QualifyMCPEvents executes the full staged MCP Events qualification contract
// (OCL-004). Default execution is read-only; mutating subscription and callback
// qualification runs only when cfg.QualifySubscription is explicitly true.
func QualifyMCPEvents(cfg MCPEventsQualificationConfig) MCPEventsQualificationResult {
	res := MCPEventsQualificationResult{
		PublicTransport:        "FAIL",
		ResourceDiscovery:      "FAIL",
		AnonymousAuthorization: "SKIPPED",
		InvalidTokenRejection:  "SKIPPED",
		MCPNegotiation:         "SKIPPED",
		ServerDiscovery:        "SKIPPED",
		EventsAdvertised:       "SKIPPED",
		EventsList:             "SKIPPED",
		CapabilityConsistency:  "SKIPPED",
		Subscription:           "NOT_REQUESTED",
		CallbackDelivery:       "NOT_REQUESTED",
		ObservedOutcomes:       []string{},
		HostSubscription:       "UNVERIFIED",
		HostEventConsumption:   "UNVERIFIED",
	}
	// Surface real (non-synthetic) host observations independently of synthetic probes.
	for _, o := range cfg.HostObservations {
		if !o.IsSynthetic && o.ClientKind != "synthetic-probe" && o.ResultCategory == "ok" && o.Stage == authz.StageEventsSubscriptionObserved {
			res.HostSubscription = "OBSERVED"
			res.ObservedOutcomes = append(res.ObservedOutcomes, EventsStageHostSubscriptionObserved)
			break
		}
	}

	if cfg.PublicEndpoint == nil {
		res.Detail = "missing public MCP endpoint URL"
		return res
	}
	hc := wrapNoRedirectClient(cfg.Client)

	// Stages 1 & 2: Public transport + Resource discovery.
	disc := runReadOnlyDiscoveryCheckWithAllowlist(hc, cfg.PublicEndpoint.String(), cfg.TrustedIssuerOrigins)
	res.PublicTransport = disc.Transport
	res.ResourceDiscovery = disc.Discovery
	if disc.Transport != "PASS" || disc.Discovery != "PASS" {
		res.Detail = disc.Detail
		return res
	}

	// Stage 3: Anonymous authorization rejection (required for non-fixture OAuth routes).
	if cfg.AuthMode != "mcp_anonymous_fixture" {
		anonOut := runMCPProbeWithConfig(MCPProbeConfig{
			Endpoint: cfg.PublicEndpoint,
			AuthMode: cfg.AuthMode,
			Client:   hc,
			IsPublic: true,
		})
		if !anonOut.Verified && (anonOut.AuthEvidence.PublicEnforcement == "ENFORCED" || anonOut.Auth == "AUTH_REQUIRED") {
			res.AnonymousAuthorization = "PASS"
		} else {
			res.AnonymousAuthorization = "FAIL"
			res.Detail = "anonymous request to protected public MCP endpoint was not rejected"
			return res
		}

		// Stage 4: Invalid bearer rejection.
		var badBytes [24]byte
		_, _ = rand.Read(badBytes[:])
		badTok := "ocliv-invalid-" + hex.EncodeToString(badBytes[:])
		invOut := runMCPProbeWithConfig(MCPProbeConfig{
			Endpoint:    cfg.PublicEndpoint,
			AuthMode:    cfg.AuthMode,
			BearerToken: badTok,
			Client:      hc,
			IsPublic:    true,
		})
		if !invOut.Verified && (invOut.AuthEvidence.AuthenticatedPublicMCP == "REJECTED" || invOut.Auth == "AUTH_REQUIRED") {
			res.InvalidTokenRejection = "PASS"
		} else {
			res.InvalidTokenRejection = "FAIL"
			res.Detail = "invalid bearer token was not rejected by public MCP endpoint"
			return res
		}
	}

	if cfg.BearerToken == "" && cfg.AuthMode != "mcp_anonymous_fixture" {
		res.Detail = "no bearer token supplied; pass --token-file PATH to qualify authenticated MCP Events"
		return res
	}

	// Stage 5: Authenticated MCP negotiation.
	authProbe := runMCPProbeWithConfig(MCPProbeConfig{
		Endpoint:    cfg.PublicEndpoint,
		AuthMode:    cfg.AuthMode,
		BearerToken: cfg.BearerToken,
		Client:      hc,
		IsPublic:    true,
	})
	if !authProbe.Verified {
		res.MCPNegotiation = "FAIL"
		res.Detail = redactSecret(authProbe.Summary, cfg.BearerToken)
		return res
	}
	res.MCPNegotiation = "PASS"
	res.ProtocolVersion = authProbe.Protocol

	// Stages 6, 7, 8: server/discover, Events advertisement, events/list.
	pv, discStatus, adv, pubEvents, pubSess, evErr := probeEventsCatalogOnEndpoint(cfg.PublicEndpoint, cfg.BearerToken, hc)
	if pubSess != nil {
		defer pubSess.Close()
	}
	if pv != "" {
		res.ProtocolVersion = pv
	}
	res.ServerDiscovery = discStatus
	if adv || hasEventsCapability(authProbe.ServerCapabilities) {
		res.EventsAdvertised = "PASS"
		res.ObservedOutcomes = append(res.ObservedOutcomes, EventsStageAdvertised)
	} else {
		res.EventsAdvertised = "FAIL"
	}
	if evErr != nil {
		res.EventsList = "FAIL"
		res.Detail = redactSecret(evErr.Error(), cfg.BearerToken)
		return res
	}
	res.EventsList = "PASS"
	res.PublicEvents = pubEvents
	res.ObservedOutcomes = append(res.ObservedOutcomes, EventsStageListVerified)

	// Stage 9: Local vs public event catalog consistency (when local endpoint is provided).
	if cfg.LocalEndpoint != nil {
		localHC := cfg.LocalClient
		if localHC == nil {
			localHC = &http.Client{Timeout: 5 * time.Second}
		}
		_, _, _, localEvents, localSess, lerr := probeEventsCatalogOnEndpoint(cfg.LocalEndpoint, "", localHC)
		if localSess != nil {
			localSess.Close()
		}
		if lerr != nil {
			res.CapabilityConsistency = "FAIL"
			res.Detail = "local events/list failed: " + lerr.Error()
			return res
		}
		res.LocalEvents = localEvents
		if stringSlicesEqual(localEvents, pubEvents) {
			res.CapabilityConsistency = "PASS"
		} else {
			res.CapabilityConsistency = "FAIL"
			res.Detail = fmt.Sprintf("local events (%v) and public events (%v) catalogs disagree", localEvents, pubEvents)
			return res
		}
	}

	// Stage 10 (opt-in only): Subscription & authenticated callback delivery with cleanup.
	if cfg.QualifySubscription {
		res.Subscription = "FAIL"
		res.CallbackDelivery = "FAIL"
		if err := qualifyEventsSubscription(cfg, pubSess, res.ProtocolVersion, pubEvents, &res); err != nil {
			res.Detail = redactSecret(err.Error(), cfg.BearerToken)
			return res
		}
	}

	return res
}

func qualifyEventsSubscription(cfg MCPEventsQualificationConfig, sess *mcpSessionClient, protocolVersion string, events []string, res *MCPEventsQualificationResult) error {
	if sess == nil {
		return fmt.Errorf("no active MCP session for subscription qualification")
	}
	var secretBytes [24]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return fmt.Errorf("generate callback secret: %w", err)
	}
	callbackSecret := "ocb_" + hex.EncodeToString(secretBytes[:])

	ttl := cfg.SubscriptionTTL
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 30 * time.Second
	}
	cbTimeout := cfg.CallbackTimeout
	if cbTimeout <= 0 || cbTimeout > 30*time.Second {
		cbTimeout = 3 * time.Second
	}

	var deliveredCh chan bool
	var cbSrv *http.Server
	callbackURL := strings.TrimSpace(cfg.CallbackURL)
	if callbackURL == "" {
		deliveredCh = make(chan bool, 1)
		var once sync.Once
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("start local callback receiver: %w", err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			gotSecret := strings.TrimSpace(r.Header.Get("X-Ocliv-Callback-Secret"))
			if gotSecret == "" {
				authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
				if strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
					gotSecret = strings.TrimSpace(authHdr[7:])
				}
			}
			if subtle.ConstantTimeCompare([]byte(gotSecret), []byte(callbackSecret)) != 1 {
				http.Error(w, "unauthorized callback", http.StatusUnauthorized)
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64*1024))
			w.WriteHeader(http.StatusAccepted)
			once.Do(func() { deliveredCh <- true })
		})
		cbSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = cbSrv.Serve(ln) }()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = cbSrv.Shutdown(ctx)
		}()
		callbackURL = "http://" + ln.Addr().String() + "/callback"
	}

	subParams := map[string]any{
		"callbackUrl":    callbackURL,
		"callbackSecret": callbackSecret,
		"ttlSeconds":     int(ttl.Seconds()),
	}
	if len(events) > 0 {
		subParams["events"] = []string{events[0]}
	}
	if protocolVersion == "2026-07-28" {
		subParams["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    protocolVersion,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}
	}

	_, subEnv, err := sess.call("events/subscribe", subParams, protocolVersion)
	if err != nil {
		return fmt.Errorf("events/subscribe failed: %s", redactSecret(err.Error(), callbackSecret))
	}
	if _, hasErr := subEnv["error"]; hasErr {
		return fmt.Errorf("events/subscribe returned error")
	}
	subRes, ok := subEnv["result"].(map[string]any)
	if !ok {
		return fmt.Errorf("events/subscribe missing result")
	}
	subID, _ := subRes["subscriptionId"].(string)
	if subID == "" {
		subID, _ = subRes["id"].(string)
	}
	if subID == "" {
		return fmt.Errorf("events/subscribe did not return a subscriptionId")
	}

	// Always clean up the bounded test subscription on exit.
	defer func() {
		unsubParams := map[string]any{"subscriptionId": subID}
		if protocolVersion == "2026-07-28" {
			unsubParams["_meta"] = map[string]any{
				"io.modelcontextprotocol/protocolVersion":    protocolVersion,
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			}
		}
		_, _, _ = sess.call("events/unsubscribe", unsubParams, protocolVersion)
	}()

	res.Subscription = "PASS"
	res.ObservedOutcomes = append(res.ObservedOutcomes, EventsStageSubscriptionVerified)

	if deliveredCh != nil {
		select {
		case <-deliveredCh:
			res.CallbackDelivery = "PASS"
			res.ObservedOutcomes = append(res.ObservedOutcomes, EventsStageCallbackDeliveryVerified)
		case <-time.After(cbTimeout):
			res.CallbackDelivery = "FAIL"
			return fmt.Errorf("timed out waiting %s for authenticated callback delivery", cbTimeout)
		}
	} else {
		// External callback URL supplied: cannot observe local delivery directly.
		res.CallbackDelivery = "NOT_REQUESTED"
	}
	return nil
}
