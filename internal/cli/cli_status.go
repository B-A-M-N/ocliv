// Local status and diagnostics: status and doctor.
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/agent"
	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/doctor"
)

// statusProblem is a classified failure to reach the authoritative
// relay record. The state names the condition; advice names the next
// corrective action. An unclassified error stays UNKNOWN, never a
// stale cache echo (P1-F, OCL-002).
type statusProblem struct {
	state  string
	advice string
}

func (e *statusProblem) Error() string { return e.state + ": " + e.advice }

// classifyRelayMgmtError maps typed transport failures onto accurate observer
// diagnostics without conflating observer reachability failures with confirmed
// tunnel disconnection (OCL-002).
func classifyRelayMgmtError(err error) *statusProblem {
	if err == nil {
		return nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return &statusProblem{
			state:  "RELAY_DNS_UNREACHABLE",
			advice: "DNS lookup failed for relay (" + dnsErr.Error() + "); tunnel state is unknown, check DNS/network then run `ocliv doctor`",
		}
	}
	var (
		unkAuth   x509.UnknownAuthorityError
		certInv   x509.CertificateInvalidError
		hostErr   x509.HostnameError
		sysRoots  x509.SystemRootsError
		recHdrErr tls.RecordHeaderError
		alertErr  tls.AlertError
	)
	if errors.As(err, &unkAuth) || errors.As(err, &certInv) || errors.As(err, &hostErr) ||
		errors.As(err, &sysRoots) || errors.As(err, &recHdrErr) || errors.As(err, &alertErr) {
		return &statusProblem{
			state:  "RELAY_TLS_ERROR",
			advice: "TLS validation failed while contacting relay (" + err.Error() + "); verify certificate/CA trust then run `ocliv doctor`",
		}
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &statusProblem{
			state:  "RELAY_UNREACHABLE",
			advice: "timed out contacting relay (" + err.Error() + "); tunnel state is unknown, check network and relay URL then run `ocliv doctor`",
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return &statusProblem{
			state:  "RELAY_UNREACHABLE",
			advice: "could not reach relay (" + opErr.Error() + "); tunnel state is unknown, check network and relay URL then run `ocliv doctor`",
		}
	}
	return &statusProblem{
		state:  "TUNNEL_STATE_UNKNOWN",
		advice: "observer could not query relay (" + err.Error() + "); tunnel state is unknown, run `ocliv doctor`",
	}
}

// relayStateAdvice maps terminal/in-transit relay lease states to the
// operator's next action. ACTIVE needs none.
func relayStateAdvice(state string) string {
	switch state {
	case "RECONNECTING":
		return "agent is reattaching; if it stays here, check the agent's network, then run `ocliv doctor`"
	case "CLOSED", "EXPIRED", "REVOKED":
		return "this tunnel has ended; start a new one with `ocliv PORT`"
	}
	return ""
}

// renderStatus builds the status report from the cached local lease and
// the authoritative relay record. The relay state wins whenever the query
// succeeded; anything else is UNKNOWN, never a stale cache echo (P1).
func renderStatus(local, remote map[string]any, fetchErr error, showJSON bool) (string, int) {
	if len(local) == 0 {
		return "no active tunnel\n", apperr.ExitOK
	}
	state := "UNKNOWN"
	authoritative := false
	if fetchErr == nil && remote != nil {
		if s, ok := remote["status"].(string); ok && s != "" {
			state, authoritative = s, true
		}
	}
	url, _ := local["url"].(string)
	mode, _ := local["access_mode"].(string)
	// The local readiness contract (Domain A) is deployment identity,
	// not a reachability claim: show the recorded probe path and
	// expected status so the operator knows which contract a
	// local-target-unreachable message is judged against.
	probePath, _ := local["probe_path"].(string)
	if probePath == "" {
		probePath = "/"
	}
	probeStatus := "any status"
	if n, ok := local["probe_status"].(int); ok && n != 0 {
		probeStatus = fmt.Sprintf("%d", n)
	} else if f, ok := local["probe_status"].(float64); ok && f != 0 {
		probeStatus = fmt.Sprintf("%d", int64(f))
	}
	// Route state is a separate authoritative signal from attachment:
	// live means a session at the recorded generation is forwarding now;
	// anything else never implies reachability. External (public-internet)
	// reachability is not claimed here; `ocliv doctor` probes it.
	route := "unknown"
	tunnelState := "TUNNEL_STATE_UNKNOWN"
	if authoritative {
		if u, ok := remote["url"].(string); ok && u != "" {
			url = u
		}
		if m, ok := remote["access_mode"].(string); ok && m != "" {
			mode = m
		}
		if live, ok := remote["route_live"].(bool); ok {
			route = "offline (no live session)"
			tunnelState = "TUNNEL_OFFLINE"
			if live {
				route = "live"
				tunnelState = "TUNNEL_ONLINE"
				if g, ok := remote["live_generation"].(float64); ok && g >= 0 {
					route = fmt.Sprintf("live (generation %d)", int64(g))
				}
			}
		} else if state == "CLOSED" || state == "EXPIRED" || state == "REVOKED" || state == "RECONNECTING" {
			tunnelState = "TUNNEL_OFFLINE"
		}
	}
	lastKnownStatus, _ := local["last_known_status"].(string)
	lastKnownRoute, _ := local["last_known_route"].(string)
	lastObservedAt, _ := local["last_observed_at"].(string)
	if showJSON {
		if !authoritative {
			var prob *statusProblem
			if errors.As(fetchErr, &prob) {
				state = prob.state
			}
		}
		payload := map[string]any{
			"lease_id": local["lease_id"], "url": url, "access_mode": mode,
			"port": local["port"], "status": state, "tunnel_state": tunnelState,
			"authoritative": authoritative,
			"route":         route, "probe_path": probePath,
			"probe_status": local["probe_status"],
		}
		if !authoritative && lastKnownStatus != "" {
			payload["last_known_status"] = lastKnownStatus
			if lastKnownRoute != "" {
				payload["last_known_route"] = lastKnownRoute
			}
			if lastObservedAt != "" {
				payload["last_observed_at"] = lastObservedAt
			}
		}
		raw, _ := json.Marshal(payload)
		return string(raw) + "\n", apperr.ExitOK
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Lease:  %v\nURL:    %s\nMode:   %s\nPort:   %v\n",
		local["lease_id"], url, mode, local["port"])
	fmt.Fprintf(&sb, "Probe:  %s (expect %s)\n", probePath, probeStatus)
	if authoritative {
		fmt.Fprintf(&sb, "Status: %s (relay)\n", state)
		fmt.Fprintf(&sb, "Tunnel: %s\n", tunnelState)
		fmt.Fprintf(&sb, "Route:  %s\n", route)
		if adv := relayStateAdvice(state); adv != "" {
			fmt.Fprintf(&sb, "Next:   %s\n", adv)
		}
		if route != "unknown" && !strings.HasPrefix(route, "live") {
			fmt.Fprintf(&sb, "Next:   route is offline; check the agent and local service, then run `ocliv doctor`\n")
		}
	} else if fetchErr != nil {
		var prob *statusProblem
		if errors.As(fetchErr, &prob) {
			fmt.Fprintf(&sb, "Status: %s\n", prob.state)
			fmt.Fprintf(&sb, "Tunnel: %s\n", tunnelState)
			if lastKnownStatus != "" {
				ts := lastObservedAt
				if ts == "" {
					ts = "timestamp unavailable"
				}
				fmt.Fprintf(&sb, "Last known (non-authoritative, observed %s): status=%s route=%s\n", ts, lastKnownStatus, lastKnownRoute)
			}
			fmt.Fprintf(&sb, "Next:   %s\n", prob.advice)
		} else {
			fmt.Fprintf(&sb, "Status: UNKNOWN (%s)\n", fetchErr.Error())
			fmt.Fprintf(&sb, "Tunnel: %s\n", tunnelState)
			if lastKnownStatus != "" {
				ts := lastObservedAt
				if ts == "" {
					ts = "timestamp unavailable"
				}
				fmt.Fprintf(&sb, "Last known (non-authoritative, observed %s): status=%s route=%s\n", ts, lastKnownStatus, lastKnownRoute)
			}
			fmt.Fprintf(&sb, "Next:   run `ocliv doctor` to isolate relay, network, and local service\n")
		}
	} else {
		fmt.Fprintf(&sb, "Status: UNKNOWN\n")
		fmt.Fprintf(&sb, "Tunnel: %s\n", tunnelState)
	}
	return sb.String(), apperr.ExitOK
}

// resolveDoctorProbe merges the recorded probe contract with explicit
// doctor flags. Explicit flags win; everything else falls back to the
// recorded contract. Validation matches the tunnel edge exactly:
// origin-form path, expected status 100-599. An empty path means / and
// status 0 means any HTTP response.
func resolveDoctorProbe(recPath string, recStatus int, flagPath, flagStatusStr string) (string, int, error) {
	path, status := recPath, recStatus
	if flagPath != "" {
		path = flagPath
	}
	if flagStatusStr != "" {
		n, err := strconv.Atoi(flagStatusStr)
		if err != nil || n < 100 || n > 599 {
			return "", 0, fmt.Errorf("--probe-status wants 100-599")
		}
		status = n
	}
	if path != "" {
		if verr := agent.ValidateProbePath(path); verr != nil {
			return "", 0, verr
		}
	}
	return path, status, nil
}

// cmdStatus prints lease state, never credentials (A07). The cached
// local lease selects the record; the signed relay status is
// authoritative whenever reachable.
func cmdStatus(argv []string) int {
	// `ocliv status NAME [--json] [--strict-health]` inspects a hosted service directly.
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		return cmdServiceStatus(argv, defaultServiceOps())
	}
	showJSON := len(argv) > 0 && argv[0] == "--json"
	dir, _, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	store, err := config.OpenLeaseStore(dir)
	var recs []config.LeaseRecord
	if err == nil {
		recs = store.List()
	}
	if len(recs) == 0 {
		if svcStore, serr := openServices(); serr == nil {
			if svcs, lerr := svcStore.List(); lerr == nil && len(svcs) > 0 {
				if showJSON {
					b, _ := json.MarshalIndent(map[string]any{"services": svcs}, "", "  ")
					fmt.Println(string(b))
					return apperr.ExitOK
				}
				return renderServiceControlPanel(svcs, defaultServiceOps())
			}
		}
		fmt.Println("no active tunnel")
		return apperr.ExitOK
	}
	rec := recs[0] // most recently updated; others listed below
	st := map[string]any{
		"lease_id": rec.LeaseID, "hostname": rec.Hostname, "url": rec.URL,
		"port": rec.Port, "access_mode": rec.AccessMode, "generation": rec.Generation,
		"probe_path": rec.ProbePath, "probe_status": rec.ProbeStatus,
		"last_known_status": rec.LastKnownStatus, "last_known_route": rec.LastKnownRoute,
		"last_observed_at": rec.LastObservedAt,
	}
	leaseID := rec.LeaseID
	cfgVals, _ := config.LoadAgentFile(cfgPath)
	relayURL := cfgVals["relay_url"]
	if v := config.EnvRelay(); v != "" {
		relayURL = v
	}
	if relayURL == "" {
		relayURL = config.DefaultRelayURL
	}
	var remote map[string]any
	var fetchErr error
	if leaseID == "" {
		fetchErr = fmt.Errorf("no recorded lease id")
	} else if k, keyID, kerr := loadKey(); kerr != nil {
		fetchErr = &statusProblem{state: "AUTHENTICATION_REQUIRED", advice: "no usable agent key (" + kerr.Error() + "); run `ocliv login`"}
	} else {
		code, body, mgmtErr := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/lease/"+leaseID+"/status")
		if mgmtErr != nil {
			fetchErr = classifyRelayMgmtError(mgmtErr)
		} else if code != http.StatusOK {
			if code == http.StatusUnauthorized || code == http.StatusForbidden {
				fetchErr = &statusProblem{state: "AUTHENTICATION_REQUIRED", advice: fmt.Sprintf("relay refused these credentials (HTTP %d); re-enroll with `ocliv login`", code)}
			} else {
				fetchErr = fmt.Errorf("relay status %d", code)
			}
		} else if uerr := json.Unmarshal(body, &remote); uerr != nil {
			fetchErr = uerr
		} else if store != nil {
			if s, ok := remote["status"].(string); ok && s != "" {
				rec.LastKnownStatus = s
				if live, ok := remote["route_live"].(bool); ok {
					if live {
						rec.LastKnownRoute = "TUNNEL_ONLINE"
					} else {
						rec.LastKnownRoute = "TUNNEL_OFFLINE"
					}
				}
				rec.LastObservedAt = time.Now().UTC().Format(time.RFC3339)
				_ = store.Save(rec)
			}
		}
	}
	out, code := renderStatus(st, remote, fetchErr, showJSON)
	fmt.Print(out)
	// Enumerate sibling tunnels without credentials: closing or
	// restarting one must never silently affect another (P1-7).
	// Human output only; --json stays machine-parseable.
	if !showJSON {
		for _, other := range recs[1:] {
			fmt.Printf("Other tunnel: %s (port %d, lease %s)\n", other.Hostname, other.Port, other.LeaseID)
		}
		if svcStore, serr := openServices(); serr == nil {
			if svcs, lerr := svcStore.List(); lerr == nil && len(svcs) > 0 {
				fmt.Println()
				_ = renderServiceControlPanel(svcs, defaultServiceOps())
			}
		}
	}
	return code
}

// renderServiceControlPanel renders the operator-friendly control panel view
// for `ocliv status`: relay & device identity, hosted services with trusted
// clients, and any pending OAuth clients with exact actionable commands.
func renderServiceControlPanel(svcs []config.ServiceRecord, ops serviceOps) int {
	profile := config.ActiveProfile()
	relayURL := agentRelayURLForProfile(profile)
	k, keyID, kerr := loadKeyForProfile(profile)
	host, _ := os.Hostname()
	if relayURL != "" {
		fmt.Printf("Relay:   %s\n", relayURL)
	}
	if kerr == nil {
		if host != "" {
			fmt.Printf("Device:  %s (%s)\n", host, keyID)
		} else {
			fmt.Printf("Device:  %s\n", keyID)
		}
	} else {
		fmt.Printf("Device:  not enrolled (profile %s)\n", profile)
	}

	// Best-effort fetch of trusted clients per route from the signed publications endpoint.
	trustedByRoute := map[string][]string{}
	if kerr == nil && relayURL != "" {
		if pubs, _, err := fetchRelayPublications(relayURL, k, keyID, ops); err == nil {
			for _, p := range pubs {
				if len(p.TrustedClients) > 0 {
					trustedByRoute[p.RouteID] = p.TrustedClients
				}
			}
		}
	}

	type pendingEntry struct {
		service  string
		clientID string
		name     string
	}
	var pending []pendingEntry

	fmt.Println("\nServices:")
	for _, rec := range svcs {
		rk, rKeyID := k, keyID
		if rec.Profile != "" && rec.Profile != profile {
			rk, rKeyID, _ = loadKeyForProfile(rec.Profile)
		}
		rep := inspectServiceStatus(rec, rk, rKeyID, ops)
		urlStr := rep.PublicURL
		if urlStr == "" {
			urlStr = "-"
		}
		resolvedPubID := rep.PublicationID
		if resolvedPubID == "" {
			resolvedPubID = rec.PublicationID
		}
		trustedStr := ""
		if tcs := trustedByRoute[resolvedPubID]; len(tcs) > 0 {
			trustedStr = "  trusted=" + strings.Join(tcs, ",")
		}
		fmt.Printf("  %-14s  %-4s  %-10s  %s%s\n", rec.Name, rec.Type, rep.State, urlStr, trustedStr)

		// Collect pending OAuth clients for managed-OAuth MCP services.
		if rec.Type == "mcp" && resolvedPubID != "" && rk != nil {
			rURL := rec.RelayURL
			if rURL == "" {
				rURL = relayURL
			}
			if rURL != "" {
				if st, body, err := ops.mgmtCall(rURL, rk, rKeyID, http.MethodGet, "/v1/agent/mcp-routes/"+resolvedPubID+"/authz/pending"); err == nil && st == http.StatusOK {
					var pResp struct {
						Pending []struct {
							ClientID string `json:"client_id"`
							Name     string `json:"name"`
						} `json:"pending"`
					}
					if json.Unmarshal(body, &pResp) == nil {
						for _, pc := range pResp.Pending {
							pending = append(pending, pendingEntry{
								service:  rec.Name,
								clientID: pc.ClientID,
								name:     pc.Name,
							})
						}
					}
				}
			}
		}
	}

	if len(pending) > 0 {
		fmt.Println("\nPending OAuth clients:")
		for _, p := range pending {
			label := p.name
			if label == "" {
				label = "unnamed"
			}
			fmt.Printf("  %s (%s) on %s\n", p.clientID, label, p.service)
			fmt.Printf("    approve: ocliv trust %s --client %s\n", p.service, p.clientID)
			fmt.Printf("    revoke:  ocliv revoke client %s --service %s\n", p.clientID, p.service)
		}
	}
	return apperr.ExitOK
}

// cmdDoctor runs agent-side diagnostics, or hosted-service diagnostics when
// given a service NAME or --all (P2-23).
func cmdDoctor(argv []string) int {
	return runDoctor(argv, defaultServiceOps())
}

func runDoctor(argv []string, ops serviceOps) int {
	// P1-5: parse all CLI flags FIRST (including --profile) before resolving
	// any profile-dependent paths or relay configuration.
	var cacert string
	var flagPath, flagStatusStr, profileFlag string
	var serviceTarget string
	var checkAll, jsonOut bool
	for i := 0; i < len(argv); i++ {
		if strings.HasPrefix(argv[i], "--cacert=") {
			cacert = strings.TrimPrefix(argv[i], "--cacert=")
		} else if argv[i] == "--cacert" && i+1 < len(argv) {
			i++
			cacert = argv[i]
		} else if strings.HasPrefix(argv[i], "--profile=") {
			profileFlag = strings.TrimPrefix(argv[i], "--profile=")
		} else if argv[i] == "--profile" && i+1 < len(argv) {
			i++
			profileFlag = argv[i]
		} else if strings.HasPrefix(argv[i], "--probe-path=") {
			flagPath = strings.TrimPrefix(argv[i], "--probe-path=")
		} else if argv[i] == "--probe-path" && i+1 < len(argv) {
			i++
			flagPath = argv[i]
		} else if strings.HasPrefix(argv[i], "--probe-status=") {
			flagStatusStr = strings.TrimPrefix(argv[i], "--probe-status=")
		} else if argv[i] == "--probe-status" && i+1 < len(argv) {
			i++
			flagStatusStr = argv[i]
		} else if argv[i] == "--all" {
			checkAll = true
		} else if argv[i] == "--json" {
			jsonOut = true
		} else if !strings.HasPrefix(argv[i], "-") && serviceTarget == "" {
			serviceTarget = argv[i]
		} else {
			fmt.Fprintf(os.Stderr, "unknown doctor flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if serviceTarget != "" && checkAll {
		fmt.Fprintln(os.Stderr, "cannot combine service NAME with --all")
		return apperr.ExitCLIValidation
	}
	if serviceTarget != "" || checkAll {
		return runDoctorServices(serviceTarget, checkAll, jsonOut, profileFlag, ops)
	}
	dir, keyPath, cfgPath, perr := agentFilesForProfile(profileFlag)
	if perr != nil {
		fmt.Fprintln(os.Stderr, "error: "+perr.Error())
		return apperr.ExitCLIValidation
	}
	cfgVals, _ := config.LoadAgentFile(cfgPath)
	relayURL := cfgVals["relay_url"]
	if v := config.EnvRelay(); v != "" {
		relayURL = v
	}
	if relayURL == "" {
		relayURL = config.DefaultRelayURL
	}
	if cacert == "" {
		cacert = os.Getenv("OCLIV_CACERT")
	}
	// Doctor inspects the latest tunnel; mcp doctor --lease selects one
	// explicitly (P1-7). The record file doubles as the legacy lease path
	// doctor accepts, and its port drives the local-service probe. The
	// recorded probe contract is the default verdict line; explicit flags
	// override it after the same edge validation the tunnel applies.
	var leasePath string
	var leasePort int
	var leaseIPv6 bool
	recPath, recStatus := "", 0
	if store, serr := config.OpenLeaseStore(dir); serr == nil {
		if rec, ok := store.Latest(); ok {
			leasePath = filepath.Join(dir, config.LeaseStoreDir, rec.LeaseID+".json")
			leasePort = rec.Port
			leaseIPv6 = rec.IPv6
			recPath, recStatus = rec.ProbePath, rec.ProbeStatus
		}
	}
	probePath, probeStatus, verr := resolveDoctorProbe(recPath, recStatus, flagPath, flagStatusStr)
	if verr != nil {
		fmt.Fprintln(os.Stderr, "error: "+verr.Error())
		return apperr.ExitCLIValidation
	}
	res := doctor.CheckAgent(doctor.AgentInput{
		KeyPath: keyPath, RelayURL: relayURL,
		LeasePath: leasePath, Port: leasePort, IPv6: leaseIPv6,
		CACertPath: cacert,
		ProbePath:  probePath, ProbeStatus: probeStatus,
	})
	fmt.Print(res.Report())
	if res.OK {
		return apperr.ExitOK
	}
	return apperr.ExitRelayTLS
}

func runDoctorServices(name string, all, jsonOut bool, profile string, ops serviceOps) int {
	var svcStore *config.ServiceStore
	var err error
	if strings.TrimSpace(profile) != "" {
		svcStore, err = openServicesForProfile(profile)
	} else {
		svcStore, err = openServices()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	var targets []config.ServiceRecord
	if all {
		svcs, lerr := svcStore.List()
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "error: "+lerr.Error())
			return apperr.ExitInternal
		}
		targets = svcs
	} else {
		rec, ok, gerr := svcStore.Get(name)
		if gerr != nil {
			fmt.Fprintln(os.Stderr, "error: "+gerr.Error())
			return apperr.ExitInternal
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown hosted service %q\n", name)
			return apperr.ExitCLIValidation
		}
		targets = []config.ServiceRecord{rec}
	}
	type serviceDiag struct {
		Name        string                  `json:"name"`
		Type        string                  `json:"type"`
		OK          bool                    `json:"ok"`
		Status      ServiceStatusReport     `json:"status"`
		Persistence PersistenceVerification `json:"persistence"`
	}
	diags := make([]serviceDiag, 0, len(targets))
	allOK := true
	for _, rec := range targets {
		pv := verifyRebootPersistence(rec, ops)
		k, keyID, kerr := loadKeyForProfile(rec.Profile)
		var rep ServiceStatusReport
		if kerr != nil && rec.DesiredState != config.DesiredDisabled {
			// P1-4: missing/unreadable agent key must NEVER panic inside
			// inspectServiceStatus -> mgmtCall -> k.Private().
			serviceID := ""
			if rec.Identity != nil {
				serviceID = rec.Identity.ServiceID
			}
			rep = ServiceStatusReport{
				Name:          rec.Name,
				ServiceID:     serviceID,
				Type:          rec.Type,
				Profile:       rec.Profile,
				BackendMode:   rec.BackendMode,
				DesiredState:  rec.DesiredState,
				Revision:      rec.Revision,
				State:         ServiceStateUnknown,
				Health:        HealthBlocked,
				IngressDetail: "agent credentials missing (" + kerr.Error() + "); run `ocliv login` to re-enroll",
				Layers: ServiceLayers{
					Process:       "unknown",
					Backend:       "unknown",
					Agent:         "disconnected",
					Lease:         "unknown",
					Publication:   "unknown",
					Authorization: "missing_key",
					Edge:          "unknown",
					Client:        "unverified",
				},
			}
		} else {
			rep = inspectServiceStatus(rec, k, keyID, ops)
		}
		// For desired-enabled hosted services, a clean doctor verdict requires
		// BOTH runtime/transport health AND verified reboot persistence.
		ok := rep.State == ServiceStateServing &&
			(rep.Health == HealthReady || rep.Health == "HEALTHY") &&
			pv.PersistenceConfigured
		if rec.DesiredState == config.DesiredDisabled && rep.State == ServiceStateDisabled {
			ok = true
		}
		if !ok {
			allOK = false
		}
		diags = append(diags, serviceDiag{
			Name:        rec.Name,
			Type:        rec.Type,
			OK:          ok,
			Status:      rep,
			Persistence: pv,
		})
	}
	if jsonOut {
		b, _ := json.MarshalIndent(map[string]any{
			"ok":       allOK,
			"services": diags,
		}, "", "  ")
		fmt.Println(string(b))
	} else {
		if len(diags) == 0 {
			fmt.Println("No hosted services configured.")
			return apperr.ExitOK
		}
		for _, d := range diags {
			mark := "✓"
			if !d.OK {
				mark = "✗"
			}
			fmt.Printf("%s %s (%s) state=%s health=%s level=%s persistence=%v\n",
				mark, d.Name, d.Type, d.Status.State, d.Status.Health, d.Status.VerificationLevel, d.Persistence.PersistenceConfigured)
			fmt.Printf("  layers: process=%s backend=%s agent=%s lease=%s pub=%s auth=%s edge=%s\n",
				d.Status.Layers.Process, d.Status.Layers.Backend, d.Status.Layers.Agent,
				d.Status.Layers.Lease, d.Status.Layers.Publication, d.Status.Layers.Authorization, d.Status.Layers.Edge)
			if d.Status.IngressDetail != "" {
				fmt.Printf("  detail: %s\n", d.Status.IngressDetail)
			}
			if !d.Persistence.PersistenceConfigured && d.Persistence.FailureReason != "" {
				fmt.Printf("  persistence: %s\n", d.Persistence.FailureReason)
			}
		}
	}
	if allOK {
		return apperr.ExitOK
	}
	return apperr.ExitRelayTLS
}

// cmdRelay handles relay-side operations.
