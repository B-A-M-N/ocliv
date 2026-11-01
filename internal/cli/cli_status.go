// Local status and diagnostics: status and doctor.
package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/doctor"
)

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
	if authoritative {
		if u, ok := remote["url"].(string); ok && u != "" {
			url = u
		}
		if m, ok := remote["access_mode"].(string); ok && m != "" {
			mode = m
		}
		if live, ok := remote["route_live"].(bool); ok {
			route = "down (no live session)"
			if live {
				route = "live"
				if g, ok := remote["live_generation"].(float64); ok && g >= 0 {
					route = fmt.Sprintf("live (generation %d)", int64(g))
				}
			}
		}
	}
	if showJSON {
		raw, _ := json.Marshal(map[string]any{
			"lease_id": local["lease_id"], "url": url, "access_mode": mode,
			"port": local["port"], "status": state, "authoritative": authoritative,
			"route": route, "probe_path": probePath,
			"probe_status": local["probe_status"],
		})
		return string(raw) + "\n", apperr.ExitOK
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Lease:  %v\nURL:    %s\nMode:   %s\nPort:   %v\n",
		local["lease_id"], url, mode, local["port"])
	fmt.Fprintf(&sb, "Probe:  %s (expect %s)\n", probePath, probeStatus)
	if authoritative {
		fmt.Fprintf(&sb, "Status: %s (relay)\n", state)
		fmt.Fprintf(&sb, "Route:  %s\n", route)
	} else if fetchErr != nil {
		fmt.Fprintf(&sb, "Status: UNKNOWN (%s)\n", fetchErr.Error())
	} else {
		fmt.Fprintf(&sb, "Status: UNKNOWN\n")
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
	showJSON := len(argv) > 0 && argv[0] == "--json"
	dir, _, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	store, err := config.OpenLeaseStore(dir)
	if err != nil {
		fmt.Println("no active tunnel")
		return apperr.ExitOK
	}
	recs := store.List()
	if len(recs) == 0 {
		fmt.Println("no active tunnel")
		return apperr.ExitOK
	}
	rec := recs[0] // most recently updated; others listed below
	st := map[string]any{
		"lease_id": rec.LeaseID, "hostname": rec.Hostname, "url": rec.URL,
		"port": rec.Port, "access_mode": rec.AccessMode, "generation": rec.Generation,
		"probe_path": rec.ProbePath, "probe_status": rec.ProbeStatus,
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
		fetchErr = kerr
	} else if code, body := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/lease/"+leaseID+"/status"); code != http.StatusOK {
		fetchErr = fmt.Errorf("relay status %d", code)
	} else if uerr := json.Unmarshal(body, &remote); uerr != nil {
		fetchErr = uerr
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
	}
	return code
}

// cmdDoctor runs agent-side diagnostics.
func cmdDoctor(argv []string) int {
	_ = argv
	dir, keyPath, cfgPath, _ := agentFiles()
	cfgVals, _ := config.LoadAgentFile(cfgPath)
	relayURL := cfgVals["relay_url"]
	if v := config.EnvRelay(); v != "" {
		relayURL = v
	}
	if relayURL == "" {
		relayURL = config.DefaultRelayURL
	}
	var cacert string
	var flagPath, flagStatusStr string
	for i := 0; i < len(argv); i++ {
		if strings.HasPrefix(argv[i], "--cacert=") {
			cacert = strings.TrimPrefix(argv[i], "--cacert=")
		} else if argv[i] == "--cacert" && i+1 < len(argv) {
			i++
			cacert = argv[i]
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
		}
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
	recPath, recStatus := "", 0
	if store, serr := config.OpenLeaseStore(dir); serr == nil {
		if rec, ok := store.Latest(); ok {
			leasePath = filepath.Join(dir, config.LeaseStoreDir, rec.LeaseID+".json")
			leasePort = rec.Port
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
		LeasePath: leasePath, Port: leasePort,
		CACertPath: cacert,
		ProbePath:  probePath, ProbeStatus: probeStatus,
	})
	fmt.Print(res.Report())
	if res.OK {
		return apperr.ExitOK
	}
	return apperr.ExitRelayTLS
}

// cmdRelay handles relay-side operations.
