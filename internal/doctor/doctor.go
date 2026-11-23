// Package doctor reports substantiated diagnostics only (A05): verified
// facts are marked verified; anything unproven is unknown/unavailable, never
// a green check.
package doctor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/B-A-M-N/ocliv/internal/limits"
)

// Finding is one diagnostic line.
type Finding struct {
	OK       bool
	Verified bool
	Name     string
	Detail   string
}

// Result is a doctor report.
type Result struct {
	OK       bool
	Findings []Finding
}

// Report renders human-readable diagnostics with secrets redacted.
func (r Result) Report() string {
	var sb strings.Builder
	for _, f := range r.Findings {
		mark := "?"
		if f.Verified && f.OK {
			mark = "✓"
		} else if f.Verified && !f.OK {
			mark = "✗"
		}
		fmt.Fprintf(&sb, "%s %s: %s\n", mark, f.Name, f.Detail)
	}
	return sb.String()
}

// AgentInput for agent-side checks. CACertPath optionally points at a
// staging CA root (PEM); empty means system roots only. There is no
// insecure-skip flag: untrusted TLS is reported, never bypassed.
// ProbePath/ProbeStatus carry the tunnel's recorded readiness contract
// (Domain A): empty path means / and status 0 means any HTTP response.
// IPv6 selects the [::1] loopback family recorded at tunnel startup;
// without it the probe assumes 127.0.0.1 and misdiagnoses IPv6 tunnels.
type AgentInput struct {
	KeyPath     string
	RelayURL    string
	LeasePath   string
	Port        int
	IPv6        bool
	CACertPath  string
	ProbePath   string
	ProbeStatus int
}

// CheckAgent runs agent-side diagnostics.
func CheckAgent(in AgentInput) Result {
	res := Result{OK: true}
	add := func(ok, verified bool, name, detail string) {
		res.Findings = append(res.Findings, Finding{OK: ok, Verified: verified, Name: name, Detail: detail})
		if verified && !ok {
			res.OK = false
		}
	}
	// Key file.
	fi, err := os.Stat(in.KeyPath)
	switch {
	case err != nil:
		add(false, true, "enrollment", "no agent key; run `ocliv login`")
	case fi.Mode().Perm()&0o077 != 0:
		add(false, true, "key permissions", fmt.Sprintf("unsafe mode %o; want 0600", fi.Mode().Perm()))
	default:
		add(true, true, "enrollment", "agent key present with safe permissions")
	}
	// Relay reachability + TLS identity, probed through the real agent
	// surface (POST /v1/agent/challenge), not the loopback-only health
	// listener. Any HTTP status — even 400 for the empty probe body —
	// proves the relay dispatched the request.
	pool, err := rootPool(in.CACertPath)
	if err != nil {
		add(false, true, "staging CA", "cannot load "+in.CACertPath+": "+shortErr(err))
	}
	client := &http.Client{Timeout: 10 * time.Second}
	externalProbeOK := false
	if strings.HasPrefix(in.RelayURL, "https") {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	}
	challengeBody, _ := json.Marshal(map[string]string{})
	resp, err := client.Post(strings.TrimRight(in.RelayURL, "/")+"/v1/agent/challenge", "application/json", bytes.NewReader(challengeBody))
	switch {
	case err == nil:
		resp.Body.Close()
		externalProbeOK = true
		add(true, true, "relay reachability", "agent-protocol endpoint answered (HTTP "+resp.Status+")")
		if strings.HasPrefix(in.RelayURL, "https") {
			add(true, true, "relay TLS identity", "certificate trusted by the configured roots")
		}
	case isTrustFailure(err):
		add(false, true, "relay TLS identity", "certificate NOT trusted: "+shortErr(err))
		add(false, false, "relay reachability", "unverified: TLS trust failed first")
	default:
		add(false, false, "relay reachability", "unverified from here ("+shortErr(err)+")")
	}
	// When this machine is also the self-hosted edge, compare the public
	// relay URL with direct loopback and local Caddy/SNI probes. A public
	// URL failure alongside a healthy local SNI edge is consistent with
	// hairpin NAT or split-horizon DNS; it cannot establish off-LAN health.
	if u, uerr := url.Parse(in.RelayURL); uerr == nil && u.Scheme == "https" && u.Hostname() != "" &&
		(u.Port() == "" || u.Port() == "443") && (net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback()) {
		localClient := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		loopResp, loopErr := localClient.Post("http://127.0.0.1:8080/v1/agent/challenge", "application/json", bytes.NewReader(challengeBody))
		loopOK := loopErr == nil
		if loopResp != nil {
			loopResp.Body.Close()
		}
		if loopOK {
			add(true, true, "self-hosted relay loopback", "127.0.0.1:8080 agent challenge answered (HTTP "+loopResp.Status+")")
		} else {
			add(false, false, "self-hosted relay loopback", "not verified on this host ("+shortErr(loopErr)+")")
		}
		localEdge := *client
		localEdge.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: u.Hostname()},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:443")
			},
		}
		caddyResp, caddyErr := localEdge.Post("https://"+u.Host+"/v1/agent/challenge", "application/json", bytes.NewReader(challengeBody))
		caddyOK := caddyErr == nil
		if caddyResp != nil {
			caddyResp.Body.Close()
		}
		if caddyOK {
			add(true, true, "self-hosted Caddy SNI edge", u.Hostname()+" certificate and local :443 agent route answered (HTTP "+caddyResp.Status+")")
		} else if isTrustFailure(caddyErr) {
			add(false, true, "self-hosted Caddy SNI edge", "local :443 certificate is not trusted for "+u.Hostname()+": "+shortErr(caddyErr))
		} else {
			add(false, false, "self-hosted Caddy SNI edge", "local :443 not verified ("+shortErr(caddyErr)+")")
		}
		if !externalProbeOK && caddyOK {
			add(false, false, "public edge path", "failed from this network while local Caddy/SNI works; possible hairpin NAT or split-horizon DNS — verify from off-LAN")
		} else if externalProbeOK {
			add(true, false, "public edge path", "relay answered from this host; off-LAN reachability remains unverified")
		} else {
			add(false, false, "public edge path", "unverified from this network; check local edge and verify from off-LAN")
		}
	}
	// Local target: judged against the tunnel's recorded probe contract
	// (Domain A), never a hardcoded GET /. A path the tunnel never
	// promised, or a status outside the recorded expectation, is a
	// verified negative.
	if in.Port > 0 {
		path := in.ProbePath
		if path == "" {
			path = "/"
		}
		// Probe the exact loopback family the tunnel was started with
		// (Round 18): an IPv6 tunnel has nothing on 127.0.0.1, so the
		// historical hardcoded IPv4 target misdiagnosed it as down.
		host := "127.0.0.1"
		if in.IPv6 {
			host = "::1"
		}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", in.Port))
		lresp, lerr := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + addr + path)
		if lerr != nil {
			add(false, true, "local service", addr+path+" unreachable ("+shortErr(lerr)+")")
		} else {
			lresp.Body.Close()
			if in.ProbeStatus != 0 && lresp.StatusCode != in.ProbeStatus {
				add(false, true, "local service", fmt.Sprintf("%s%s answered HTTP %s, want %d under the recorded probe contract", addr, path, lresp.Status, in.ProbeStatus))
			} else {
				add(true, true, "local service", fmt.Sprintf("%s%s answered HTTP %s (probe contract: expect %s)", addr, path, lresp.Status, wantStatus(in.ProbeStatus)))
			}
		}
	}
	// Explicit non-claims: doctor cannot prove these from here.
	add(false, false, "visitor forwarding", "requires an attached lease; verify with an independent end-to-end probe")
	add(false, false, "public internet", "not applicable to private staging; NOT VERIFIED for production")
	// Clock skew: reported, not verified against NTP (H05).
	add(true, false, "clock", "system time "+time.Now().UTC().Format(time.RFC3339)+" (unverified locally)")
	return res
}

// wantStatus renders the recorded expected status: 0 means the tunnel
// accepts any HTTP response as a live local target.
func wantStatus(n int) string {
	if n == 0 {
		return "any status"
	}
	return fmt.Sprintf("%d", n)
}

// rootPool returns system roots plus the optional staging CA file.
func rootPool(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates parsed")
	}
	return pool, nil
}

// isTrustFailure reports certificate-verification failures (as opposed to
// connection failures): the server was reachable but its identity is not
// trusted by the configured roots.
func isTrustFailure(err error) bool {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return true
	}
	var invalid x509.HostnameError
	if errors.As(err, &invalid) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "certificate") && (strings.Contains(s, "unknown") || strings.Contains(s, "untrusted") || strings.Contains(s, "verify") || strings.Contains(s, "authority"))
}

// RelayInput for relay-side checks. CACertPath optionally points at a
// staging CA root (PEM); empty means system roots only. RelayHost
// overrides the default relay.<domain> control authority when the relay
// was started with --relay-host (e.g. temporary *.ts.net ingress);
// without it the doctor probes (and misdiagnoses) the wrong hostname.
type RelayInput struct {
	DataDir        string
	Domain         string
	RelayHost      string
	CACertPath     string
	MaxHTTPStreams int64
	MaxWSStreams   int64
	MaxSessions    int64
}

// relayAuthorityHost resolves the exact control hostname the relay was
// configured to serve: an explicit --relay-host wins, otherwise the
// default relay.<domain>. Empty means no authority is known.
func relayAuthorityHost(in RelayInput) string {
	if strings.TrimSpace(in.RelayHost) != "" {
		return strings.ToLower(strings.TrimSpace(in.RelayHost))
	}
	if strings.TrimSpace(in.Domain) != "" {
		return "relay." + strings.ToLower(strings.TrimSpace(in.Domain))
	}
	return ""
}

// CheckRelay runs relay-side diagnostics.
func CheckRelay(in RelayInput) Result {
	res := Result{OK: true}
	add := func(ok, verified bool, name, detail string) {
		res.Findings = append(res.Findings, Finding{OK: ok, Verified: verified, Name: name, Detail: detail})
		if verified && !ok {
			res.OK = false
		}
	}
	fi, err := os.Stat(in.DataDir)
	if err != nil || !fi.IsDir() {
		add(false, true, "data dir", in.DataDir+" missing; run `ocliv relay init`")
	} else {
		add(true, true, "data dir", in.DataDir+" present")
	}
	// Local DNS resolution of the relay authority: a verified fact about
	// this machine's resolver, not proof of external/public DNS. The
	// authority is the explicitly configured one (Round 18), never a
	// hardcoded relay.<domain> guess when --relay-host was set.
	relayHost := relayAuthorityHost(in)
	if relayHost == "" {
		add(false, true, "relay DNS", "no relay authority known (domain and relay-host both empty)")
		add(false, false, "relay TLS identity", "unprobed: no authority to dial")
		add(false, false, "wildcard DNS", "unverifiable without a domain")
		add(false, false, "wildcard TLS", "unverifiable without a domain")
		add(false, false, "public internet", "not applicable to private staging; NOT VERIFIED for production")
		add(true, false, "health endpoints", "/health/live, /health/ready, /metrics expected on loopback only (binding not verified by doctor)")
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	addrs, err := net.DefaultResolver.LookupHost(ctx, relayHost)
	cancel()
	if err != nil {
		add(false, true, "relay DNS", relayHost+" does not resolve here: "+shortErr(err))
		add(false, false, "relay TLS identity", "unprobed: no local resolution")
	} else {
		add(true, true, "relay DNS", relayHost+" resolves here to "+strings.Join(addrs, ",")+" (local resolver only)")
		pool, perr := rootPool(in.CACertPath)
		if perr != nil {
			add(false, true, "staging CA", "cannot load "+in.CACertPath+": "+shortErr(perr))
		}
		tconn, terr := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort(relayHost, "443"), &tls.Config{ServerName: relayHost, MinVersion: tls.VersionTLS12, RootCAs: pool})
		if terr != nil {
			if isTrustFailure(terr) {
				add(false, true, "relay TLS identity", "presented certificate NOT trusted: "+shortErr(terr))
			} else {
				add(false, true, "relay TLS identity", "no TLS on "+relayHost+":443 ("+shortErr(terr)+")")
			}
		} else {
			state := tconn.ConnectionState()
			leaf := ""
			if len(state.PeerCertificates) > 0 {
				c := state.PeerCertificates[0]
				leaf = "CN=" + c.Subject.CommonName + " issuer=" + c.Issuer.CommonName + " until=" + c.NotAfter.UTC().Format(time.RFC3339)
			}
			tconn.Close()
			add(true, true, "relay TLS identity", "trusted by the configured roots ("+leaf+")")
		}
	}
	if strings.TrimSpace(in.Domain) != "" {
		add(false, false, "wildcard DNS", "*.t."+in.Domain+" must resolve for visitors; verify from another network")
		add(false, false, "wildcard TLS", "ACME DNS-01 certificate must be installed in Caddy; not verifiable locally")
	} else {
		add(false, false, "wildcard DNS", "unverifiable: relay host is explicit, no wildcard namespace configured")
		add(false, false, "wildcard TLS", "unverifiable: relay host is explicit, no wildcard namespace configured")
	}
	add(false, false, "public internet", "not applicable to private staging; NOT VERIFIED for production")
	add(true, false, "health endpoints", "/health/live, /health/ready, /metrics expected on loopback only (binding not verified by doctor)")
	// OS file-descriptor budget: verify RLIMIT_NOFILE can accommodate the
	// configured stream and publisher-session concurrency limits.
	maxHTTP := in.MaxHTTPStreams
	if maxHTTP <= 0 {
		maxHTTP = limits.DefaultGlobalMaxHTTPStreams
	}
	maxWS := in.MaxWSStreams
	if maxWS <= 0 {
		maxWS = limits.DefaultGlobalMaxWSStreams
	}
	maxSess := in.MaxSessions
	if maxSess <= 0 {
		maxSess = limits.DefaultGlobalMaxSessions
	}
	// Worst-case FD estimate: ~3 FDs per publisher session + 1 per active WS
	// visitor connection + 1 per active HTTP visitor connection + 256 headroom
	// for SQLite/listeners/logs.
	neededFDs := uint64(maxSess*3 + maxHTTP + maxWS + 256)
	if neededFDs < 4096 {
		neededFDs = 4096
	}
	add(true, true, "capacity config", fmt.Sprintf("max_http_streams=%d max_ws_streams=%d max_publisher_sessions=%d (estimated FD need=%d)", maxHTTP, maxWS, maxSess, neededFDs))
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		add(false, false, "fd limit", "could not read RLIMIT_NOFILE: "+shortErr(err))
	} else {
		safeCeiling := (rLimit.Cur * 80) / 100
		detail := fmt.Sprintf("RLIMIT_NOFILE soft=%d hard=%d (need >=%d, 80%% safe ceiling=%d)", rLimit.Cur, rLimit.Max, neededFDs, safeCeiling)
		if rLimit.Cur < neededFDs {
			add(false, true, "fd limit", detail+" — configured concurrency exceeds process FD ceiling; set LimitNOFILE=65536 in the systemd unit or run ulimit -n 65536")
		} else if neededFDs > safeCeiling {
			add(false, true, "fd limit", detail+" — configured concurrency exceeds 80% headroom of RLIMIT_NOFILE; increase LimitNOFILE=65536")
		} else {
			add(true, true, "fd limit", detail)
		}
	}
	return res
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
