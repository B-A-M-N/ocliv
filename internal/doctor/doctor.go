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
	"os"
	"strings"
	"time"
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
type AgentInput struct {
	KeyPath     string
	RelayURL    string
	LeasePath   string
	Port        int
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
	if strings.HasPrefix(in.RelayURL, "https") {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	}
	challengeBody, _ := json.Marshal(map[string]string{})
	resp, err := client.Post(strings.TrimRight(in.RelayURL, "/")+"/v1/agent/challenge", "application/json", bytes.NewReader(challengeBody))
	switch {
	case err == nil:
		resp.Body.Close()
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
	// Local target: judged against the tunnel's recorded probe contract
	// (Domain A), never a hardcoded GET /. A path the tunnel never
	// promised, or a status outside the recorded expectation, is a
	// verified negative.
	if in.Port > 0 {
		path := in.ProbePath
		if path == "" {
			path = "/"
		}
		addr := fmt.Sprintf("127.0.0.1:%d", in.Port)
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
// staging CA root (PEM); empty means system roots only.
type RelayInput struct {
	DataDir    string
	Domain     string
	CACertPath string
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
	// this machine's resolver, not proof of external/public DNS.
	relayHost := "relay." + in.Domain
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
	add(false, false, "wildcard DNS", "*.t."+in.Domain+" must resolve for visitors; verify from another network")
	add(false, false, "wildcard TLS", "ACME DNS-01 certificate must be installed in Caddy; not verifiable locally")
	add(false, false, "public internet", "not applicable to private staging; NOT VERIFIED for production")
	add(true, false, "health endpoints", "/health/live, /health/ready, /metrics expected on loopback only (binding not verified by doctor)")
	return res
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
