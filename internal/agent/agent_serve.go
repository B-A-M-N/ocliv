// Stream serving: each yamux stream maps to exactly one local upstream
// exchange against the fixed literal loopback destination (D06, D07).
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/yamux"

	"ocliv/internal/config"
	"ocliv/internal/limits"
	"ocliv/internal/protocol"
)

func rand01() float64 { return rand.Float64() }

// resumeLeaseID returns the lease id for same-deployment resume, if any.
// The full deployment identity must match (relay, key, port, mode, name,
// public flag): any change requires a fresh lease, never a silent resume
// of the wrong tunnel (P1-7, P0-04).
func (rn *Runner) resumeLeaseID() string {
	if rn.Cfg.DataDir == "" {
		return ""
	}
	store, err := config.OpenLeaseStore(rn.Cfg.DataDir)
	if err != nil {
		return ""
	}
	rec, ok := store.FindResume(config.ResumeQuery{
		RelayURL: rn.Cfg.RelayURL, KeyID: rn.KeyID, Port: rn.Cfg.Port,
		AccessMode: rn.Cfg.AccessMode, Name: rn.Cfg.Name, Public: rn.Cfg.Public,
		IPv6: rn.Cfg.IPv6, TTLSeconds: rn.Cfg.TTLSeconds, UpstreamHost: rn.Cfg.UpstreamHost,
	})
	if !ok {
		return ""
	}
	return rec.LeaseID
}

// saveLease persists resumable lease state (no secrets inside). A
// persistence failure is returned, never swallowed: without a durable
// lease record the tunnel can neither resume nor be closed at shutdown,
// so the attach must fail loudly instead of running stranded. Each lease
// owns its record, so concurrent tunnels never overwrite each other.
func (rn *Runner) saveLease(att Attached) error {
	if rn.Cfg.DataDir == "" {
		return nil
	}
	store, err := config.OpenLeaseStore(rn.Cfg.DataDir)
	if err != nil {
		return err
	}
	// The record stores the invocation identity (Cfg), not the
	// relay-echoed mode: a plain `ocliv PORT` invocation carries
	// AccessMode "" while the relay reports "protected", and resume
	// must match the invocation shape to find its own lease.
	return store.Save(config.LeaseRecord{
		LeaseID: att.LeaseID, Hostname: att.Hostname, URL: att.URL,
		Port: rn.Cfg.Port, AccessMode: rn.Cfg.AccessMode, Public: rn.Cfg.Public,
		Name: rn.Cfg.Name, RelayURL: rn.Cfg.RelayURL, KeyID: rn.KeyID,
		Generation: att.Generation, IPv6: rn.Cfg.IPv6,
		TTLSeconds: rn.Cfg.TTLSeconds, UpstreamHost: rn.Cfg.UpstreamHost,
	})
}

// atomicWriteFile replaces path via temp file and rename in the same
// directory (same filesystem), with restricted permissions from
// creation, file fsync before rename, and directory fsync after.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if dfd, err := os.Open(dir); err == nil {
		_ = dfd.Sync()
		_ = dfd.Close()
	}
	return nil
}

// serve accepts streams until the session dies or ctx ends. Context
// cancellation closes the session so AcceptStream unblocks: without this,
// Ctrl+C could never stop a connected agent (F10 graceful drain relies on
// Run actually returning).
func (rn *Runner) serve(ctx context.Context, ys *yamux.Session, att Attached) error {
	// P1-6: the cancellation watcher lives exactly as long as this
	// session. AfterFunc disarms on serve return, so a naturally ended
	// session leaves no goroutine parked on the parent context until
	// the whole runner exits (previously one waiter per reconnect).
	stop := context.AfterFunc(ctx, func() { ys.Close() })
	defer stop()
	for {
		stream, err := ys.AcceptStream()
		if err != nil {
			return err // session over; reconnect loop decides (F09)
		}
		go rn.handleStream(ctx, stream, att)
	}
}

// handleStream serves one request/response exchange with bounded buffers.
func (rn *Runner) handleStream(ctx context.Context, stream net.Conn, att Attached) {
	defer stream.Close()
	ftype, payload, err := protocol.ReadFrame(stream)
	if err != nil || ftype != protocol.FRequestHead {
		return
	}
	var head protocol.RequestHead
	if err := json.Unmarshal(payload, &head); err != nil {
		return
	}
	// The agent trusts neither lease mutation nor target override from the
	// stream: generation must match this session, and the dial destination
	// is always the configured literal loopback (D06, D07, F13).
	if head.LeaseID != att.LeaseID || head.Generation != att.Generation {
		raw, _ := protocol.MarshalJSON(protocol.Abort{Type: "abort", Code: "stale_generation"})
		_ = protocol.WriteFrame(stream, protocol.FAbort, raw)
		return
	}
	if head.UpgradeWS {
		rn.serveLocalWS(ctx, stream, head)
		return
	}
	rn.serveLocalHTTP(ctx, stream, head)
}

// localClient returns the loopback-only HTTP client (D06). No proxy, no
// redirect following (D10), bounded timeouts. One client (and one
// Transport with its bounded idle pool) is shared across all streams of
// this runner: building a Transport per request leaked an idle-keep-alive
// goroutine pair plus a socket per exchange for the 90s default idle
// timeout, a steady-state bloat under stall/cancel churn (P2-1).
func (rn *Runner) localClient() *http.Client {
	if rn.HTTP != nil {
		return rn.HTTP
	}
	rn.mu.Lock()
	defer rn.mu.Unlock()
	if rn.httpShared != nil {
		return rn.httpShared
	}
	target := rn.Target
	rn.httpShared = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: limits.UpstreamTimeout}
				return d.DialContext(ctx, "tcp", target)
			},
			Proxy:               nil,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 0, // streaming: per-phase deadlines, no global kill (G04)
	}
	return rn.httpShared
}

// closeIdleLocalConns releases pooled keep-alive connections to the local
// service. Called when the runner stops reconnecting for good.
func (rn *Runner) closeIdleLocalConns() {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	if rn.httpShared == nil {
		return
	}
	if tr, ok := rn.httpShared.Transport.(interface{ CloseIdleConnections() }); ok {
		tr.CloseIdleConnections()
	}
}

// upstreamHost returns the Host to present locally (D09).
func (rn *Runner) upstreamHost() string {
	if rn.Cfg.UpstreamHost != "" {
		return rn.Cfg.UpstreamHost
	}
	if rn.Cfg.IPv6 {
		return "[::1]:" + itoaPort(rn.Cfg.Port)
	}
	return "127.0.0.1:" + itoaPort(rn.Cfg.Port)
}

func itoaPort(p int) string {
	if p == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}

// serveLocalHTTP forwards one HTTP exchange to the fixed loopback target.
func (rn *Runner) serveLocalHTTP(ctx context.Context, stream net.Conn, head protocol.RequestHead) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Exactly one reader ever consumes the stream (the streamReader below):
	// a second raw reader would steal frame bytes and corrupt multiplexing
	// (E04). Relay aborts surface as frame errors inside Read.
	sr := &streamReader{stream: stream}
	body := sr
	path := head.Path
	if path == "" {
		path = "/"
	}
	if head.RawQuery != "" {
		path += "?" + head.RawQuery
	}
	req, err := http.NewRequestWithContext(ctx, head.Method, "http://local"+path, body)
	if err != nil {
		_ = sendAgentAbort(stream, "bad_request", "invalid request")
		return
	}
	req.Host = rn.upstreamHost()
	for k, v := range head.Headers {
		if strings.EqualFold(k, "Cookie") {
			for _, c := range strings.Split(v, ";") {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				parts := strings.SplitN(c, "=", 2)
				val := ""
				if len(parts) == 2 {
					val = parts[1]
				}
				req.AddCookie(&http.Cookie{Name: parts[0], Value: val})
			}
			continue
		}
		req.Header.Set(k, v)
	}
	if head.BodyKnown && head.BodyLen >= 0 {
		req.ContentLength = head.BodyLen
	}
	resp, err := rn.localClient().Do(req)
	if err != nil {
		_ = sendAgentAbort(stream, "upstream_dial", "local service unreachable")
		return
	}
	// No drain: the Transport owns body consumption from here, and it
	// keeps uploading in the background after an early response head.
	// A second reader here would race the Transport for frames and
	// corrupt framing (P0-06): the relay reads an early head
	// concurrently, so an in-flight upload never blocks the response.
	defer resp.Body.Close()
	// Trailers cannot be delivered intact: response headers are already
	// committed upstream by the time trailers exist, and the relay has no
	// trailer channel. Go surfaces announced trailers in resp.Trailer (the
	// "Trailer" header itself is consumed by the transport), so check
	// there. A response announcing trailers is explicitly rejected
	// instead of being silently completed as if whole (E12).
	if len(resp.Trailer) > 0 {
		_ = sendAgentAbort(stream, "unsupported", "response trailers unsupported")
		return
	}
	// No drain: the Transport owns body consumption from here. The stream is
	// single-use; unread frames are discarded at Close. A second reader here
	// would race the Transport and corrupt framing (E04).
	outHeaders := map[string]string{}
	for k, vs := range resp.Header {
		// Set-Cookie uses newline separation: the relay splits it back
		// into separate cookie lines (ResponseHeadersToPublic). Comma
		// joining would merge distinct cookies into one broken line.
		if strings.EqualFold(k, "Set-Cookie") {
			outHeaders[k] = strings.Join(vs, "\n")
			continue
		}
		outHeaders[k] = strings.Join(vs, ", ")
	}
	rh := protocol.ResponseHead{
		Type: "response_head", Proto: protocol.Version, RequestID: head.RequestID,
		Status: resp.StatusCode, Headers: outHeaders,
		BodyKnown: resp.ContentLength >= 0, BodyLen: resp.ContentLength,
	}
	raw, _ := protocol.MarshalJSON(rh)
	if err := protocol.WriteFrame(stream, protocol.FResponseHead, raw); err != nil {
		return
	}
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if werr := protocol.WriteFrame(stream, protocol.FResponseData, buf[:n]); werr != nil {
				return
			}
		}
		// Only a clean EOF completes the body. Any other read error means
		// the backend died mid-body: abort so the relay truncates loudly
		// instead of sending a normal end frame for partial bytes (P0-05).
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = sendAgentAbort(stream, "upstream_body", "local response body failed")
			return
		}
	}
	trailers := map[string]string{}
	for k, vs := range resp.Trailer {
		trailers[k] = strings.Join(vs, ", ")
	}
	endRaw, _ := protocol.MarshalJSON(protocol.EndFrame{Type: "response_end", Trailers: trailers})
	_ = protocol.WriteFrame(stream, protocol.FResponseEnd, endRaw)
}

// streamReader exposes the relay stream as the local request body: DATA
// frames until REQUEST_END (bounded by the relay's 64 MiB cap, E05).
// Any frame error (ABORT, CLOSE, transport failure) ends the body (E06).
type streamReader struct {
	stream net.Conn
	buf    []byte
	done   bool
}

func (sr *streamReader) Read(p []byte) (int, error) {
	for len(sr.buf) == 0 {
		if sr.done {
			return 0, io.EOF
		}
		ft, data, err := protocol.ReadFrame(sr.stream)
		// Transport failures, aborts, and malformed frames are real errors,
		// never a clean end: the local app must see a truncated body as a
		// failure, not as a complete short request (P0-05). Only an
		// explicit REQUEST_END completes the body.
		if err != nil {
			return 0, fmt.Errorf("stream read failed: %w", err)
		}
		switch ft {
		case protocol.FRequestData:
			sr.buf = data
		case protocol.FRequestEnd:
			var end protocol.EndFrame
			_ = json.Unmarshal(data, &end)
			sr.done = true
			return 0, io.EOF
		case protocol.FAbort, protocol.FClose:
			return 0, fmt.Errorf("stream aborted by relay")
		default:
			return 0, fmt.Errorf("unexpected stream frame %d", ft)
		}
	}
	n := copy(p, sr.buf)
	sr.buf = sr.buf[n:]
	return n, nil
}

func sendAgentAbort(stream net.Conn, code, reason string) error {
	raw, _ := protocol.MarshalJSON(protocol.Abort{Type: "abort", Code: code, Reason: reason})
	return protocol.WriteFrame(stream, protocol.FAbort, raw)
}
