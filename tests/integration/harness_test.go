// End-to-end integration: real local app -> agent -> relay -> visitor.
// No mocks on the forwarding path; every byte crosses real code.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"ocliv/internal/agent"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/relay"
	"ocliv/internal/store"
)

// localApp is a real HTTP service with observable endpoints.
type localApp struct {
	t    *testing.T
	hits atomic.Int64
	// postHits counts only POST requests. Forwarded visitor traffic in
	// these tests is always POST; the agent's GET readiness probes must
	// not pollute per-request assertions (e.g. a reconnect re-probe
	// landing mid-test would otherwise look like a forwarded duplicate).
	postHits atomic.Int64
	srv      *httptest.Server
	URL      string
	Port     int
	lnAddr   string
	// Upload observation for /upload-report (P0-05).
	upMu       sync.Mutex
	upBytes    int64
	upCleanEOF bool
	upSawEnd   bool
}

func (a *localApp) uploadOutcome() (bytes int64, cleanEOF, saw bool) {
	a.upMu.Lock()
	defer a.upMu.Unlock()
	return a.upBytes, a.upCleanEOF, a.upSawEnd
}

func startLocalApp(t *testing.T) *localApp {
	t.Helper()
	app := &localApp{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		app.hits.Add(1)
		if r.Method == http.MethodPost {
			app.postHits.Add(1)
		}
		switch r.URL.Path {
		case "/echo":
			body, _ := io.ReadAll(io.LimitReader(r.Body, 70<<20))
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
		case "/headers":
			w.Header().Set("Content-Type", "application/json")
			// relay_auth exposes what the app would see of the relay
			// credential: it must always be empty (C04).
			_ = json.NewEncoder(w).Encode(map[string]string{
				"host":                 r.Host,
				"path":                 r.URL.Path,
				"x-forwarded-host":     r.Header.Get("X-Forwarded-Host"),
				"x-forwarded-proto":    r.Header.Get("X-Forwarded-Proto"),
				"cookie":               r.Header.Get("Cookie"),
				"app_auth":             r.Header.Get("Authorization"),
				"relay_auth":           r.Header.Get("X-Ocliv-Authorization"),
				"origin":               r.Header.Get("Origin"),
				"mcp_protocol_version": r.Header.Get("MCP-Protocol-Version"),
				"mcp_session_id":       r.Header.Get("Mcp-Session-Id"),
			})
		case "/slow":
			time.Sleep(5 * time.Second)
			_, _ = w.Write([]byte("slow done"))
		case "/slow-body":
			// Commits the head immediately, then stalls the body: lets a
			// short lease TTL expire mid-stream (R4).
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			time.Sleep(4 * time.Second)
			_, _ = w.Write([]byte("late body"))
		case "/multicookie":
			w.Header().Add("Set-Cookie", "a=1; Path=/")
			w.Header().Add("Set-Cookie", "b=2; Path=/")
			_, _ = w.Write([]byte("cookies"))
		case "/trailers":
			w.Header().Set("Trailer", "X-Checksum")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial-body"))
			w.Header().Set("X-Checksum", "abc123")
			// Trailer values flush at handler return.
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "data: %d\n\n", i)
				fl.Flush()
				time.Sleep(50 * time.Millisecond)
			}
		case "/big":
			w.Header().Set("Content-Type", "application/octet-stream")
			chunk := bytes.Repeat([]byte("x"), 32*1024)
			for i := 0; i < 160; i++ { // 5 MiB
				_, _ = w.Write(chunk)
			}
		case "/die-mid-body":
			// Streams an unbounded (chunked) body but dies after 100 KiB:
			// the tunnel must not report the truncated body as cleanly
			// completed (P0-05). A normal handler return would be a clean
			// chunked end, so the connection is hijacked and killed
			// mid-body to simulate a backend crash.
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"+
				"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
			_, _ = fmt.Fprintf(rw, "19000\r\n")
			_, _ = rw.Write(bytes.Repeat([]byte("y"), 100*1024))
			_, _ = rw.Write([]byte("\r\n"))
			_ = rw.Flush()
			_ = conn.Close()
		case "/reject-early":
			// Rejects a large upload without reading a single body byte.
			// The tunnel must surface the 413, not block or substitute a
			// 502 (P0-06).
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		case "/hold-upload":
			// Blocks consuming the request body until the visitor closes
			// it: lets a test hold N streams open and release them
			// deterministically by closing the client-side pipes.
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write([]byte("released"))
		case "/accept-then-hang":
			// Consumes the full upload, then never produces response
			// headers: the tunnel must time out the head wait instead of
			// hanging. Returns promptly on client/relay teardown via the
			// request context so the fixture never stalls test shutdown.
			_, _ = io.ReadAll(io.LimitReader(r.Body, 70<<20))
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		case "/stream-while-ignoring":
			// Streams a 2 MiB response while ignoring the request upload.
			// With a large concurrent upload this deadlocks a serialized
			// tunnel in both directions (P0-06).
			w.Header().Set("Content-Type", "application/octet-stream")
			fl, _ := w.(http.Flusher)
			chunk := bytes.Repeat([]byte("z"), 32*1024)
			for i := 0; i < 64; i++ {
				_, _ = w.Write(chunk)
				if fl != nil {
					fl.Flush()
				}
			}
		case "/answer-without-reading":
			// Answers 200 with a tiny complete body without consuming a
			// single request-body byte. Lets a test race a fully early
			// response against a slow/failing upload: the tunnel must not
			// report the response as cleanly complete when the upload
			// outcome turns out to be a failure (Finding 5).
			_, _ = w.Write([]byte("early-ok"))
		case "/upload-report":
			// Records how the request body ended: clean EOF vs error, and
			// how many bytes arrived (P0-05).
			body, err := io.ReadAll(io.LimitReader(r.Body, 70<<20))
			clean := err == nil
			app.upMu.Lock()
			app.upBytes = int64(len(body))
			app.upCleanEOF = clean
			app.upSawEnd = true
			app.upMu.Unlock()
			if err != nil {
				http.Error(w, "body read failed", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("ok"))
		case "/mcp":
			// Minimal JSON-RPC shape: proves an MCP-style HTTP API rides
			// the ordinary protected forwarding path (Phase 6).
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var in struct {
				JSONRPC string `json:"jsonrpc"`
				ID      any    `json:"id"`
				Method  string `json:"method"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Method == "" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": in.ID, "result": map[string]any{"tools": []string{}},
				// Observed headers prove the header boundary through
				// any ingress (wildcard or path route): the app
				// bearer arrives byte-identical for upstream
				// validation while Ocliv's own credential never
				// reaches the child (C04, P0-B).
				"observed": map[string]any{
					"app_auth":             r.Header.Get("Authorization"),
					"relay_auth":           r.Header.Get("X-Ocliv-Authorization"),
					"mcp_protocol_version": r.Header.Get("MCP-Protocol-Version"),
				},
			})
		case "/ws":
			// The agent forwards the visitor's public Origin unchanged so
			// the local app can apply its own WS origin policy; this test
			// echo app explicitly allows tunnel origins.
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
			if err != nil {
				return
			}
			c.SetReadLimit(4 << 20)
			defer c.Close(websocket.StatusNormalClosure, "")
			for {
				typ, msg, err := c.Read(r.Context())
				if err != nil {
					return
				}
				if err := c.Write(r.Context(), typ, msg); err != nil {
					return
				}
			}
		case "/ws-immediate":
			// Pushes a server message in the SAME TCP write as the 101
			// handshake response, before reading anything: bytes the
			// agent's handshake reader buffers ahead must still reach
			// the visitor (P1-10). Raw framing keeps the coalescing
			// deterministic; a WS library may flush headers separately.
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			// The server already consumed the handshake request before
			// invoking this handler; only the parsed headers are usable.
			key := r.Header.Get("Sec-WebSocket-Key")
			h := sha1.New()
			_, _ = h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			var out bytes.Buffer
			fmt.Fprintf(&out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
				"Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
				base64.StdEncoding.EncodeToString(h.Sum(nil)))
			msg := []byte("immediate-hello")
			out.Write([]byte{0x81, byte(len(msg))})
			out.Write(msg)
			if _, err := rw.Write(out.Bytes()); err != nil {
				return
			}
			_ = rw.Flush()
			// Minimal client-frame loop: answer close/ping so the
			// visitor's close handshake completes promptly, skip
			// anything else until the visitor goes away.
			hdr := make([]byte, 2)
			for {
				_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				if _, err := io.ReadFull(conn, hdr); err != nil {
					return
				}
				op := hdr[0] & 0x0f
				ln := int(hdr[1] & 0x7f)
				switch ln {
				case 126:
					var ext [2]byte
					if _, err := io.ReadFull(conn, ext[:]); err != nil {
						return
					}
					ln = int(ext[0])<<8 | int(ext[1])
				case 127:
					var ext [8]byte
					if _, err := io.ReadFull(conn, ext[:]); err != nil {
						return
					}
					ln = 0
					for _, b := range ext {
						ln = ln<<8 | int(b)
					}
				}
				var mask [4]byte
				if hdr[1]&0x80 != 0 {
					if _, err := io.ReadFull(conn, mask[:]); err != nil {
						return
					}
				}
				if _, err := io.CopyN(io.Discard, conn, int64(ln)); err != nil {
					return
				}
				switch op {
				case 0x8:
					_, _ = conn.Write([]byte{0x88, 0x00})
					return
				case 0x9:
					_, _ = conn.Write([]byte{0x8a, 0x00})
				}
			}
		case "/ws-sub":
			// Selects the subprotocol named by ?select= unconditionally,
			// even when the visitor never offered it: the tunnel must
			// refuse to complete such an upgrade (P1-10).
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			key := r.Header.Get("Sec-WebSocket-Key")
			h := sha1.New()
			_, _ = h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			var out bytes.Buffer
			fmt.Fprintf(&out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
				"Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n",
				base64.StdEncoding.EncodeToString(h.Sum(nil)))
			if sel := r.URL.Query().Get("select"); sel != "" {
				fmt.Fprintf(&out, "Sec-WebSocket-Protocol: %s\r\n", sel)
			}
			out.WriteString("\r\n")
			if _, err := rw.Write(out.Bytes()); err != nil {
				return
			}
			_ = rw.Flush()
			drain := make([]byte, 4096)
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			_, _ = conn.Read(drain)
		default:
			_, _ = w.Write([]byte("hello"))
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second},
	}
	s.Start()
	port := s.Listener.Addr().(*net.TCPAddr).Port
	app.srv = s
	app.URL = s.URL
	app.Port = port
	app.lnAddr = fmt.Sprintf("127.0.0.1:%d", port)
	return app
}

func (a *localApp) Hits() int64 { return a.hits.Load() }

// harness wires relay + enrolled agent + attached lease.
type harness struct {
	t        *testing.T
	relaySrv *httptest.Server
	relay    *relay.Server
	db       *store.DB
	dir      string
	// relayHost is the authority agent control paths must present.
	// The test server dials loopback, but every agent-path request
	// carries this Host — exactly like Caddy-forwarded production
	// traffic, which the relay authorizes by Host, never by peer.
	relayHost string
	agentKey  *identity.KeyPair
	keyID     string
	agentDir  string
	lastOpts  config.Agent
	attached  agent.Attached
	cancel    context.CancelFunc
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// handshakeTransport dials the loopback test server while presenting the
// configured relay authority on every agent control request. Production
// agents dial the public relay address directly, so its Host is already
// the relay authority; the harness needs this split to exercise the same
// strict boundary over loopback.
func (h *harness) handshakeTransport() http.RoundTripper {
	host := h.relayHost
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		r2 := req.Clone(req.Context())
		r2.Host = host
		return http.DefaultTransport.RoundTrip(r2)
	})
}

// enrollClient posts enrollment/challenge requests with the relay
// authority, dialing the loopback test server underneath.
func (h *harness) enrollClient() *http.Client {
	return &http.Client{Transport: h.handshakeTransport(), Timeout: 60 * time.Second}
}

// enrollKey enrolls a fresh agent key, returning keypair + key id.
func (h *harness) enrollKey(t *testing.T, tenant string) (*identity.KeyPair, string) {
	t.Helper()
	code, err := relay.IssueEnrollmentCode(h.db, tenant, time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"code": code, "public_key": base64.StdEncoding.EncodeToString(k.Public()),
	})
	resp, err := h.enrollClient().Post(h.relaySrv.URL+"/v1/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status %d", resp.StatusCode)
	}
	return k, "key-" + string(k.ID())
}

// mgmt performs a signed agent management call for the attached lease.
func (h *harness) mgmt(t *testing.T, k *identity.KeyPair, keyID, method, action string) (int, []byte) {
	t.Helper()
	ts := time.Now().UTC()
	path := "/v1/agent/lease/" + h.attached.LeaseID + "/" + action
	nonce, err := agent.MgmtNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(k.Private(), agent.MgmtMessage(keyID, method, path, ts, nonce))
	req, _ := http.NewRequest(method, h.relaySrv.URL+path, nil)
	req.Host = h.relayHost
	req.Header.Set("X-Ocliv-Key", keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, raw
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessNS(t, "t.example.test", "relay.example.test")
}

// newHarnessNS builds the same harness against explicit authorities (e.g.
// the staging t.ocliv.test / relay.ocliv.test pair) instead of the default
// test namespace. An optional fourth argument sets the single-host MCP
// external hostname (P0-A path-route ingress); absent means the feature
// is off, exactly as in production relays without it configured.
func newHarnessNS(t *testing.T, namespace, relayHost string, mcpHost ...string) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "ocliv-relay-*")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	mcpExternal := ""
	if len(mcpHost) > 0 {
		mcpExternal = mcpHost[0]
	}
	srv, err := relay.New(relay.Options{DB: db, Namespace: namespace, RelayHost: relayHost, MCPExternalHost: mcpExternal})
	if err != nil {
		t.Fatal(err)
	}
	rs := httptest.NewServer(srv.Handler())
	h := &harness{t: t, relaySrv: rs, relay: srv, db: db, dir: dir, relayHost: relayHost}
	code, err := relay.IssueEnrollmentCode(db, "tenant-test", time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	h.agentKey = k
	h.keyID = "key-" + string(k.ID())
	body, _ := json.Marshal(map[string]string{
		"code": code, "public_key": base64.StdEncoding.EncodeToString(k.Public()),
	})
	resp, err := h.enrollClient().Post(rs.URL+"/v1/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status %d", resp.StatusCode)
	}
	return h
}

// startAgent connects one agent to localPort and waits for attach.
func (h *harness) startAgent(t *testing.T, localPort int) {
	t.Helper()
	h.startAgentOpts(t, localPort, config.Agent{})
}

// startAgentOpts connects with extra agent options (public mode, names).
func (h *harness) startAgentOpts(t *testing.T, localPort int, extra config.Agent) {
	t.Helper()
	agentDir, err := os.MkdirTemp("", "ocliv-agent-*")
	if err != nil {
		t.Fatal(err)
	}
	h.agentDir = agentDir
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	cfg := config.Agent{RelayURL: h.relaySrv.URL, Port: localPort, DataDir: agentDir,
		Public: extra.Public, AccessMode: extra.AccessMode, Name: extra.Name, TTLSeconds: extra.TTLSeconds}
	h.lastOpts = extra
	h.runAgent(t, ctx, cfg, agentDir, localPort)
	t.Cleanup(cancel)
}

// runAgent launches one agent process image and waits for its attach.
func (h *harness) runAgent(t *testing.T, ctx context.Context, cfg config.Agent, agentDir string, localPort int) {
	t.Helper()
	rn := &agent.Runner{
		Cfg:                cfg,
		Key:                h.agentKey,
		KeyID:              h.keyID,
		Target:             fmt.Sprintf("127.0.0.1:%d", localPort),
		HandshakeTransport: h.handshakeTransport(),
	}
	attached := make(chan agent.Attached, 4)
	rn.OnAttach = func(a agent.Attached) { attached <- a }
	go func() { _ = rn.Run(ctx) }()
	select {
	case a := <-attached:
		h.attached = a
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not attach")
	}
}

// restartAgent stops the running agent image and starts a fresh one reusing
// the same data dir, i.e. attempting resume of the same lease (F04). This is
// the deterministic way to exercise reconnect-after-restart: closing an
// httptest listener cannot break already-hijacked WebSocket connections, so
// the old image would otherwise never notice a simulated crash.
func (h *harness) restartAgent(t *testing.T, localPort int) {
	t.Helper()
	if h.cancel != nil {
		h.cancel()
		time.Sleep(300 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	extra := h.lastOpts
	cfg := config.Agent{RelayURL: h.relaySrv.URL, Port: localPort, DataDir: h.agentDir,
		Public: extra.Public, AccessMode: extra.AccessMode, Name: extra.Name, TTLSeconds: extra.TTLSeconds}
	h.runAgent(t, ctx, cfg, h.agentDir, localPort)
	t.Cleanup(cancel)
}

func (h *harness) host() string {
	return h.attached.Hostname // already a full name under the namespace
}

// visitorClient never follows redirects: auth redirects are assertions.
var visitorClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 60 * time.Second,
}

// visitorReq issues a request with an explicit Host (public routing).
func (h *harness) visitorReq(t *testing.T, method, path string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	url := h.relaySrv.URL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = h.host()
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(io.LimitReader(r, 80<<20))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
