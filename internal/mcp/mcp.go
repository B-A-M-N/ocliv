// Package mcp adapts an operator-selected stdio MCP server to loopback
// HTTP so it can be exposed through Ocliv's ordinary secure forwarding
// path (V1.1, invariants M07/M08/M13).
//
// Security contract:
//   - The child command is chosen only by the local operator via argv.
//     Remote clients can never select executables, arguments, working
//     directories, or environment variables (M07).
//   - No shell is ever involved: the executable is resolved once with
//     LookPath at startup and spawned directly (M07).
//   - The child inherits a scrubbed minimal environment, never the
//     operator's ambient credentials (M08).
//   - The HTTP listener binds loopback only (M08).
//   - Requests are bounded in size, concurrency, and lifetime (M13).
//     Waits for replies are independent per call — only stdin writes
//     serialize — so MaxConcurrent in-flight calls genuinely progress
//     together; a wedged child still fails closed via timeout+retire.
//   - The adapter is protocol-version transparent: initialize version
//     negotiation happens end-to-end between the MCP client and the
//     child. The adapter never rewrites versioned semantics; it only
//     translates transport outcomes (202 for accepted notifications,
//     id-correlated replies, explicit failures).
//   - Child output is treated as untrusted protocol input: oversize or
//     malformed output is rejected, never forwarded blindly.
//
// Ownership is split deliberately so neither type becomes a god object:
//   - childProc owns exactly one OS process: its pipes, serialized
//     exchanges, and kill/wait lifecycle. It knows nothing about HTTP.
//   - Adapter owns the loopback HTTP front: method checks, body caps,
//     concurrency semaphore, listener lifecycle, and broken fail-closed
//     state. It never touches process handles directly.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults bound an adapter that the operator does not tune explicitly.
const (
	DefaultMaxBodyBytes = 1 << 20 // 1 MiB per JSON-RPC message
	DefaultMaxConns     = 8       // concurrent in-flight stdio round trips
	DefaultMaxSessions  = 8       // independent stdio child processes
	DefaultTimeout      = 30 * time.Second
	DefaultSessionIdle  = 30 * time.Minute
)

// errChildTimeout marks a wedged child. The caller kills the child,
// maps it to 504 and retires the adapter; every other exchange error
// is a 502.
var errChildTimeout = errors.New("mcp child timed out")
var errChildUnavailable = errors.New("mcp child unavailable")
var errChildCancelled = errors.New("mcp child cancelled during notification write")

// errDuplicateID marks a second in-flight call reusing an outstanding
// request id. JSON-RPC ids must be unique per peer; answering 400 keeps
// a confused client from stealing another call's reply.
var errDuplicateID = errors.New("mcp duplicate request id in flight")

// Options selects the child process. Every field is operator-supplied via
// local argv; none of them may originate from a remote client.
type Options struct {
	// Command is the stdio MCP server executable. It is resolved with
	// LookPath once at startup and then pinned; shell metacharacters in
	// it are literal path characters, never interpreted.
	Command string
	// Args are fixed operator-supplied arguments.
	Args []string
	// Dir is the child's working directory. Empty means the relay's own
	// directory; a remote client can never override it.
	Dir string
	// Env carries extra KEY=VALUE entries for the child. Entries without
	// '=' are rejected. The ambient process environment is never inherited.
	Env []string
	// MaxBodyBytes caps one request or response message. Zero selects
	// DefaultMaxBodyBytes. Negative rejects everything.
	MaxBodyBytes int64
	// MaxConcurrent caps in-flight round trips; excess gets 503. Zero
	// selects DefaultMaxConns.
	MaxConcurrent int
	// Timeout bounds one stdio round trip. Zero selects DefaultTimeout.
	Timeout time.Duration
	// MultiClientSessions enables Streamable HTTP sessions backed by one
	// isolated child process per MCP client. Local `mcp expose` keeps the
	// legacy single-child behavior.
	MultiClientSessions bool
	// MaxSessions bounds child processes in session mode. Zero selects
	// DefaultMaxSessions.
	MaxSessions int
	// SessionIdleTimeout bounds abandoned session lifetime. Zero selects
	// DefaultSessionIdle.
	SessionIdleTimeout time.Duration
}

// childProc owns one spawned stdio MCP server: its pipes, the mutex that
// serializes whole request/reply exchanges, and its kill/wait lifecycle.
// It knows nothing about HTTP; concurrent callers are serialized so they
// cannot interleave frames on the child's pipes (M09).
type childProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	// mu serializes whole exchanges. procMu guards proc independently:
	// the timeout path must kill a wedged child while an exchange holds
	// mu across a blocking read; sharing one mutex would deadlock the
	// killer until the child exits on its own.
	mu     sync.Mutex
	procMu sync.Mutex
	proc   *os.Process
}

// startChild resolves nothing — path must already be pinned by the caller —
// and spawns the child with a scrubbed environment. Stderr stays nil (the
// null device) so unbounded child logs cannot exhaust relay memory (M13).
func startChild(ctx context.Context, path string, args []string, dir string, env []string) (*childProc, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	// Scrubbed minimal environment: the child never inherits ambient
	// operator credentials (M08). Only PATH plus explicit entries.
	cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp: start %q: %w", path, err)
	}
	c := &childProc{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
	c.procMu.Lock()
	c.proc = cmd.Process
	c.procMu.Unlock()
	return c, nil
}

// kill terminates the child without touching exchange serialization.
func (c *childProc) kill() {
	c.procMu.Lock()
	proc := c.proc
	c.proc = nil
	stdin := c.stdin
	c.procMu.Unlock()
	// Kill first. Closing the parent pipe while another goroutine is
	// blocked writing to a child that never reads can itself stall; the
	// process exit releases the pipe before we close our endpoint.
	if proc != nil {
		_ = proc.Kill()
	}
	if stdin != nil {
		_ = stdin.Close()
	}
}

// wait reaps the child. Call after kill, or after natural exit.
func (c *childProc) wait() {
	c.mu.Lock()
	cmd := c.cmd
	c.cmd = nil
	c.mu.Unlock()
	if cmd != nil {
		_ = cmd.Wait()
	}
}

// Adapter serves an operator-selected stdio MCP server over loopback HTTP.
// Legacy mode shares one child; session mode creates one isolated child per
// Streamable HTTP session. No request content can select a different
// command, directory, or environment: those were pinned at startup (M07).
type Adapter struct {
	child       *childProc
	coord       *coordinator
	path        string // pinned absolute executable, resolved once in New
	args        []string
	dir         string
	env         []string
	maxBody     int64
	timeout     time.Duration
	sem         chan struct{}
	multiClient bool
	maxSessions int
	sessionIdle time.Duration
	sessionMu   sync.Mutex
	sessions    map[string]*clientSession
	startCtx    context.Context

	ln  net.Listener
	srv *http.Server

	spawned       atomic.Int32
	nextRequestID atomic.Uint64
	broken        atomic.Bool
	closed        atomic.Bool
	done          chan struct{}
}

// New validates options and resolves the executable. It does not start
// any process.
func New(o Options) (*Adapter, error) {
	if strings.TrimSpace(o.Command) == "" {
		return nil, fmt.Errorf("mcp: no command selected")
	}
	// Resolve once, locally, at startup. A command containing spaces or
	// shell metacharacters resolves as a literal path and fails here
	// instead of being interpreted (M07).
	path, err := exec.LookPath(o.Command)
	if err != nil {
		return nil, fmt.Errorf("mcp: resolve %q: %w", o.Command, err)
	}
	if o.Dir != "" {
		fi, err := os.Stat(o.Dir)
		if err != nil {
			return nil, fmt.Errorf("mcp: workdir: %w", err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("mcp: workdir %q is not a directory", o.Dir)
		}
	}
	maxBody := o.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	maxConns := o.MaxConcurrent
	if maxConns == 0 {
		maxConns = DefaultMaxConns
	}
	if maxConns < 0 {
		return nil, fmt.Errorf("mcp: negative concurrency")
	}
	maxSessions := o.MaxSessions
	if maxSessions == 0 {
		maxSessions = DefaultMaxSessions
	}
	if maxSessions < 1 {
		return nil, fmt.Errorf("mcp: max sessions must be positive")
	}
	sessionIdle := o.SessionIdleTimeout
	if sessionIdle == 0 {
		sessionIdle = DefaultSessionIdle
	}
	if sessionIdle < 0 {
		return nil, fmt.Errorf("mcp: negative session idle timeout")
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("mcp: non-positive timeout")
	}
	for _, kv := range o.Env {
		if !strings.Contains(kv, "=") {
			return nil, fmt.Errorf("mcp: env entry %q is not KEY=VALUE", kv)
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return &Adapter{
		path:        path,
		args:        append([]string(nil), o.Args...),
		dir:         o.Dir,
		env:         append([]string(nil), o.Env...),
		maxBody:     maxBody,
		timeout:     timeout,
		sem:         make(chan struct{}, maxConns),
		multiClient: o.MultiClientSessions,
		maxSessions: maxSessions,
		sessionIdle: sessionIdle,
		sessions:    make(map[string]*clientSession),
		done:        make(chan struct{}),
	}, nil
}

// Start serves on a loopback-only listener. Legacy mode starts one pinned
// child here; session mode starts one pinned child for each accepted
// initialize request. Every child dies with ctx. Process parameters were
// pinned in New; Start takes no command, directory, or environment input.
func (a *Adapter) Start(ctx context.Context) error {
	if a.multiClient {
		return a.startSessionServer(ctx)
	}
	c, err := startChild(ctx, a.path, a.args, a.dir, a.env)
	if err != nil {
		return err
	}
	a.child = c
	// The reader starts with the child: every stdout line is framed
	// and dispatched by id from here on. A dead child fails pending
	// calls and retires the adapter fail-closed.
	a.coord = runCoordinator(c, a.maxBody, func() { a.broken.Store(true) })
	a.spawned.Add(1)

	// Loopback only: the adapter is reachable from this host, and Ocliv's
	// ordinary tunnel path carries it further only after visitor
	// authorization (M08/M11).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.kill()
		c.wait()
		return fmt.Errorf("mcp: loopback listen: %w", err)
	}
	a.ln = ln
	a.srv = &http.Server{Handler: a, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = a.srv.Serve(ln)
	}()
	return nil
}

// Addr returns the loopback address served, or nil before Start.
func (a *Adapter) Addr() net.Addr {
	if a.ln == nil {
		return nil
	}
	return a.ln.Addr()
}

// Spawned reports how many child processes were started. Legacy mode starts
// one at Start; session mode starts one per accepted initialize, within the
// configured session cap. Remote requests cannot select process parameters.
func (a *Adapter) Spawned() int32 { return a.spawned.Load() }

// SessionCount reports currently active Streamable HTTP client sessions.
// It returns zero for the legacy single-child adapter.
func (a *Adapter) SessionCount() int {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	return len(a.sessions)
}

// Close stops the HTTP listener and terminates every owned child. Kill precedes
// any exchange serialization so shutdown cannot hang behind a wedged
// child holding the round-trip mutex.
func (a *Adapter) Close() error {
	if !a.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(a.done)
	var err error
	if a.srv != nil {
		err = a.srv.Close()
	}
	if a.multiClient {
		a.sessionMu.Lock()
		all := make([]*clientSession, 0, len(a.sessions))
		for _, s := range a.sessions {
			all = append(all, s)
		}
		a.sessionMu.Unlock()
		for _, s := range all {
			s.shutdown()
		}
	}
	if a.child != nil {
		a.child.kill()
		a.child.wait()
	}
	return err
}

// ServeHTTP forwards one POST body as one stdio message and returns the
// single reply line.
func (a *Adapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.multiClient {
		a.serveSessionHTTP(w, r)
		return
	}
	if a.broken.Load() {
		http.Error(w, "mcp adapter broken", http.StatusServiceUnavailable)
		return
	}
	if a.child == nil {
		http.Error(w, "mcp adapter not started", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// One JSON-RPC endpoint, two local spellings: "/" is the loopback
	// root `mcp expose` prints for local development, and "/mcp" is the
	// backend path the relay's MCP route-surface policy forwards. Any
	// other path is a routing error and fails closed before the child
	// is touched — the child must never see requests addressed
	// elsewhere (P0-3: one published endpoint, no sibling paths).
	if p := r.URL.EscapedPath(); p != "/" && p != "/mcp" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		http.Error(w, "mcp concurrency exhausted", http.StatusServiceUnavailable)
		return
	}
	if a.maxBody >= 0 && r.ContentLength > a.maxBody {
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, a.maxBody+1))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > a.maxBody {
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		body = append(body, '\n')
	}
	// Decode the JSON-RPC envelope before touching the child. A
	// notification (no id) has no reply by definition: route it
	// through the write-only path and answer 202 instead of blocking
	// for an output line that must never come. Anything that is not
	// a JSON-RPC call or notification is rejected before the child
	// ever sees it.
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.JSONRPC != "2.0" || env.Method == "" {
		http.Error(w, "not a JSON-RPC 2.0 message", http.StatusBadRequest)
		return
	}
	if len(env.ID) == 0 {
		if err := a.coord.notify(r.Context(), body, a.timeout); err != nil {
			if errors.Is(err, errChildCancelled) {
				a.broken.Store(true)
				return // caller is gone; notify retired the blocked child
			}
			if r.Context().Err() != nil {
				return // caller left before the notification write began
			}
			a.broken.Store(true)
			a.child.kill()
			if errors.Is(err, errChildTimeout) {
				http.Error(w, "mcp child timed out; adapter retired", http.StatusGatewayTimeout)
				return
			}
			http.Error(w, "mcp child exchange failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	_, ok := idKey(env.ID)
	if !ok {
		http.Error(w, "request id must be a string or number", http.StatusBadRequest)
		return
	}
	internalID, _ := json.Marshal(fmt.Sprintf("ocliv-%d", a.nextRequestID.Add(1)))
	internalKey, _ := idKey(internalID)
	internalBody, err := replaceJSONRPCID(body, internalID)
	if err != nil {
		http.Error(w, "invalid JSON-RPC request id", http.StatusBadRequest)
		return
	}
	line, err := a.coord.call(r.Context(), internalBody, internalKey, a.timeout)
	if err != nil {
		if errors.Is(err, errChildUnavailable) {
			a.broken.Store(true)
			http.Error(w, "mcp adapter broken", http.StatusServiceUnavailable)
			return
		}
		if errors.Is(err, errChildTimeout) {
			a.child.kill()
			a.broken.Store(true)
			http.Error(w, "mcp child timed out; adapter retired", http.StatusGatewayTimeout)
			return
		}
		if r.Context().Err() != nil {
			return // caller gone; nothing to report to
		}
		a.broken.Store(true)
		a.child.kill()
		http.Error(w, "mcp child exchange failed", http.StatusBadGateway)
		return
	}
	line, err = replaceJSONRPCID(line, env.ID)
	if err != nil {
		a.broken.Store(true)
		a.child.kill()
		http.Error(w, "mcp child returned an invalid JSON-RPC reply", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(line)
}

// replaceJSONRPCID gives every child round trip a private internal ID, then
// restores the caller's original ID in the HTTP reply. This keeps two MCP
// clients that reuse the same JSON-RPC ID from colliding on the shared stdio
// child while preserving each client's wire contract.
func replaceJSONRPCID(message, id json.RawMessage) ([]byte, error) {
	if len(id) == 0 || !json.Valid(id) {
		return nil, fmt.Errorf("missing JSON-RPC id")
	}
	dec := json.NewDecoder(bytes.NewReader(message))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("JSON-RPC message is not an object")
	}
	start, end := -1, -1
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("JSON-RPC object key is not a string")
		}
		afterKey := int(dec.InputOffset())
		colon := afterKey
		for colon < len(message) && (message[colon] == ' ' || message[colon] == '\t' || message[colon] == '\r' || message[colon] == '\n') {
			colon++
		}
		if colon >= len(message) || message[colon] != ':' {
			return nil, fmt.Errorf("malformed JSON-RPC object")
		}
		valueStart := colon + 1
		for valueStart < len(message) && (message[valueStart] == ' ' || message[valueStart] == '\t' || message[valueStart] == '\r' || message[valueStart] == '\n') {
			valueStart++
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if key == "id" {
			if start >= 0 {
				return nil, fmt.Errorf("duplicate JSON-RPC id field")
			}
			start, end = valueStart, int(dec.InputOffset())
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if start < 0 || end < start {
		return nil, fmt.Errorf("missing JSON-RPC id")
	}
	result := make([]byte, 0, len(message)-end+start+len(id)+1)
	result = append(result, message[:start]...)
	result = append(result, id...)
	result = append(result, message[end:]...)
	if len(result) == 0 || result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result, nil
}
