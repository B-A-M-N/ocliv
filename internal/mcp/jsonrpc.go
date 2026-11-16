package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// fileWithDeadline exposes the write deadline of pipe-backed stdin.
// StdinPipe always wraps an *os.File; anything else fails closed.
func fileWithDeadline(w io.Writer) (*os.File, bool) {
	f, ok := w.(*os.File)
	return f, ok
}

// coordinator matches child stdout lines to the requests that caused
// them by JSON-RPC id. The old next-line-is-the-reply assumption is
// wrong for real MCP servers: child-generated notifications can arrive
// before a request's actual reply, and a late reply to an already-timed
// -out call must never be mistaken for the next call's answer.
//
// Ownership:
//   - exactly one reader goroutine reads stdout; nobody else reads it.
//   - stdin writes serialize on wmu; waits for replies do not hold wmu,
//     so independent calls progress without head-of-line mutex blocking.
//   - a cancelled or timed-out caller drops its waiter; a late reply
//     then finds no waiter and is discarded instead of poisoning a
//     later call.
type coordinator struct {
	child *childProc
	wmu   chan struct{}

	mu      sync.Mutex
	pending map[string]chan coordResult
	// events carries child-originated requests and notifications to the
	// owning Streamable HTTP session. It is nil for the legacy adapter.
	events chan []byte
	// serverRequests contains child-originated request IDs awaiting the
	// corresponding client response on this same session.
	serverRequests map[string]struct{}
	closed         bool

	maxBody int64
	onDeath func()
}

type coordResult struct {
	line []byte
	err  error
}

// idKey normalizes a raw JSON-RPC id to a map key. Numbers and strings
// are distinct namespaces in JSON-RPC; the raw encoding preserves that.
func idKey(raw json.RawMessage) (string, bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	switch v.(type) {
	case string, float64:
		return string(raw), true
	}
	return "", false
}

// runCoordinator starts the reader and returns a coordinator bound to
// the child's lifetime. onDeath fires once when the reader observes
// child EOF or a fatal read error.
func runCoordinator(c *childProc, maxBody int64, onDeath func()) *coordinator {
	co := &coordinator{
		child:   c,
		wmu:     make(chan struct{}, 1),
		pending: make(map[string]chan coordResult),
		maxBody: maxBody,
		onDeath: onDeath,
	}
	go co.readLoop(c.stdout)
	return co
}

// runSessionCoordinator preserves server-originated MCP requests and
// notifications in a bounded queue owned by one client session.
func runSessionCoordinator(c *childProc, maxBody int64, eventQueue int, onDeath func()) *coordinator {
	co := &coordinator{
		child:          c,
		wmu:            make(chan struct{}, 1),
		pending:        make(map[string]chan coordResult),
		events:         make(chan []byte, eventQueue),
		serverRequests: make(map[string]struct{}),
		maxBody:        maxBody,
		onDeath:        onDeath,
	}
	go co.readLoop(c.stdout)
	return co
}

// readLoop owns stdout. Each line is framed, measured, and dispatched
// by id; lines without a deliverable id (notifications, garbage, late
// replies to dropped waiters) are discarded, never misattributed.
func (co *coordinator) readLoop(r *bufio.Reader) {
	fail := func(err error) {
		// This callback is the adapter retirement linearization point. Mark
		// the HTTP surface unavailable before making the coordinator reject
		// calls or waking existing waiters.
		if co.onDeath != nil {
			co.onDeath()
		}
		co.mu.Lock()
		if co.closed {
			co.mu.Unlock()
			return
		}
		co.closed = true
		waiters := co.pending
		co.pending = make(map[string]chan coordResult)
		co.mu.Unlock()
		for _, w := range waiters {
			w <- coordResult{err: err}
		}
	}
	var buf []byte
	for {
		frag, err := r.ReadSlice('\n')
		if int64(len(buf))+int64(len(frag)) > co.maxBody {
			fail(fmt.Errorf("child output exceeds %d bytes", co.maxBody))
			return
		}
		buf = append(buf, frag...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && len(frag) != 0 {
				// Unterminated tail: untrusted output, never a reply.
				buf = nil
				continue
			}
			fail(fmt.Errorf("mcp child output ended: %w", err))
			return
		}
		line := buf
		buf = nil
		var env struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
		}
		if err := json.Unmarshal(line, &env); err != nil || env.JSONRPC != "2.0" {
			continue // unparsable child chatter is never forwarded
		}
		if env.Method != "" && co.events != nil {
			var key string
			if len(env.ID) != 0 {
				var ok bool
				key, ok = idKey(env.ID)
				if !ok {
					fail(fmt.Errorf("mcp child sent a request with invalid id"))
					return
				}
				co.mu.Lock()
				if _, exists := co.serverRequests[key]; exists {
					co.mu.Unlock()
					fail(fmt.Errorf("mcp child reused an outstanding server request id"))
					return
				}
				co.serverRequests[key] = struct{}{}
				co.mu.Unlock()
			}
			select {
			case co.events <- append([]byte(nil), line...):
			default:
				fail(fmt.Errorf("mcp session notification queue full"))
				return
			}
			continue
		}
		if len(env.ID) == 0 {
			continue // malformed or non-deliverable child message
		}
		key, ok := idKey(env.ID)
		if !ok {
			continue // null id or non-scalar id: not deliverable
		}
		co.mu.Lock()
		w, found := co.pending[key]
		if found {
			delete(co.pending, key)
		}
		co.mu.Unlock()
		if found {
			w <- coordResult{line: line}
		}
		// else: late reply to a dropped waiter — discard, never reuse.
	}
}

// reply forwards a response to a child-originated request. IDs are
// session-local and accepted once, only after the child emitted them.
func (co *coordinator) reply(ctx context.Context, msg []byte, id string, timeout time.Duration) error {
	co.mu.Lock()
	if co.closed {
		co.mu.Unlock()
		return errChildUnavailable
	}
	if _, ok := co.serverRequests[id]; !ok {
		co.mu.Unlock()
		return fmt.Errorf("mcp response does not match a pending server request")
	}
	delete(co.serverRequests, id)
	co.mu.Unlock()
	return co.notify(ctx, msg, timeout)
}

// call writes one request and waits for the reply carrying the same id.
// The HTTP caller's context cancels the wait without disturbing the
// child or other in-flight calls; the timeout still fails closed and
// reports errChildTimeout so the adapter can retire a wedged child.
func (co *coordinator) call(ctx context.Context, msg []byte, id string, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	timeoutT := time.NewTimer(timeout)
	defer timeoutT.Stop()
	waiter := make(chan coordResult, 1)
	co.mu.Lock()
	if co.closed {
		co.mu.Unlock()
		return nil, errChildUnavailable
	}
	if _, dup := co.pending[id]; dup {
		co.mu.Unlock()
		return nil, errDuplicateID
	}
	co.pending[id] = waiter
	co.mu.Unlock()
	drop := func() {
		co.mu.Lock()
		if w, ok := co.pending[id]; ok && w == waiter {
			delete(co.pending, id)
		}
		co.mu.Unlock()
	}
	select {
	case co.wmu <- struct{}{}:
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	case <-timeoutT.C:
		drop()
		return nil, errChildTimeout
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	pipe, ok := fileWithDeadline(co.child.stdin)
	if !ok {
		<-co.wmu
		drop()
		return nil, fmt.Errorf("mcp child stdin does not support deadlines")
	}
	_ = pipe.SetWriteDeadline(deadline)
	written := make(chan error, 1)
	go func() {
		_, err := co.child.stdin.Write(msg)
		written <- err
	}()
	select {
	case werr := <-written:
		_ = pipe.SetWriteDeadline(time.Time{})
		<-co.wmu
		if werr != nil {
			drop()
			if errors.Is(werr, os.ErrDeadlineExceeded) || !time.Now().Before(deadline) {
				co.child.kill()
				return nil, errChildTimeout
			}
			return nil, werr
		}
	case <-ctx.Done():
		co.child.kill()
		<-co.wmu
		drop()
		return nil, ctx.Err()
	case <-timeoutT.C:
		co.child.kill()
		<-co.wmu
		drop()
		return nil, errChildTimeout
	}
	select {
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	case <-timeoutT.C:
		drop()
		return nil, errChildTimeout
	case res := <-waiter:
		return res.line, res.err
	}
}

// notify writes one notification and returns. It never waits for output
// because notifications have no reply by definition.
func (co *coordinator) notify(ctx context.Context, msg []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	timeoutT := time.NewTimer(timeout)
	defer timeoutT.Stop()
	select {
	case co.wmu <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-timeoutT.C:
		co.child.kill()
		return errChildTimeout
	}
	done := make(chan error, 1)
	go func() {
		defer func() { <-co.wmu }()
		if f, ok := fileWithDeadline(co.child.stdin); ok {
			_ = f.SetWriteDeadline(deadline)
			defer f.SetWriteDeadline(time.Time{})
		}
		if n, err := co.child.stdin.Write(msg); err != nil || n != len(msg) {
			if err == nil {
				err = io.ErrShortWrite
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				err = errChildTimeout
			}
			done <- err
			return
		}
		done <- nil
	}()
	select {
	case <-ctx.Done():
		co.child.kill()
		return errChildCancelled
	case <-timeoutT.C:
		co.child.kill()
		return errChildTimeout
	case err := <-done:
		return err
	}
}
