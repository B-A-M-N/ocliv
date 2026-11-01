package mcp

import (
	"bufio"
	"context"
	"encoding/json"
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
	wmu   sync.Mutex

	mu      sync.Mutex
	pending map[string]chan coordResult
	closed  bool

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
		pending: make(map[string]chan coordResult),
		maxBody: maxBody,
		onDeath: onDeath,
	}
	go co.readLoop(c.stdout)
	return co
}

// readLoop owns stdout. Each line is framed, measured, and dispatched
// by id; lines without a deliverable id (notifications, garbage, late
// replies to dropped waiters) are discarded, never misattributed.
func (co *coordinator) readLoop(r *bufio.Reader) {
	fail := func(err error) {
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
		if co.onDeath != nil {
			co.onDeath()
		}
	}
	var buf []byte
	for {
		frag, err := r.ReadBytes('\n')
		buf = append(buf, frag...)
		if int64(len(buf)) > co.maxBody {
			buf = nil
			fail(fmt.Errorf("child output exceeds %d bytes", co.maxBody))
			return
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
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(line, &env); err != nil || len(env.ID) == 0 {
			continue // notification or unparsable child chatter: drop
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

// call writes one request and waits for the reply carrying the same id.
// The HTTP caller's context cancels the wait without disturbing the
// child or other in-flight calls; the timeout still fails closed and
// reports errChildTimeout so the adapter can retire a wedged child.
func (co *coordinator) call(ctx context.Context, msg []byte, id string, timeout time.Duration) ([]byte, error) {
	waiter := make(chan coordResult, 1)
	co.mu.Lock()
	if co.closed {
		co.mu.Unlock()
		return nil, fmt.Errorf("mcp child gone")
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
	co.wmu.Lock()
	_, werr := co.child.stdin.Write(msg)
	co.wmu.Unlock()
	if werr != nil {
		drop()
		return nil, werr
	}
	timeoutT := time.NewTimer(timeout)
	defer timeoutT.Stop()
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
func (co *coordinator) notify(msg []byte, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		co.wmu.Lock()
		defer co.wmu.Unlock()
		if f, ok := fileWithDeadline(co.child.stdin); ok {
			_ = f.SetWriteDeadline(time.Now().Add(timeout))
			defer f.SetWriteDeadline(time.Time{})
		}
		if n, err := co.child.stdin.Write(msg); err != nil || n != len(msg) {
			if err == nil {
				err = io.ErrShortWrite
			}
			done <- err
			return
		}
		done <- nil
	}()
	timeoutT := time.NewTimer(timeout)
	defer timeoutT.Stop()
	select {
	case <-timeoutT.C:
		return errChildTimeout
	case err := <-done:
		return err
	}
}
