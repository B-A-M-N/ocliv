// HTTP request/response exchange over one yamux stream (relay side).
//
// One httpExchange owns exactly one visitor request/response cycle: the
// concurrent upload pump, the response-head wait with first-byte deadline,
// the coordination between the two, and the committed response stream.
// Exactly one logical reader consumes the stream (E04): the single head
// reader, then the single body loop. Upload DATA frames and the terminal
// END/ABORT are serialized through one writer lock, so DATA always
// precedes END/ABORT and concurrent frame writes are impossible.
//
// serveHTTP (in relay_public.go) is the admission entry point; it builds
// the exchange and runs it. The coordinator preserves the original
// concurrency semantics exactly: upload and head proceed concurrently so
// neither stalls the other, determined outcomes outrank cancellation, and
// a committed response is torn down rather than replaced (E13, P0-05).
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"ocliv/internal/limits"
	"ocliv/internal/metrics"
	"ocliv/internal/protocol"
	"ocliv/internal/proxy"
)

// errUploadStopped tells the upload worker to exit without a terminal
// frame: main already handled (or is handling) the outcome.
var errUploadStopped = errors.New("relay: upload stopped")

// uploadOutcome is the single terminal report of the upload worker.
type uploadOutcome struct {
	ok         bool
	abandoned  bool
	failStatus int
	failMsg    string
	failCode   string
	failWhy    string
}

// headOutcome is the single response-head report of the head reader.
type headOutcome struct {
	ftype   byte
	payload []byte
	err     error
}

// httpExchange is the request-scoped owner of one proxied HTTP exchange.
// All mutable coordination state lives here; nothing is shared between
// exchanges except the Server (audits, budgets) and the stream itself.
type httpExchange struct {
	srv    *Server
	w      http.ResponseWriter
	r      *http.Request
	stream net.Conn
	t      *routeTarget

	ctx context.Context

	// wmu serializes stream frames: the upload worker emits DATA only
	// and reports one outcome, while the coordinator emits the terminal
	// frame. stopped makes a blocked upload exit after the fact.
	wmu     sync.Mutex
	stopped atomic.Bool
	endSent bool

	// lastProgress tracks the most recent upload DATA write (or
	// exchange start) as Unix nanos. The coordinator enforces an idle window, not an
	// absolute cap, while the upload runs: steady progress extends the
	// wait, a full window with zero progress and zero head aborts it
	// (Finding 2). Absolute bounds remain the body cap and the lease TTL.
	lastProgress atomic.Int64
	// uploadWriting reports where the upload worker is blocked: false
	// while waiting to READ from the visitor, true while blocked WRITING
	// a read chunk downstream. A full idle window in the reading state
	// means the client stopped sending while the tunnel was ready to
	// receive (client-side stall: never certify). A full idle window in
	// the writing state means the app stopped consuming while visitor
	// data was available (app-side stall: the app answered without
	// reading, so the tunnel releases exactly what the app produced
	// rather than deadlock a completed response). Responsibility follows
	// the stall: each side's stall is held against that side (P0-06 vs
	// P1-9 reconciliation). Advisory only; consulted on the 1s tick
	// after a full idle window, never on a hot path.
	uploadWriting atomic.Bool

	uploadDone   chan uploadOutcome
	uploadFailed chan struct{}
	uploadOk     chan struct{}
	headArrived  chan headOutcome

	headTimeout  time.Duration
	headDeadline *time.Timer

	ftype       byte
	payload     []byte
	haveHead    bool
	uploadClean bool
	// headStatus is the committed response status, parsed in run() before
	// the head is written. streamBody uses it to decide whether the
	// terminal frame must wait for the upload outcome (Finding 5).
	headStatus int
}

func newHTTPExchange(s *Server, w http.ResponseWriter, r *http.Request, stream net.Conn, t *routeTarget) *httpExchange {
	x := &httpExchange{
		srv: s, w: w, r: r, stream: stream, t: t, ctx: r.Context(),
		uploadDone:   make(chan uploadOutcome, 1),
		uploadFailed: make(chan struct{}),
		uploadOk:     make(chan struct{}),
		headArrived:  make(chan headOutcome, 1),
	}
	x.lastProgress.Store(time.Now().UnixNano())
	return x
}

// serveHTTP streams one request body up and one response down with bounded
// buffers and incremental flushing (E05, E11).
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, stream net.Conn, _ string, t *routeTarget) {
	newHTTPExchange(s, w, r, stream, t).run()
}

// writeFrame emits one frame unless the exchange already stopped.
func (x *httpExchange) writeFrame(ft byte, p []byte) error {
	if x.stopped.Load() {
		return errUploadStopped
	}
	x.wmu.Lock()
	defer x.wmu.Unlock()
	if x.stopped.Load() {
		return errUploadStopped
	}
	if err := protocol.WriteFrame(x.stream, ft, p); err != nil {
		return err
	}
	if ft == protocol.FRequestEnd {
		x.endSent = true
	}
	return nil
}

func (x *httpExchange) markStopped() { x.stopped.Store(true) }

// abort never blocks behind an in-flight DATA write: when the writer lock
// is held by a blocked upload, the stopped flag alone makes that upload
// exit after, and returning from the handler releases the stream. An END
// already sent suppresses the ABORT so a terminal frame never follows a
// completed upload.
func (x *httpExchange) abort(code, reason string) {
	x.stopped.Store(true)
	if x.wmu.TryLock() {
		defer x.wmu.Unlock()
		if !x.endSent {
			_ = sendAbort(x.stream, code, reason)
		}
	}
}

// run executes the exchange: upload and response-head proceed concurrently
// so an early response head is never stuck behind a slow upload and a slow
// upload is never stuck behind a withheld head (no half-close deadlock
// either way).
func (x *httpExchange) run() {
	// Three distinct deadlines (Finding 2): the lease TTL is the absolute
	// bound (checked per upload read, per stream frame, and on timer
	// fire); the coordinator timer below is an upload-IDLE policy until
	// the upload completes (steady progress extends it, a full idle
	// window aborts it); only after completion does it become the
	// response first-byte deadline. The initial cap by remaining TTL keeps
	// expiry from outliving the wait (R4).
	x.headTimeout = limits.FirstByteTimeout
	if !x.t.ExpiresAt.IsZero() {
		if d := time.Until(x.t.ExpiresAt); d < x.headTimeout {
			x.headTimeout = d
			if x.headTimeout < 0 {
				x.headTimeout = 0
			}
		}
	}
	if x.headTimeout <= 0 {
		x.markStopped()
		x.srv.db.Audit("visitor", "", x.t.LeaseID, "route", "denied", "lease ttl expired mid-flight")
		http.Error(x.w, "lease expired", http.StatusNotFound)
		return
	}
	go x.runUpload()
	go x.awaitHead()
	x.headDeadline = time.NewTimer(x.headTimeout)
	defer x.headDeadline.Stop()
	// Determined outcomes outrank cancellation: the wait loop drains a
	// ready upload outcome before blocking (see waitHead).
	if x.waitHead() {
		return
	}
	if x.ftype == protocol.FAbort {
		http.Error(x.w, "upstream error", http.StatusBadGateway)
		return
	}
	if x.ftype != protocol.FResponseHead {
		http.Error(x.w, "upstream error", http.StatusBadGateway)
		return
	}
	var rh protocol.ResponseHead
	if err := json.Unmarshal(x.payload, &rh); err != nil {
		http.Error(x.w, "upstream error", http.StatusBadGateway)
		return
	}
	x.headStatus = rh.Status
	proxy.ResponseHeadersToPublic(x.w.Header(), rh.Headers)
	x.w.WriteHeader(rh.Status)
	x.streamBody()
}

// runUpload forwards the visitor body as FRequestData chunks with a hard
// total cap, then sends REQUEST_END itself so the END always follows its
// own DATA under the writer lock. Reports exactly one outcome. Only a
// clean io.EOF completes the upload; any other read error aborts the
// request and never reaches the agent as clean (P0-05). A TTL expiring
// mid-upload aborts it (R4).
func (x *httpExchange) runUpload() {
	fail := func(status int, msg, code, why string) {
		x.uploadDone <- uploadOutcome{failStatus: status, failMsg: msg, failCode: code, failWhy: why}
	}
	abandoned := func() {
		x.uploadDone <- uploadOutcome{abandoned: true}
	}
	sendEnd := func() error {
		endRaw, _ := protocol.MarshalJSON(protocol.EndFrame{Type: "request_end"})
		return x.writeFrame(protocol.FRequestEnd, endRaw)
	}
	if x.r.Body == nil {
		if err := sendEnd(); err != nil {
			if err == errUploadStopped {
				abandoned()
			} else {
				fail(http.StatusBadGateway, "agent unreachable", "", "")
			}
			return
		}
		x.uploadDone <- uploadOutcome{ok: true}
		return
	}
	defer x.r.Body.Close() //nolint:errcheck
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if leaseExpired(x.t) {
			fail(http.StatusNotFound, "lease expired", "cancelled", "lease ttl expired")
			return
		}
		x.uploadWriting.Store(false) // about to block reading the visitor (or already blocked there)
		n, re := x.r.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > protocol.MaxBodyBytes {
				fail(http.StatusRequestEntityTooLarge, "request body too large", "size_limit", "request body exceeds cap")
				return
			}
			x.lastProgress.Store(time.Now().UnixNano())
			metrics.Global.BytesUp.Add(uint64(n))
			x.uploadWriting.Store(true) // about to block writing downstream (or already blocked there)
			if err := x.writeFrame(protocol.FRequestData, buf[:n]); err != nil {
				if err == errUploadStopped {
					abandoned()
				} else {
					fail(http.StatusBadGateway, "agent unreachable", "", "")
				}
				return
			}
		}
		if re == io.EOF {
			if err := sendEnd(); err != nil {
				if err == errUploadStopped {
					abandoned()
				} else {
					fail(http.StatusBadGateway, "agent unreachable", "", "")
				}
				return
			}
			x.uploadDone <- uploadOutcome{ok: true}
			return
		}
		if re != nil {
			fail(http.StatusBadRequest, "request body incomplete", "cancelled", "request body incomplete")
			return
		}
	}
}

// awaitHead reads the response head on its own goroutine so it can overtake
// a still-running upload; the channel is buffered so the reader never
// blocks after the coordinator moves on. No socket deadline is armed here:
// response first-byte enforcement starts only after the upload completes
// (see restartHeadDeadline), so a slow legitimate upload can never trip
// it (Finding 2). A coordinator timeout or handler-return stream close
// still releases a blocked read: the admission site closes the stream on
// every return path. The clear below disarms the post-upload deadline
// when the head arrives.
func (x *httpExchange) awaitHead() {
	ftype, payload, err := protocol.ReadFrame(x.stream)
	_ = x.stream.SetReadDeadline(time.Time{})
	x.headArrived <- headOutcome{ftype: ftype, payload: payload, err: err}
}

func (x *httpExchange) headErr(h headOutcome) bool {
	if h.err == nil {
		return false
	}
	if leaseExpired(x.t) {
		x.abort("cancelled", "lease ttl expired")
		x.srv.db.Audit("visitor", "", x.t.LeaseID, "route", "denied", "lease ttl expired mid-flight")
		http.Error(x.w, "lease expired", http.StatusNotFound)
		return true
	}
	select {
	case <-x.ctx.Done():
		x.markStopped()
		return true // client went away; cleanup via defer
	default:
	}
	x.abort("timeout", "no response head from agent")
	http.Error(x.w, "upstream timeout", http.StatusGatewayTimeout)
	return true
}

// onUpload applies a determined upload outcome. True means the request
// is terminally answered (or abandoned): return.
func (x *httpExchange) onUpload(up uploadOutcome) bool {
	if up.abandoned {
		return true // stopped from elsewhere; terminal already handled
	}
	if up.failStatus != 0 {
		if up.failCode != "" {
			x.abort(up.failCode, up.failWhy)
		} else {
			x.markStopped()
		}
		http.Error(x.w, up.failMsg, up.failStatus)
		return true
	}
	return false // clean: END sent by the worker, head still needed
}

func (x *httpExchange) acceptEarlyHead(h headOutcome) {
	x.ftype, x.payload = h.ftype, h.payload
	x.haveHead = true
	// The upload may still be running; watch its outcome so a late
	// upload failure aborts the stream, which the response loop
	// below turns into a teardown — and so a late upload success can
	// release a held terminal frame (Finding 5). Abandonment needs no
	// signal: the exchange is already terminal elsewhere, and the
	// end-hold below is bounded by context and TTL regardless.
	go func() {
		up := <-x.uploadDone
		if up.ok {
			close(x.uploadOk)
			return
		}
		if !up.abandoned {
			code, why := up.failCode, up.failWhy
			if code == "" {
				code, why = "cancelled", "request body incomplete"
			}
			x.abort(code, why)
			close(x.uploadFailed)
		}
	}()
}

// Bounds the wait for the response head only, never the upload: a slow
// legitimate upload keeps the pre-existing unbounded behavior, and the
// deadline restarts once the upload completes (matching the old
// arm-after-END semantics). Timer-only: socket-level enforcement is armed
// separately by armHeadSocketDeadline, and only once the upload completes —
// arming it here would reintroduce mid-upload socket enforcement on every
// idle extension (Finding 2).
func (x *httpExchange) restartHeadDeadline() {
	if !x.headDeadline.Stop() {
		select {
		case <-x.headDeadline.C:
		default:
		}
	}
	x.headDeadline.Reset(x.headTimeout)
}

// armHeadSocketDeadline starts socket-level first-byte enforcement on the
// already-running head reader. Called only when the upload completes: an
// early head arriving mid-upload already returned from awaitHead (which
// clears any deadline), so this never constrains an in-flight upload.
// The coordinator timer armed by restartHeadDeadline is the primary
// bound; the socket deadline unblocks a stuck reader.
func (x *httpExchange) armHeadSocketDeadline() {
	if x.headTimeout > 0 {
		_ = x.stream.SetReadDeadline(time.Now().Add(x.headTimeout))
	}
}

func (x *httpExchange) timeoutHead() {
	x.abort("timeout", "no response head from agent")
	http.Error(x.w, "agent did not respond in time", http.StatusGatewayTimeout)
}

// waitHead settles the response head. True means the request was
// terminally answered (or abandoned): the caller must return.
func (x *httpExchange) waitHead() bool {
	for !x.haveHead {
		// Determined outcomes outrank cancellation: drain a ready
		// upload outcome before blocking. A half-closed visitor cancels
		// its context at the same moment its truncated body surfaces;
		// answering the known 400 beats a bare return, which would
		// fabricate an implicit 200 for a failed upload (P0-05).
		select {
		case up := <-x.uploadDone:
			if x.onUpload(up) {
				return true
			}
			x.uploadClean = true
			x.restartHeadDeadline()
			x.armHeadSocketDeadline()
		default:
		}
		if x.uploadClean {
			select {
			case h := <-x.headArrived:
				if x.headErr(h) {
					return true
				}
				x.ftype, x.payload = h.ftype, h.payload
				x.haveHead = true
			case <-x.ctx.Done():
				x.markStopped()
				return true
			case <-x.headDeadline.C:
				select {
				case h := <-x.headArrived:
					if x.headErr(h) {
						return true
					}
					x.ftype, x.payload = h.ftype, h.payload
					x.haveHead = true
				default:
					x.timeoutHead()
					return true
				}
			}
			continue
		}
		select {
		case up := <-x.uploadDone:
			if x.onUpload(up) {
				return true
			}
			x.uploadClean = true
			x.restartHeadDeadline()
			x.armHeadSocketDeadline()
		case h := <-x.headArrived:
			if x.headErr(h) {
				return true
			}
			x.acceptEarlyHead(h)
		case <-x.ctx.Done():
			// Re-check determined outcomes before surrendering: an
			// upload result or head already in hand still wins over
			// the cancellation.
			select {
			case up := <-x.uploadDone:
				if x.onUpload(up) {
					return true
				}
				x.uploadClean = true
				x.restartHeadDeadline()
			default:
			}
			if !x.uploadClean {
				select {
				case h := <-x.headArrived:
					if x.headErr(h) {
						return true
					}
					x.acceptEarlyHead(h)
				default:
				}
			}
			if !x.haveHead {
				// No consumer remains for a head or upload outcome not
				// already drained above: waiting out the head deadline
				// would hold a stream slot for a gone visitor (F3).
				// Determined outcomes already in hand were applied
				// above, so this surrenders nothing known — and
				// markStopped also releases a still-running upload
				// worker instead of leaving it for the deadline.
				x.markStopped()
				return true
			}
		case <-x.headDeadline.C:
			select {
			case up := <-x.uploadDone:
				if x.onUpload(up) {
					return true
				}
				x.uploadClean = true
				x.restartHeadDeadline()
			default:
				select {
				case h := <-x.headArrived:
					if x.headErr(h) {
						return true
					}
					x.acceptEarlyHead(h)
				default:
				}
				if !x.haveHead {
					if leaseExpired(x.t) {
						x.abort("cancelled", "lease ttl expired")
						x.srv.db.Audit("visitor", "", x.t.LeaseID, "route", "denied", "lease ttl expired mid-flight")
						http.Error(x.w, "lease expired", http.StatusNotFound)
						return true
					}
					if x.uploadIdleExpired() {
						x.timeoutHead()
						return true
					}
					// Steady upload progress: extend the idle window
					// rather than killing a healthy slow exchange.
					x.restartHeadDeadline()
				}
			}
		}
	}
	return false
}

// uploadIdleExpired reports whether a full head-timeout window has passed
// with neither upload progress nor a response head. Stalled exchanges
// hold a stream, budget slot, and goroutines without doing work, so the
// wait must end (Finding 2, G06/M13). Steady progress extends the wait
// instead: this is an idle policy, not an absolute upload cap.
func (x *httpExchange) uploadIdleExpired() bool {
	since := time.Since(time.Unix(0, x.lastProgress.Load()))
	return since >= x.headTimeout
}

// streamBody streams the committed response incrementally; a committed
// response can never be replaced with a new status (E13): on later failure
// it tears the connection down, because returning or writing another
// status would end the chunked stream cleanly and fabricate a complete
// delivery (P0-05).
// Read deadlines keep a blocked read responsive to visitor cancellation.
// A TTL expiring mid-stream aborts it: expiry bounds in-flight requests,
// not just new admissions (R4).
func (x *httpExchange) streamBody() {
	flusher, _ := x.w.(http.Flusher)
	for {
		if leaseExpired(x.t) {
			x.abort("cancelled", "lease ttl expired")
			// Committed headers mean only teardown is honest (P0-05).
			tearDownResponse(x.w)
			return
		}
		select {
		case <-x.ctx.Done():
			x.abort("cancelled", "visitor went away")
			return
		case <-x.uploadFailed:
			// The upload failed after an early head: the request never
			// completed upstream, so tear down the committed response
			// rather than deliver it as whole.
			tearDownResponse(x.w)
			return
		default:
		}
		_ = x.stream.SetReadDeadline(time.Now().Add(30 * time.Second))
		ft, data, err := protocol.ReadFrame(x.stream)
		_ = x.stream.SetReadDeadline(time.Time{})
		if err != nil {
			select {
			case <-x.ctx.Done():
				x.abort("cancelled", "visitor went away")
			default:
				x.markStopped()
			}
			// Partial delivery after commit: returning would end the
			// chunked stream cleanly. Tear down instead (P0-05).
			tearDownResponse(x.w)
			return
		}
		switch ft {
		case protocol.FResponseData:
			metrics.Global.BytesDown.Add(uint64(len(data)))
			if _, err := x.w.Write(data); err != nil {
				x.abort("cancelled", "visitor write failed")
				return
			}
			if flusher != nil {
				flusher.Flush() // SSE incrementally (E11)
			}
		case protocol.FResponseEnd:
			var end protocol.EndFrame
			_ = json.Unmarshal(data, &end)
			// Trailers announced before WriteHeader would be needed for
			// correctness; our protocol delivers them here for observance.
			_ = end
			// A complete success must not be reported for a request that
			// never completed upstream (Finding 5): when the head arrived
			// early with a success status and the upload outcome is still
			// unknown, the terminal frame waits for it. A rejection
			// stands on its own — the app refused the request regardless
			// of the upload's fate — and a completed upload needs no wait.
			if x.headStatus < 400 && !x.uploadClean {
				if !x.awaitUploadOutcome() {
					x.markStopped()
					tearDownResponse(x.w)
					return
				}
			}
			x.markStopped()
			return
		case protocol.FAbort:
			x.markStopped()
			// Committed headers mean only teardown is honest (P0-05).
			tearDownResponse(x.w)
			return
		default:
			x.markStopped()
			tearDownResponse(x.w)
			return
		}
	}
}

// awaitUploadOutcome waits for a still-running upload to resolve after
// the full response has arrived early. True means the terminal frame may
// be delivered cleanly. False means tear down instead: the upload failed,
// the visitor went away, or the lease expired.
//
// Explicit early-response policy (P1-9, reconciled with P0-06): a FAILED
// upload (error, abort, expiry, visitor gone) withholds clean completion
// — delivering success for a request that demonstrably did not complete
// upstream would fabricate delivery (Finding 5). A STALLED upload is
// judged by which side stalled (see uploadWriting): a client-side stall
// (tunnel ready to receive, client silent) also withholds clean
// completion, because the request never arrived and the client may still
// send. An app-side stall (visitor data available, app not consuming)
// releases the terminal frame: the app answered without reading — a
// legitimate HTTP pattern, the same one behind early 413s — and every
// response byte it produced was already streamed honestly, so delivering
// the end reports exactly what the app produced, no more. Steady upload
// progress extends the wait without bound (within the body cap), so a
// merely slow client with an early-answering app is never penalized.

func (x *httpExchange) awaitUploadOutcome() bool {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-x.uploadOk:
			return true
		case <-x.uploadFailed:
			return false
		case <-x.ctx.Done():
			return false
		case <-tick.C:
			if leaseExpired(x.t) {
				x.abort("cancelled", "lease ttl expired")
				return false
			}
			if x.uploadIdleExpired() {
				// No upload progress for a full window. Release the
				// terminal only for an app-side stall (the app is done
				// and will never consume more); a client-side stall
				// tears down rather than certifying an unreceived
				// request.
				return x.uploadWriting.Load()
			}
		}
	}
}

// tearDownResponse aborts a partially delivered visitor response by
// closing the underlying connection. After WriteHeader, neither returning
// nor writing another status can report the truncation: both end the
// chunked stream cleanly and fabricate a complete delivery. Only an
// abrupt close is observable as truncated (P0-05, acceptance).
func tearDownResponse(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	// No hijack support (e.g. HTTP/2): ErrAbortHandler is recovered
	// per-request by net/http and closes the connection without a
	// clean chunked terminator.
	panic(http.ErrAbortHandler)
}

// setStreamDeadline sets a deadline when the stream supports it.
func setStreamDeadline(stream io.ReadWriter, d time.Duration) error {
	type deadliner interface{ SetDeadline(time.Time) error }
	if dl, ok := stream.(deadliner); ok {
		if d == 0 {
			return dl.SetDeadline(time.Time{})
		}
		return dl.SetDeadline(time.Now().Add(d))
	}
	return nil
}

func sendAbort(w io.Writer, code, reason string) error {
	raw, _ := protocol.MarshalJSON(protocol.Abort{Type: "abort", Code: code, Reason: reason})
	return protocol.WriteFrame(w, protocol.FAbort, raw)
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "req-" + hex.EncodeToString(b[:])
}
