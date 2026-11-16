package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sessionHeader       = "Mcp-Session-Id"
	sessionEventQueue   = 32
	sessionWriteTimeout = 5 * time.Second
)

type clientSession struct {
	id              string
	protocolVersion string
	child           *childProc
	coord           *coordinator
	cancel          context.CancelFunc

	done    chan struct{}
	dead    atomic.Bool
	closed  sync.Once
	getOpen atomic.Bool

	idleMu   sync.Mutex
	idle     *time.Timer
	owner    *Adapter
	reqMu    sync.Mutex
	requests map[string]json.RawMessage
}

func (a *Adapter) startSessionServer(ctx context.Context) error {
	a.startCtx = ctx
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("mcp: loopback listen: %w", err)
	}
	a.ln = ln
	a.srv = &http.Server{Handler: a, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = a.srv.Serve(ln) }()
	go func() {
		select {
		case <-ctx.Done():
			_ = a.Close()
		case <-a.done:
		}
	}()
	return nil
}

func (a *Adapter) serveSessionHTTP(w http.ResponseWriter, r *http.Request) {
	if a.closed.Load() {
		http.Error(w, "mcp adapter closed", http.StatusServiceUnavailable)
		return
	}
	if r.URL.EscapedPath() != "/mcp" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPost:
		a.serveSessionPost(w, r)
	case http.MethodGet:
		a.serveSessionEvents(w, r)
	case http.MethodDelete:
		a.serveSessionDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Adapter) serveSessionPost(w http.ResponseWriter, r *http.Request) {
	if !accepts(r.Header, "application/json") || !accepts(r.Header, "text/event-stream") {
		http.Error(w, "Accept must include application/json and text/event-stream", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := a.readSessionBody(r)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "unreadable JSON-RPC message", http.StatusBadRequest)
		}
		return
	}
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.JSONRPC != "2.0" {
		http.Error(w, "not a JSON-RPC 2.0 message", http.StatusBadRequest)
		return
	}

	sid := strings.TrimSpace(r.Header.Get(sessionHeader))
	if sid == "" {
		if env.Method != "initialize" || len(env.ID) == 0 {
			http.Error(w, "first POST must be initialize", http.StatusBadRequest)
			return
		}
		if _, ok := idKey(env.ID); !ok {
			http.Error(w, "request id must be a string or number", http.StatusBadRequest)
			return
		}
		a.startClientSession(w, r, body, env.ID)
		return
	}
	s, ok := a.lookupSession(sid)
	if !ok {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}
	if version := r.Header.Get("Mcp-Protocol-Version"); version == "" || version != s.protocolVersion {
		http.Error(w, "Mcp-Protocol-Version is missing or does not match the session", http.StatusBadRequest)
		return
	}
	s.touch()
	if s.dead.Load() {
		http.Error(w, "MCP session unavailable", http.StatusNotFound)
		return
	}

	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		http.Error(w, "mcp concurrency exhausted", http.StatusServiceUnavailable)
		return
	}
	if len(env.ID) == 0 {
		if env.Method == "" || len(env.Result) != 0 || len(env.Error) != 0 {
			http.Error(w, "invalid JSON-RPC notification", http.StatusBadRequest)
			return
		}
		if env.Method == "notifications/cancelled" {
			body, _ = s.rewriteCancellation(body)
			if body == nil {
				w.WriteHeader(http.StatusAccepted)
				return
			}
		}
		if err := s.coord.notify(r.Context(), append(body, '\n'), a.timeout); err != nil {
			s.shutdown()
			if errors.Is(err, errChildTimeout) {
				http.Error(w, "mcp child timed out; session retired", http.StatusGatewayTimeout)
			} else if r.Context().Err() == nil {
				http.Error(w, "mcp child exchange failed", http.StatusBadGateway)
			}
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if env.Method == "" {
		if (len(env.Result) == 0) == (len(env.Error) == 0) {
			http.Error(w, "JSON-RPC response must contain exactly one of result or error", http.StatusBadRequest)
			return
		}
		key, valid := idKey(env.ID)
		if !valid {
			http.Error(w, "response id must be a string or number", http.StatusBadRequest)
			return
		}
		if err := s.coord.reply(r.Context(), append(body, '\n'), key, a.timeout); err != nil {
			http.Error(w, "response does not match a pending server request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if len(env.Result) != 0 || len(env.Error) != 0 {
		http.Error(w, "invalid JSON-RPC request", http.StatusBadRequest)
		return
	}
	if _, ok := idKey(env.ID); !ok {
		http.Error(w, "request id must be a string or number", http.StatusBadRequest)
		return
	}
	originalKey, _ := idKey(env.ID)
	internalID, _ := json.Marshal(fmt.Sprintf("ocliv-%d", a.nextRequestID.Add(1)))
	internalKey, _ := idKey(internalID)
	internalBody, err := replaceJSONRPCID(body, internalID)
	if err != nil {
		http.Error(w, "invalid JSON-RPC request id", http.StatusBadRequest)
		return
	}
	if !s.registerRequest(originalKey, internalID) {
		http.Error(w, "duplicate request id is already in flight", http.StatusBadRequest)
		return
	}
	defer s.removeRequest(originalKey, internalID)
	line, err := s.coord.call(r.Context(), internalBody, internalKey, a.timeout)
	if err != nil {
		if r.Context().Err() != nil {
			// Use the adapter-owned context because the HTTP request is already
			// cancelled. The child sees the private id used for correlation.
			ctx, cancel := context.WithTimeout(context.Background(), sessionWriteTimeout)
			cancelBody, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"method":  "notifications/cancelled",
				"params":  map[string]json.RawMessage{"requestId": internalID},
			})
			_ = s.coord.notify(ctx, append(cancelBody, '\n'), sessionWriteTimeout)
			cancel()
			return
		}
		if errors.Is(err, errChildTimeout) || errors.Is(err, errChildUnavailable) {
			s.shutdown()
			if errors.Is(err, errChildTimeout) {
				http.Error(w, "mcp child timed out; session retired", http.StatusGatewayTimeout)
			} else {
				http.Error(w, "MCP session unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		http.Error(w, "mcp child exchange failed", http.StatusBadGateway)
		return
	}
	line, err = replaceJSONRPCID(line, env.ID)
	if err != nil {
		s.shutdown()
		http.Error(w, "mcp child returned an invalid JSON-RPC reply", http.StatusBadGateway)
		return
	}
	s.touch()
	w.Header().Set(sessionHeader, s.id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bytesTrimLine(line))
}

func (a *Adapter) startClientSession(w http.ResponseWriter, r *http.Request, body []byte, originalID json.RawMessage) {
	var initEnvelope struct {
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &initEnvelope); err != nil || initEnvelope.Params.ProtocolVersion == "" {
		http.Error(w, "initialize request has no protocolVersion", http.StatusBadRequest)
		return
	}
	a.sessionMu.Lock()
	if a.closed.Load() {
		a.sessionMu.Unlock()
		http.Error(w, "mcp adapter closed", http.StatusServiceUnavailable)
		return
	}
	if len(a.sessions) >= a.maxSessions {
		a.sessionMu.Unlock()
		http.Error(w, "MCP session capacity exhausted", http.StatusServiceUnavailable)
		return
	}
	sid, err := randomSessionID()
	if err != nil {
		a.sessionMu.Unlock()
		http.Error(w, "could not create MCP session", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithCancel(a.startCtx)
	child, err := startChild(ctx, a.path, a.args, a.dir, a.env)
	if err != nil {
		cancel()
		a.sessionMu.Unlock()
		http.Error(w, "could not start MCP child", http.StatusBadGateway)
		return
	}
	protocolVersion := initEnvelope.Params.ProtocolVersion
	s := &clientSession{id: sid, protocolVersion: protocolVersion, child: child, cancel: cancel, done: make(chan struct{}), owner: a, requests: make(map[string]json.RawMessage)}
	s.coord = runSessionCoordinator(child, a.maxBody, sessionEventQueue, s.shutdown)
	a.sessions[sid] = s
	a.spawned.Add(1)
	if a.sessionIdle > 0 {
		s.idleMu.Lock()
		s.idle = time.AfterFunc(a.sessionIdle, s.shutdown)
		s.idleMu.Unlock()
	}
	a.sessionMu.Unlock()

	internalID, _ := json.Marshal(fmt.Sprintf("ocliv-%s-1", sid))
	key, _ := idKey(internalID)
	internalBody, err := replaceJSONRPCID(body, internalID)
	if err != nil {
		s.shutdown()
		http.Error(w, "invalid initialize request", http.StatusBadRequest)
		return
	}
	line, err := s.coord.call(r.Context(), internalBody, key, a.timeout)
	if err != nil {
		s.shutdown()
		if errors.Is(err, errChildTimeout) {
			http.Error(w, "MCP initialize timed out", http.StatusGatewayTimeout)
		} else {
			http.Error(w, "MCP initialize failed", http.StatusBadGateway)
		}
		return
	}
	line, err = replaceJSONRPCID(line, originalID)
	if err != nil {
		s.shutdown()
		http.Error(w, "invalid initialize response from MCP child", http.StatusBadGateway)
		return
	}
	var initReply struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if err := json.Unmarshal(line, &initReply); err != nil || initReply.Result.ProtocolVersion == "" {
		s.shutdown()
		http.Error(w, "MCP initialize response has no negotiated protocolVersion", http.StatusBadGateway)
		return
	}
	s.protocolVersion = initReply.Result.ProtocolVersion
	w.Header().Set(sessionHeader, sid)
	w.Header().Set("Mcp-Protocol-Version", s.protocolVersion)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bytesTrimLine(line))
}

func (a *Adapter) serveSessionEvents(w http.ResponseWriter, r *http.Request) {
	if !accepts(r.Header, "text/event-stream") {
		http.Error(w, "Accept must include text/event-stream", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Last-Event-ID") != "" {
		http.Error(w, "MCP event resumption is not available", http.StatusBadRequest)
		return
	}
	s, ok := a.lookupSession(strings.TrimSpace(r.Header.Get(sessionHeader)))
	if !ok {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}
	if version := r.Header.Get("Mcp-Protocol-Version"); version == "" || version != s.protocolVersion {
		http.Error(w, "Mcp-Protocol-Version is missing or does not match the session", http.StatusBadRequest)
		return
	}
	if !s.getOpen.CompareAndSwap(false, true) {
		http.Error(w, "MCP session already has an event stream", http.StatusConflict)
		return
	}
	defer s.getOpen.Store(false)
	s.touch()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		case event := <-s.coord.events:
			if err := writeSSE(w, flusher, event); err != nil {
				return
			}
			s.touch()
		case <-keepalive.C:
			if err := writeSSEComment(w, flusher); err != nil {
				return
			}
		}
	}
}

func (a *Adapter) serveSessionDelete(w http.ResponseWriter, r *http.Request) {
	s, ok := a.lookupSession(strings.TrimSpace(r.Header.Get(sessionHeader)))
	if !ok {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}
	if version := r.Header.Get("Mcp-Protocol-Version"); version == "" || version != s.protocolVersion {
		http.Error(w, "Mcp-Protocol-Version is missing or does not match the session", http.StatusBadRequest)
		return
	}
	s.shutdown()
	w.WriteHeader(http.StatusOK)
}

func (a *Adapter) lookupSession(id string) (*clientSession, bool) {
	if id == "" {
		return nil, false
	}
	a.sessionMu.Lock()
	s, ok := a.sessions[id]
	a.sessionMu.Unlock()
	return s, ok && !s.dead.Load()
}

func (s *clientSession) touch() {
	s.idleMu.Lock()
	if s.idle != nil && !s.dead.Load() {
		s.idle.Reset(s.owner.sessionIdle)
	}
	s.idleMu.Unlock()
}

func (s *clientSession) registerRequest(clientKey string, internalID json.RawMessage) bool {
	s.reqMu.Lock()
	defer s.reqMu.Unlock()
	if _, exists := s.requests[clientKey]; exists {
		return false
	}
	s.requests[clientKey] = append(json.RawMessage(nil), internalID...)
	return true
}

func (s *clientSession) removeRequest(clientKey string, internalID json.RawMessage) {
	s.reqMu.Lock()
	defer s.reqMu.Unlock()
	if current, exists := s.requests[clientKey]; exists && string(current) == string(internalID) {
		delete(s.requests, clientKey)
	}
}

// rewriteCancellation translates the client's request ID to the private ID
// sent to the child. An unknown cancellation is accepted and dropped.
func (s *clientSession) rewriteCancellation(message []byte) ([]byte, bool) {
	var envelope struct {
		Params struct {
			RequestID json.RawMessage `json:"requestId"`
		} `json:"params"`
	}
	if err := json.Unmarshal(message, &envelope); err != nil {
		return nil, false
	}
	clientKey, ok := idKey(envelope.Params.RequestID)
	if !ok {
		return nil, false
	}
	s.reqMu.Lock()
	internalID, found := s.requests[clientKey]
	internalID = append(json.RawMessage(nil), internalID...)
	s.reqMu.Unlock()
	if !found {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(message, &obj); err != nil {
		return nil, false
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(obj["params"], &params); err != nil {
		return nil, false
	}
	params["requestId"] = internalID
	obj["params"], _ = json.Marshal(params)
	result, err := json.Marshal(obj)
	return result, err == nil
}

func (s *clientSession) shutdown() {
	s.closed.Do(func() {
		s.dead.Store(true)
		close(s.done)
		s.idleMu.Lock()
		if s.idle != nil {
			s.idle.Stop()
		}
		s.idleMu.Unlock()
		s.owner.sessionMu.Lock()
		if s.owner.sessions[s.id] == s {
			delete(s.owner.sessions, s.id)
		}
		s.owner.sessionMu.Unlock()
		s.cancel()
		s.child.kill()
		s.child.wait()
	})
}

func (a *Adapter) readSessionBody(r *http.Request) ([]byte, error) {
	if r.ContentLength > a.maxBody {
		return nil, &http.MaxBytesError{Limit: a.maxBody}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, a.maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > a.maxBody {
		return nil, &http.MaxBytesError{Limit: a.maxBody}
	}
	return body, nil
}

func accepts(h http.Header, want string) bool {
	for _, value := range h.Values("Accept") {
		for _, part := range strings.Split(value, ",") {
			media, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err == nil && strings.EqualFold(media, want) {
				return true
			}
		}
	}
	return false
}

func randomSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func bytesTrimLine(b []byte) []byte {
	return []byte(strings.TrimSuffix(string(b), "\n"))
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event []byte) error {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(sessionWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", bytesTrimLine(event)); err != nil {
		return err
	}
	if flusher != nil {
		flusher.Flush()
	}
	return nil
}

func writeSSEComment(w http.ResponseWriter, flusher http.Flusher) error {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(sessionWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
		return err
	}
	if flusher != nil {
		flusher.Flush()
	}
	return nil
}
