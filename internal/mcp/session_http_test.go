package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const sessionProtocol = "2025-11-25"

const sessionFixture = `while IFS= read -r req; do
id=$(printf '%s' "$req" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
case "$req" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":"%s","result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id" ;;
  *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":"%s","result":{"tools":[]}}\n' "$id" ;;
  *'"method":"notifications/initialized"'*) printf '{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///session"}}\n' ;;
esac
done`

func TestReplaceJSONRPCIDPreservesWireLayout(t *testing.T) {
	input := []byte("{ \"jsonrpc\" : \"2.0\", \"id\" : 1 , \"method\":\"tools/list\" }\n")
	got, err := replaceJSONRPCID(input, json.RawMessage(`"private-1"`))
	if err != nil {
		t.Fatal(err)
	}
	want := "{ \"jsonrpc\" : \"2.0\", \"id\" : \"private-1\" , \"method\":\"tools/list\" }\n"
	if string(got) != want {
		t.Fatalf("replacement changed non-ID bytes:\n got %q\nwant %q", got, want)
	}
}

func startSessionTestAdapter(t *testing.T, script string, timeout time.Duration, maxSessions int) *Adapter {
	t.Helper()
	a, err := New(Options{Command: "sh", Args: []string{"-c", script}, Timeout: timeout,
		MultiClientSessions: true, MaxSessions: maxSessions, SessionIdleTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return a
}

type testSession struct{ id, version string }

func initTestSession(t *testing.T, a *Adapter, id int) testSession {
	t.Helper()
	body := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"initialize\",\"params\":{\"protocolVersion\":%q,\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}", id, sessionProtocol)
	w := sessionTestPost(t, a, "", "", body)
	if w.Code != http.StatusOK {
		t.Fatalf("initialize status=%d body=%q", w.Code, w.Body.String())
	}
	var reply map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || reply["id"] != float64(id) {
		t.Fatalf("initialize reply=%q err=%v", w.Body.String(), err)
	}
	result, _ := reply["result"].(map[string]any)
	if result["protocolVersion"] != sessionProtocol {
		t.Fatalf("negotiated version=%v", result["protocolVersion"])
	}
	s := testSession{w.Header().Get(sessionHeader), w.Header().Get("Mcp-Protocol-Version")}
	if s.id == "" || s.version != sessionProtocol {
		t.Fatalf("missing session headers: %v", w.Header())
	}
	return s
}

func sessionTestPost(t *testing.T, a *Adapter, sid, version, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid != "" {
		req.Header.Set(sessionHeader, sid)
		req.Header.Set("Mcp-Protocol-Version", version)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

func TestSessionedAdapterIsolatesClientsAndSameIDs(t *testing.T) {
	a := startSessionTestAdapter(t, sessionFixture, time.Second, 2)
	first, second := initTestSession(t, a, 100), initTestSession(t, a, 200)
	if first.id == second.id || a.Spawned() != 2 {
		t.Fatalf("sessions not independently allocated: first=%q second=%q spawned=%d", first.id, second.id, a.Spawned())
	}
	type response struct {
		code int
		body string
	}
	responses := make(chan response, 2)
	for _, s := range []testSession{first, second} {
		s := s
		go func() {
			w := sessionTestPost(t, a, s.id, s.version, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}")
			responses <- response{w.Code, w.Body.String()}
		}()
	}
	for range 2 {
		got := <-responses
		if got.code != http.StatusOK || !strings.Contains(got.body, "\"id\":1") {
			t.Fatalf("concurrent clients reusing id 1: status=%d body=%q", got.code, got.body)
		}
	}
	deleteReq := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	deleteReq.Header.Set(sessionHeader, first.id)
	deleteReq.Header.Set("Mcp-Protocol-Version", first.version)
	deleteW := httptest.NewRecorder()
	a.ServeHTTP(deleteW, deleteReq)
	if deleteW.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d", deleteW.Code)
	}
	if _, ok := a.lookupSession(first.id); ok {
		t.Fatal("deleted session still exists")
	}
	if _, ok := a.lookupSession(second.id); !ok {
		t.Fatal("deleting one session affected another")
	}
}

func TestSessionCapacityAndIdleExpiryBoundChildProcesses(t *testing.T) {
	a, err := New(Options{Command: "sh", Args: []string{"-c", sessionFixture}, Timeout: time.Second,
		MultiClientSessions: true, MaxSessions: 1, SessionIdleTimeout: 75 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first := initTestSession(t, a, 1)
	secondInit := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\",\"params\":{\"protocolVersion\":%q,\"capabilities\":{}}}", sessionProtocol)
	if w := sessionTestPost(t, a, "", "", secondInit); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-capacity initialization status=%d body=%q", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for a.SessionCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := a.SessionCount(); got != 0 {
		t.Fatalf("idle session retained a child past its timeout: count=%d", got)
	}
	if _, ok := a.lookupSession(first.id); ok {
		t.Fatal("idle expired session still resolves")
	}
	_ = initTestSession(t, a, 3)
}

func TestSDKStreamableClientConnectsAndClosesSession(t *testing.T) {
	a := startSessionTestAdapter(t, sessionFixture, time.Second, 2)
	endpoint := "http://" + a.Addr().String() + "/mcp"
	client := sdk.NewClient(&sdk.Implementation{Name: "session-test-client", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: endpoint}, &sdk.ClientSessionOptions{ProtocolVersion: sessionProtocol})
	if err != nil {
		t.Fatalf("SDK connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	result, err := cs.ListTools(ctx, &sdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("SDK tools/list: %v", err)
	}
	if result == nil || len(result.Tools) != 0 {
		t.Fatalf("unexpected SDK tools/list result: %+v", result)
	}
	if err := cs.Close(); err != nil {
		t.Fatalf("SDK close/DELETE: %v", err)
	}
	if got := len(a.sessions); got != 0 {
		t.Fatalf("SDK session remains after Close: %d", got)
	}
}

type sessionStreamWriter struct {
	header http.Header
	status chan int
	writes chan string
}

func newSessionStreamWriter() *sessionStreamWriter {
	return &sessionStreamWriter{header: make(http.Header), status: make(chan int, 1), writes: make(chan string, 8)}
}
func (w *sessionStreamWriter) Header() http.Header { return w.header }
func (w *sessionStreamWriter) WriteHeader(code int) {
	select {
	case w.status <- code:
	default:
	}
}
func (w *sessionStreamWriter) Write(b []byte) (int, error) {
	w.writes <- string(append([]byte(nil), b...))
	return len(b), nil
}
func (*sessionStreamWriter) Flush() {}

func openTestEventStream(t *testing.T, a *Adapter, s testSession) (context.CancelFunc, *sessionStreamWriter, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil).WithContext(ctx)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set(sessionHeader, s.id)
	req.Header.Set("Mcp-Protocol-Version", s.version)
	w := newSessionStreamWriter()
	done := make(chan struct{})
	go func() { a.ServeHTTP(w, req); close(done) }()
	select {
	case code := <-w.status:
		if code != http.StatusOK {
			cancel()
			t.Fatalf("GET stream status=%d", code)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("GET stream did not start")
	}
	return cancel, w, done
}

func TestSessionNotificationsStayOnOwningStream(t *testing.T) {
	a := startSessionTestAdapter(t, sessionFixture, time.Second, 2)
	first, second := initTestSession(t, a, 1), initTestSession(t, a, 2)
	cancel, stream, done := openTestEventStream(t, a, first)
	defer cancel()
	if w := sessionTestPost(t, a, second.id, second.version, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"); w.Code != http.StatusAccepted {
		t.Fatalf("second notification status=%d body=%q", w.Code, w.Body.String())
	}
	select {
	case event := <-stream.writes:
		t.Fatalf("cross-session event: %q", event)
	case <-time.After(100 * time.Millisecond):
	}
	if w := sessionTestPost(t, a, first.id, first.version, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"); w.Code != http.StatusAccepted {
		t.Fatalf("first notification status=%d body=%q", w.Code, w.Body.String())
	}
	select {
	case event := <-stream.writes:
		if !strings.Contains(event, "notifications/resources/updated") || !strings.Contains(event, "file:///session") {
			t.Fatalf("bad SSE event: %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("child notification did not reach SSE stream")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled GET stream did not stop")
	}
}

func TestSessionRequestCancellationReachesChild(t *testing.T) {
	script := `while IFS= read -r req; do
id=$(printf '%s' "$req" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
case "$req" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":"%s","result":{"protocolVersion":"2025-11-25","capabilities":{}}}\n' "$id" ;;
	  *'"method":"tools/call"'*) printf '{"jsonrpc":"2.0","method":"notifications/progress","params":{"message":"request-received"}}\n'; IFS= read -r cancelled; printf '{"jsonrpc":"2.0","method":"notifications/progress","params":{"message":"cancel-received"}}\n' ;;
esac
done`
	a := startSessionTestAdapter(t, script, time.Second, 1)
	s := initTestSession(t, a, 9)
	cancelStream, stream, doneStream := openTestEventStream(t, a, s)
	defer cancelStream()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"slow\"}}")).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(sessionHeader, s.id)
	req.Header.Set("Mcp-Protocol-Version", s.version)
	doneCall := make(chan struct{})
	go func() { a.ServeHTTP(httptest.NewRecorder(), req); close(doneCall) }()
	waitSessionCall(t, a, s.id)
	select {
	case event := <-stream.writes:
		if !strings.Contains(event, "request-received") {
			t.Fatalf("child did not receive the original request: %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("child did not receive the original request")
	}
	cancel()
	select {
	case <-doneCall:
	case <-time.After(time.Second):
		t.Fatal("cancelled request did not return")
	}
	select {
	case event := <-stream.writes:
		if !strings.Contains(event, "cancel-received") {
			t.Fatalf("unexpected event after cancel: %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("child did not receive notifications/cancelled")
	}
	cancelStream()
	select {
	case <-doneStream:
	case <-time.After(time.Second):
		t.Fatal("event stream did not stop")
	}
}

func TestClientCancellationIDIsTranslatedToPrivateRequestID(t *testing.T) {
	s := &clientSession{requests: map[string]json.RawMessage{}}
	if !s.registerRequest("1", json.RawMessage(`"ocliv-private-1"`)) {
		t.Fatal("could not register active request")
	}
	got, ok := s.rewriteCancellation([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`))
	if !ok || !strings.Contains(string(got), `"requestId":"ocliv-private-1"`) {
		t.Fatalf("cancellation was not mapped to the child request ID: %s", got)
	}
	if _, ok := s.rewriteCancellation([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}`)); ok {
		t.Fatal("unknown cancellation was forwarded to the child")
	}
}

func TestWedgedChildRetiresOpenEventStream(t *testing.T) {
	script := `while IFS= read -r req; do
id=$(printf '%s' "$req" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
case "$req" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":"%s","result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id" ;;
  *'"method":"tools/call"'*) sleep 30 ;;
esac
done`
	a := startSessionTestAdapter(t, script, 200*time.Millisecond, 1)
	s := initTestSession(t, a, 19)
	cancelStream, _, streamDone := openTestEventStream(t, a, s)
	defer cancelStream()
	w := sessionTestPost(t, a, s.id, s.version, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wedged"}}`)
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("wedged request status=%d body=%q, want 504", w.Code, w.Body.String())
	}
	select {
	case <-streamDone:
	case <-time.After(time.Second):
		t.Fatal("open event stream remained after its child was retired")
	}
	if _, ok := a.lookupSession(s.id); ok {
		t.Fatal("wedged child session remains registered")
	}
}

func waitSessionCall(t *testing.T, a *Adapter, sid string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s, ok := a.lookupSession(sid); ok {
			s.coord.mu.Lock()
			n := len(s.coord.pending)
			s.coord.mu.Unlock()
			if n != 0 {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("session call never reached child")
}
