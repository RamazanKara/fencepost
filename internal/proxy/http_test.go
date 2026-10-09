package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/mcp"
)

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
	once    sync.Once
}

func (w *flushRecorder) Flush() {
	w.ResponseRecorder.Flush()
	w.once.Do(func() { close(w.flushed) })
}

func TestHTTPCancellation(t *testing.T) {
	for _, mode := range []string{"notification", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			e := engine(t, "")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				m, _ := mcp.Parse(data)
				if m.String("method") == "notifications/cancelled" {
					w.WriteHeader(202)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, ": waiting\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer upstream.Close()
			h, err := NewHTTP(e.Policy, e.Log, "s", e.lockPath, upstream.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := httptest.NewRequest("POST", "http://proxy/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`)).WithContext(ctx)
			w := &flushRecorder{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{})}
			done := make(chan struct{})
			go func() { defer close(done); h.ServeHTTP(w, r) }()
			defer func() { cancel(); <-done }()
			select {
			case <-w.flushed:
			case <-time.After(5 * time.Second):
				t.Fatal("stream did not start")
			}
			if mode == "notification" {
				notification := httptest.NewRequest("POST", "http://proxy/", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`))
				h.ServeHTTP(httptest.NewRecorder(), notification)
			} else {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancelled HTTP request remained active")
			}
			h.base.mu.Lock()
			pending := len(h.base.pending)
			h.base.mu.Unlock()
			if pending != 0 {
				t.Fatalf("cancelled request retained: %d", pending)
			}
		})
	}
}

func TestHTTPStreamAndSessions(t *testing.T) {
	e := engine(t, "session_budget: 1\n")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if r.Header.Get("Mcp-Session-Id") != "session" || r.Header.Get("Last-Event-ID") != "resume" {
				t.Error("session/resume lost")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, ": heartbeat\r\n\r\nid: next\r\nretry: 10\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"srv\",\"method\":\"roots/list\"}\r\n\r\n")
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		data, _ := io.ReadAll(r.Body)
		m, err := mcp.Parse(data)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Mcp-Method") != m.String("method") {
			t.Error("method header lost")
		}
		if m.String("method") == "initialize" {
			w.Header().Set("Mcp-Session-Id", "session")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}`)
			return
		}
		if r.Header.Get("Mcp-Session-Id") != "session" {
			t.Error("missing upstream session")
		}
		if m.String("method") == "notifications/cancelled" {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "id: progress\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1}}\n\n")
		w.(http.Flusher).Flush()
		fmt.Fprintf(w, "id: result\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ghp_abcdefghijklmnopqrstuvwxyz123456\"}]}}\n\n", m.Fields["id"])
	}))
	defer upstream.Close()
	h, err := NewHTTP(e.Policy, e.Log, "s", e.lockPath, upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	s := httptest.NewServer(h)
	defer s.Close()
	do := func(method, body, session string) *http.Response {
		t.Helper()
		r, _ := http.NewRequest(method, s.URL, strings.NewReader(body))
		r.Header.Set("Mcp-Session-Id", session)
		r.Header.Set("MCP-Protocol-Version", mcp.Previous)
		r.Header.Set("Last-Event-ID", "resume")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	r := do("POST", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	if r.Header.Get("Mcp-Session-Id") != "session" {
		t.Fatal("session not returned")
	}
	r = do("POST", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}`, "session")
	data, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if !bytes.Contains(data, []byte("[redacted:github-token]")) || bytes.Contains(data, []byte("ghp_")) || !bytes.Contains(data, []byte("id: result")) || !bytes.Contains(data, []byte("notifications/progress")) {
		t.Fatal(string(data))
	}
	r = do("POST", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}`, "session")
	data, _ = io.ReadAll(r.Body)
	_ = r.Body.Close()
	if !bytes.Contains(data, []byte("budget exhausted")) {
		t.Fatal(string(data))
	}
	r = do("GET", "", "session")
	data, _ = io.ReadAll(r.Body)
	_ = r.Body.Close()
	if !bytes.Contains(data, []byte("roots/list")) || !bytes.Contains(data, []byte("retry: 10")) || !bytes.Contains(data, []byte("heartbeat")) {
		t.Fatal(string(data))
	}
	r = do("DELETE", "", "session")
	_ = r.Body.Close()
	if r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
	r = do("GET", "", "session")
	_ = r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatal(r.StatusCode)
	}
}

func TestSSEStreamingBoundaries(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- relaySSE(inR, outW, func(m mcp.Message) (mcp.Message, error) { return m, nil })
		_ = outW.Close()
	}()
	go func() { _, _ = io.WriteString(inW, ": keepalive\n\n") }()
	r := bufio.NewReader(outR)
	line, err := r.ReadString('\n')
	if err != nil || line != ": keepalive\n" {
		t.Fatal(line, err)
	}
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = inR.Close()
	_ = outR.Close()
	var out bytes.Buffer
	err = relaySSE(strings.NewReader("data: {}"), &out, func(m mcp.Message) (mcp.Message, error) { return m, nil })
	if err == nil {
		t.Fatal("truncated event accepted")
	}
}

func TestGateway(t *testing.T) {
	e := engine(t, "")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&m)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n\n", m["id"])
	}))
	defer upstream.Close()
	h, err := NewHTTP(e.Policy, e.Log, "s", e.lockPath, upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer outR.Close()
	done := make(chan error, 1)
	go func() { done <- Gateway(ctx, h, inR, outW); _ = outW.Close() }()
	m := message(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`)
	if err := mcp.WriteFrame(inW, m); err != nil {
		t.Fatal(err)
	}
	response, err := mcp.ReadFrame(bufio.NewReader(outR))
	if err != nil || response.ID() != m.ID() {
		t.Fatal(err)
	}
	_ = inW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not close")
	}
}

func TestHTTPFailuresRespectIDs(t *testing.T) {
	e := engine(t, "")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"wrong","result":{}}`)
	}))
	h, err := NewHTTP(e.Policy, e.Log, "s", e.lockPath, upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "http://proxy/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	h.ServeHTTP(w, r)
	m := message(t, w.Body.String())
	if m.ID() != "n:1" || m.Fields["error"] == nil {
		t.Fatal(w.Body.String())
	}
	upstream.Close()
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "http://proxy/", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`))
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
}
