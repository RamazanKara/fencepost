package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
)

func TestHTTPNegotiationPagination(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, sse := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%t/sse=%t", legacy, sse), func(t *testing.T) {
				var initialized, deleted atomic.Bool
				var lists atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer test-secret" {
						t.Error("missing declared header")
					}
					if r.Method == "DELETE" {
						deleted.Store(true)
						w.WriteHeader(204)
						return
					}
					var request map[string]json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						return
					}
					var method string
					_ = json.Unmarshal(request["method"], &method)
					if method == "server/discover" && legacy {
						w.WriteHeader(400)
						return
					}
					if request["id"] == nil {
						initialized.Store(true)
						w.WriteHeader(202)
						return
					}
					var params map[string]json.RawMessage
					_ = json.Unmarshal(request["params"], &params)
					if !legacy {
						if r.Header.Get("MCP-Protocol-Version") != Latest || r.Header.Get("Mcp-Method") != method || !strings.Contains(string(params["_meta"]), Latest) {
							t.Error("missing modern metadata")
						}
					}
					result := map[string]any{}
					if !legacy {
						result["resultType"] = "complete"
					}
					switch method {
					case "server/discover":
						result["supportedVersions"] = []string{Latest}
						result["capabilities"] = map[string]any{"tools": map[string]any{}, "prompts": map[string]any{}, "resources": map[string]any{}}
					case "initialize":
						result["protocolVersion"] = Previous
						result["capabilities"] = map[string]any{"tools": map[string]any{}, "prompts": map[string]any{}, "resources": map[string]any{}}
						w.Header().Set("Mcp-Session-Id", "session-test")
					default:
						if legacy && (!initialized.Load() || r.Header.Get("Mcp-Session-Id") != "session-test") {
							t.Error("legacy handshake/session missing")
						}
						lists.Add(1)
						kind := strings.Split(method, "/")[0]
						if params["cursor"] == nil {
							result[kind] = []any{}
							result["nextCursor"] = "next"
						} else {
							result[kind] = []any{map[string]any{"name": "test", "description": "A definition.", "inputSchema": map[string]string{"type": "object"}, "unknown": true}}
						}
					}
					data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request["id"], "result": result})
					if sse {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprintf(w, ": ping\n\ndata: %s\n\n", data)
					} else {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(data)
					}
				}))
				defer server.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				client, err := Connect(ctx, clientconfig.Server{Transport: "http", URL: server.URL, Headers: map[string]string{"Authorization": "Bearer test-secret"}})
				if err != nil {
					t.Fatal(err)
				}
				catalog, err := client.Catalog(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if len(catalog.Tools) != 1 || len(catalog.Prompts) != 1 || len(catalog.Resources) != 1 || lists.Load() != 6 {
					t.Fatalf("pagination failed: %+v", catalog)
				}
				if string(catalog.Tools[0]["unknown"]) != "true" {
					t.Fatal("unknown definition field lost")
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				if deleted.Load() != legacy {
					t.Fatal("incorrect session termination")
				}
			})
		}
	}
}

func TestHTTPFailures(t *testing.T) {
	for _, test := range []struct {
		name          string
		status        int
		body, content string
	}{{"auth", 401, "secret", "text/plain"}, {"bad-json", 200, "{", "application/json"}, {"batch", 200, "[]", "application/json"}, {"wrong-id", 200, `{"jsonrpc":"2.0","id":999,"result":{}}`, "application/json"}, {"modern-error", 400, `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"secret","data":{"supported":["2099-01-01"]}}}`, "application/json"}} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", test.content)
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := Connect(ctx, clientconfig.Server{Transport: "http", URL: s.URL})
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe result: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("improper fallback")
			}
		})
	}
}

func TestHTTPRedirectDoesNotForwardHeaders(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	h, _ := newHTTP(source.URL, map[string]string{"X-API-Key": "secret"})
	defer h.client.CloseIdleConnections()
	m, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "x"})
	if _, err := h.exchange(context.Background(), m, Latest); err == nil {
		t.Fatal("redirect succeeded")
	}
	if hit.Load() {
		t.Fatal("followed redirect with credentials")
	}
}

func TestHTTPStreamTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": waiting\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer s.Close()
	h, _ := newHTTP(s.URL, nil)
	defer h.client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	m, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "x"})
	if _, err := h.exchange(ctx, m, Latest); err == nil {
		t.Fatal("stream did not time out")
	}
}

func TestLegacySSEResume(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if r.Method == "POST" {
			fmt.Fprint(w, "id: event-1\nretry: 1\ndata:\n\n")
			return
		}
		if r.Header.Get("Last-Event-ID") != "event-1" {
			t.Error("resume ID missing")
		}
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
	}))
	defer s.Close()
	h, _ := newHTTP(s.URL, nil)
	defer h.client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "x"})
	if _, err := h.exchange(ctx, m, Previous); err != nil {
		t.Fatal(err)
	}
	if _, err := h.exchange(ctx, m, Latest); err != io.EOF {
		t.Fatalf("modern stream resumed: %v", err)
	}
}

func TestHeaderEncoding(t *testing.T) {
	for _, value := range []string{"café", " padded ", "line\nbreak", "=?base64?literal?="} {
		if !strings.HasPrefix(headerValue(value), "=?base64?") {
			t.Fatal("unsafe header")
		}
	}
	if headerValue("tool-name") != "tool-name" {
		t.Fatal("changed ASCII name")
	}
}
