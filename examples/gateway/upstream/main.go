package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9001", "listen address")
	flag.Parse()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Arguments       map[string]any `json:"arguments"`
				ProtocolVersion string         `json:"protocolVersion"`
			} `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&m) != nil {
			w.WriteHeader(400)
			return
		}
		if m.ID == nil {
			w.WriteHeader(202)
			return
		}
		result := map[string]any{}
		switch m.Method {
		case "server/discover":
			result = map[string]any{"supportedVersions": []string{"2026-07-28"}, "capabilities": map[string]any{"tools": map[string]any{}}, "ttlMs": 0, "cacheScope": "private"}
		case "initialize":
			version := "2025-11-25"
			if m.Params.ProtocolVersion == "2025-03-26" {
				version = m.Params.ProtocolVersion
			}
			result = map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "example", "version": "0.2.0"}}
		case "tools/list":
			result["tools"] = []any{map[string]any{"name": "echo", "description": "Echo example text.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"text": map[string]string{"type": "string"}}}}}
		case "tools/call":
			text, _ := m.Params.Arguments["text"].(string)
			result["content"] = []any{map[string]string{"type": "text", "text": text}}
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32601, "message": "Unknown method"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
	})
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
