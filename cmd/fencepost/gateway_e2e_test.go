//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/mcp"
	"gopkg.in/yaml.v3"
)

func TestE2EGatewayRemoteAndStdio(t *testing.T) {
	upstream := startHTTP(t, false)
	dir := t.TempDir()
	key := strings.Repeat("gateway-ci-", 4)
	t.Setenv("FENCEPOST_E2E_GATEWAY_KEY", key)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	base := "http://" + address
	writePolicy(t, dir, map[string]any{
		"remote": map[string]any{"default": "deny", "tools": []any{map[string]any{"name": "echo", "action": "allow", "groups": []string{"engineering"}}}},
		"stdio":  map[string]any{"default": "deny", "tools": []any{map[string]any{"name": "echo", "action": "allow", "groups": []string{"engineering"}}, map[string]any{"name": "write", "action": "ask"}}},
	})
	config := map[string]any{"listen": address, "public_url": base, "policy": map[string]string{"source": "fencepost.yaml"}, "auth": map[string]any{"api_keys": []any{map[string]any{"env": "FENCEPOST_E2E_GATEWAY_KEY", "user": "ci", "client": "workflow", "groups": []string{"engineering"}}}}, "servers": map[string]any{"remote": map[string]string{"url": upstream}, "stdio": map[string]string{"command": programs["clean"]}}}
	config["approval"] = map[string]any{"groups": []string{"engineering"}}
	config["servers"].(map[string]any)["remote"] = map[string]any{"url": upstream, "headers": map[string]string{"Authorization": "Bearer private-http-token"}}
	data, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gateway.yaml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, programs["fencepost"], "gateway", "--config", "gateway.yaml")
	cmd.Dir = dir
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if strings.Contains(diagnostics.String(), "DATA RACE") {
			t.Error(diagnostics.String())
		}
	})
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 204 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway startup timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, server := range []string{"remote", "stdio"} {
		for _, tool := range []string{"echo", "forbidden"} {
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{"text":"gateway-ok"}}}`
			r, _ := http.NewRequest("POST", base+"/mcp/"+server, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+key)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("MCP-Protocol-Version", mcp.Latest)
			resp, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != 200 {
				t.Fatal(server, tool, err, resp.StatusCode, string(data))
			}
			if tool == "echo" && !bytes.Contains(data, []byte("gateway-ok")) {
				t.Fatal(string(data))
			}
			if tool == "forbidden" && !bytes.Contains(data, []byte("does not permit")) {
				t.Fatal(string(data))
			}
		}
	}
	callContext, cancelCall := context.WithCancel(context.Background())
	defer cancelCall()
	r, _ := http.NewRequestWithContext(callContext, "POST", base+"/mcp/stdio", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write","arguments":{}}}`))
	r.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	pendingCount := func() int {
		t.Helper()
		r, _ := http.NewRequest("GET", base+"/approvals/pending", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var pending []json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
			t.Fatal(err)
		}
		return len(pending)
	}
	deadline = time.Now().Add(3 * time.Second)
	for pendingCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("stdio approval not pending")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelCall()
	_ = resp.Body.Close()
	deadline = time.Now().Add(3 * time.Second)
	for pendingCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("disconnected stdio call retained approval")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if output := cli(t, dir, 0, "log", "query", "--tool", "write", "--decision", "allow"); output != "" {
		t.Fatal("cancelled call allowed", output)
	}
	output := cli(t, dir, 0, "log", "query", "--user", "ci", "--decision", "allow")
	if !strings.Contains(output, `"server":"stdio"`) || !strings.Contains(output, `"server":"remote"`) {
		t.Fatal(output)
	}
}
