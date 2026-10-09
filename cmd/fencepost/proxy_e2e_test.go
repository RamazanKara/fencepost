//go:build e2e

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/mcp"
	"gopkg.in/yaml.v3"
)

type proxyClient struct {
	in  io.WriteCloser
	out *bufio.Reader
	id  int
}

func startProxy(t *testing.T, dir, kind string, extra ...string) *proxyClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	args := append([]string{"proxy", "--server", kind}, extra...)
	args = append(args, "--", programs[kind])
	cmd := exec.CommandContext(ctx, programs["fencepost"], args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "FENCEPOST_RUG_STATE="+filepath.Join(dir, "rug-state"))
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			cancel()
			<-done
			t.Error("proxy shutdown timed out")
		}
		cancel()
		if strings.Contains(stderr.String(), "DATA RACE") {
			t.Error(stderr.String())
		}
	})
	return &proxyClient{in: in, out: bufio.NewReader(out)}
}

func (c *proxyClient) exchange(t *testing.T, method string, params any) mcp.Message {
	t.Helper()
	c.id++
	m, err := mcp.Encode(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	if err := mcp.WriteFrame(c.in, m); err != nil {
		t.Fatal(err)
	}
	done := make(chan mcp.Message, 1)
	failure := make(chan error, 1)
	go func() {
		for {
			r, err := mcp.ReadFrame(c.out)
			if err != nil {
				failure <- err
				return
			}
			if r.ID() == m.ID() {
				done <- r
				return
			}
		}
	}()
	select {
	case r := <-done:
		return r
	case err := <-failure:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("proxy response timed out")
	}
	return mcp.Message{}
}

func writePolicy(t *testing.T, dir string, servers map[string]any) {
	t.Helper()
	data, err := yaml.Marshal(map[string]any{"version": 1, "servers": servers})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fencepost.yaml"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestE2EPolicyFixtures(t *testing.T) {
	for _, kind := range []string{"filesystem", "fetch", "leaky", "injecting"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "allowed")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "safe"), []byte("safe-content"), 0600); err != nil {
				t.Fatal(err)
			}
			tool := map[string]any{"name": "*", "action": "allow"}
			if kind == "filesystem" {
				tool["arguments"] = []any{map[string]any{"path": "$.path", "path_prefix": []string{root}}}
			}
			if kind == "fetch" {
				tool["arguments"] = []any{map[string]any{"path": "$.url", "host": []string{"example.com"}}}
			}
			writePolicy(t, dir, map[string]any{kind: map[string]any{"default": "deny", "tools": []any{tool}}})
			c := startProxy(t, dir, kind)
			var attempts []map[string]any
			switch kind {
			case "filesystem":
				attempts = []map[string]any{{"path": filepath.Join(root, "safe")}, {"path": root + "/../outside"}, {"path": root + "/%2e%2e/outside"}, {"path": root + "/%252e%252e/outside"}}
				if err := os.Symlink(dir, filepath.Join(root, "link")); err != nil {
					t.Logf("symlink e2e unavailable: %v", err)
				} else {
					attempts = append(attempts, map[string]any{"path": filepath.Join(root, "link", "fencepost.yaml")})
				}
			case "fetch":
				for _, u := range []string{"https://example.com/", "https://example.com@evil.test/", "http://127.0.0.1/", "http://2130706433/", "http://0x7f000001/", "https://еxample.com/"} {
					attempts = append(attempts, map[string]any{"url": u})
				}
			default:
				attempts = []map[string]any{{}}
			}
			for i, args := range attempts {
				r := c.exchange(t, "tools/call", map[string]any{"name": "test", "arguments": args})
				if i > 0 {
					if r.Fields["error"] == nil {
						t.Fatalf("bypass %v: %s", args, r.Raw)
					}
					continue
				}
				if r.Fields["error"] != nil {
					t.Fatal(string(r.Raw))
				}
				if kind == "leaky" && (!strings.Contains(string(r.Raw), "[redacted:github-token]") || strings.Contains(string(r.Raw), "ghp_")) {
					t.Fatal(string(r.Raw))
				}
				if kind == "injecting" && !strings.Contains(string(r.Raw), "Fencepost warning") {
					t.Fatal(string(r.Raw))
				}
			}
			cli(t, dir, 0, "log", "verify")
			stats := cli(t, dir, 0, "log", "stats")
			if !strings.Contains(stats, `"calls"`) {
				t.Fatal(stats)
			}
		})
	}
}

func TestE2ERugPullProxy(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, map[string]any{"rugpull": map[string]string{"default": "allow"}})
	config := writeConfig(t, dir, map[string]any{"rugpull": map[string]any{"command": programs["rugpull"], "env": map[string]string{"FENCEPOST_RUG_STATE": filepath.Join(dir, "rug-state")}}})
	cli(t, dir, 0, "pin", "--config", config)
	c := startProxy(t, dir, "rugpull")
	r := c.exchange(t, "tools/list", map[string]any{})
	if strings.Contains(string(r.Raw), `"name":"greet"`) {
		t.Fatal("drift visible", string(r.Raw))
	}
	r = c.exchange(t, "tools/call", map[string]any{"name": "greet"})
	if r.Fields["error"] == nil {
		t.Fatal("drift call allowed")
	}
	cli(t, dir, 0, "pin", "--config", config, "--update", "rugpull/greet")
	r = c.exchange(t, "tools/list", map[string]any{})
	if !strings.Contains(string(r.Raw), `"name":"greet"`) {
		t.Fatal("updated pin still hidden", string(r.Raw))
	}
	r = c.exchange(t, "tools/call", map[string]any{"name": "greet"})
	if r.Fields["error"] != nil {
		t.Fatal(string(r.Raw))
	}
}

func TestE2EWrapAndCrash(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, map[string]any{"clean": map[string]string{"default": "allow"}})
	config := writeConfig(t, dir, map[string]any{"clean": map[string]any{"command": programs["clean"]}})
	original, _ := os.ReadFile(config)
	cli(t, dir, 0, "policy", "check")
	cli(t, dir, 0, "wrap", "--config", config)
	after, _ := os.ReadFile(config)
	if !bytes.Equal(after, original) {
		t.Fatal("dry run wrote config")
	}
	cli(t, dir, 0, "wrap", "--config", config, "--write")
	cli(t, dir, 0, "scan", "--config", config)
	cli(t, dir, 0, "unwrap", "--config", config, "--write")
	after, _ = os.ReadFile(config)
	if !bytes.Equal(after, original) {
		t.Fatal("unwrap not exact")
	}
	c := startProxy(t, dir, "clean")
	r := c.exchange(t, "tools/call", map[string]any{"name": "crash"})
	if r.Fields["error"] == nil || !strings.Contains(string(r.Raw), "disconnected") {
		t.Fatal(string(r.Raw))
	}
}

func TestE2EWrapHTTP(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "modern", true: "legacy"}[legacy], func(t *testing.T) {
			dir := t.TempDir()
			endpoint := startHTTP(t, legacy)
			t.Setenv("FENCEPOST_HTTP_TOKEN", "private-http-token")
			writePolicy(t, dir, map[string]any{"http": map[string]string{"default": "allow"}})
			config := writeConfig(t, dir, map[string]any{"http": map[string]any{"url": endpoint, "headers": map[string]string{"Authorization": "Bearer ${FENCEPOST_HTTP_TOKEN}"}}})
			cli(t, dir, 0, "wrap", "--config", config, "--write")
			cli(t, dir, 0, "scan", "--config", config)
		})
	}
}

func TestE2EToolBudget(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, map[string]any{"clean": map[string]any{"default": "deny", "tools": []any{map[string]any{"name": "*", "action": "allow", "budget": 1}}}})
	cli(t, dir, 0, "policy", "check")
	c := startProxy(t, dir, "clean")
	for i, name := range []string{"echo", "echo", "other"} {
		r := c.exchange(t, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"text": "budget check"}})
		if (r.Fields["error"] != nil) != (i == 1) {
			t.Fatalf("call %d: %s", i, r.Raw)
		}
		if i == 1 && !strings.Contains(string(r.Raw), "Tool session budget") {
			t.Fatal(string(r.Raw))
		}
	}
	cli(t, dir, 0, "log", "verify")
	if log := cli(t, dir, 0, "log", "query", "--decision", "deny"); !strings.Contains(log, `"rule":"tool_budget"`) {
		t.Fatal(log)
	}
}
