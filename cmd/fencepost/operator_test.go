package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/fencepost/internal/policy"
)

func TestInitExplainDoctor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "starter.yaml")
	runCLI := func(want int, args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != want {
			t.Fatalf("%v: %d want %d: %s %s", args, code, want, &out, &errOut)
		}
		return out.String() + errOut.String()
	}
	runCLI(0, "init", "--policy", path, "--server", "test: server")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	runCLI(2, "init", "--policy", path)
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("init overwrote policy")
	}
	if _, err := policy.Read(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "workspace"), 0700); err != nil {
		t.Fatal(err)
	}
	callPath := filepath.Join(dir, "call.json")
	for _, tc := range []struct {
		name, path, reason string
		code               int
	}{
		{"read_file", filepath.Join(dir, "workspace", "new.txt"), "ALLOW", 0},
		{"read_file", filepath.Join(dir, "outside.txt"), "argument:1", 1},
		{"delete_file", "", "server default", 1},
	} {
		data, _ := json.Marshal(map[string]any{"server": "test: server", "name": tc.name, "arguments": map[string]any{"path": tc.path}})
		if err := os.WriteFile(callPath, data, 0600); err != nil {
			t.Fatal(err)
		}
		if output := runCLI(tc.code, "explain", path, callPath); !strings.Contains(output, tc.reason) {
			t.Fatal(output)
		}
	}
	for _, invalid := range []string{`{"server":"s","name":"x","arguments":null}`, `{}`, `{"server":"s","name":"x","arguments":[]}`, `{"server":"s","name":"x"} {}`, `{"server":"s","name":"x","typo":true}`} {
		if err := os.WriteFile(callPath, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		runCLI(2, "explain", path, callPath)
	}
	config := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(config, []byte(`{"mcpServers":{"test":{"command":"must-not-start"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	runCLI(0, "doctor", "--policy", path, "--config", config)
	runCLI(2, "doctor", "--policy", path, "--config", filepath.Join(dir, "missing"))
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".fencepost-doctor-*"))
	if len(leftovers) != 0 {
		t.Fatal("doctor left temporary files")
	}
	for _, cmd := range []string{"init", "explain", "doctor"} {
		runCLI(0, cmd, "--help")
	}
}

func TestExplainApprovalAndUnknownServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nservers: {s: {default: ask}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	call := filepath.Join(dir, "call.json")
	for _, server := range []string{"s", "missing"} {
		if err := os.WriteFile(call, []byte(`{"server":"`+server+`","name":"echo"}`), 0600); err != nil {
			t.Fatal(err)
		}
		var out, errs bytes.Buffer
		if code := run(context.Background(), []string{"explain", path, call}, &out, &errs); code != 1 {
			t.Fatal(code, &out, &errs)
		}
		want := "Approval is required"
		if server == "missing" {
			want = "server is not configured"
		}
		if !strings.Contains(out.String(), want) {
			t.Fatal(&out)
		}
	}
}

func TestPolicyErrorLocation(t *testing.T) {
	for _, tc := range []struct{ text, line string }{
		{"version: 1\nservers:\n  s:\n    default: invalid\n", "line 4"},
		{"version: 1\nservers:\n  s:\n    default: deny\n    typo: true\n", "line 5"},
		{"version: 1\nservers:\n  s:\n    default: null\n", "line 4"},
		{"version: 1\nservers:\n  s:\n    default: deny\n    tools:\n      - name: echo\n        action: allow\n        arguments:\n          - path: $.text\n            regex: '['\n", "line 10"},
	} {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(tc.text), 0600); err != nil {
			t.Fatal(err)
		}
		var out, errs bytes.Buffer
		if run(context.Background(), []string{"policy", "check", "--policy", path}, &out, &errs) != 2 || !strings.Contains(errs.String(), path) || !strings.Contains(errs.String(), tc.line) {
			t.Fatal(errs.String())
		}
	}
}
