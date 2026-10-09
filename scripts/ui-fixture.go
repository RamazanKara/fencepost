//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/mcp"
	"github.com/RamazanKara/fencepost/internal/pin"
	"github.com/RamazanKara/fencepost/internal/scan"
	"github.com/RamazanKara/fencepost/packs"
)

func main() {
	if err := fixture(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fixture() error {
	dir, err := filepath.Abs(".ui-fixture")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "workspace"), 0700); err != nil {
		return err
	}
	binary := filepath.Join(dir, "fencepost")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/fencepost")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	data, err := packs.Compose("filesystem,git,browser")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), data, 0600); err != nil {
		return err
	}
	config := map[string]any{"mcpServers": map[string]any{"filesystem": map[string]any{"command": "fixture-filesystem"}, "git": map[string]any{"command": "fixture-git"}, "browser": map[string]any{"url": "https://browser.example.invalid/mcp"}}}
	original, _ := json.Marshal(config)
	configPath := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(configPath+".fencepost.bak", original, 0600); err != nil {
		return err
	}
	servers, err := clientconfig.Parse(original, configPath, dir)
	if err != nil {
		return err
	}
	var inventories []scan.Inventory
	for _, s := range servers {
		var tool mcp.Tool
		_ = json.Unmarshal([]byte(`{"name":"read_file","description":"Read a document.","inputSchema":{"type":"object"}}`), &tool)
		inventories = append(inventories, scan.Inventory{Server: s, Catalog: mcp.Catalog{Tools: []mcp.Tool{tool}}})
	}
	lock, err := pin.Snapshot(inventories)
	if err != nil {
		return err
	}
	lockPath := filepath.Join(dir, "fencepost.lock")
	if err := pin.Write(lockPath, lock); err != nil {
		return err
	}
	wrapped, err := clientconfig.Wrap(original, configPath, dir, binary, filepath.Join(dir, "policy.yaml"), lockPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, wrapped, 0600); err != nil {
		return err
	}
	logPath := filepath.Join(dir, "fencepost-audit.jsonl")
	for _, suffix := range []string{"", ".head", ".writing"} {
		if err := os.Remove(logPath + suffix); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	log, err := audit.Open(logPath, "")
	if err != nil {
		return err
	}
	defer log.Close()
	args, _ := json.Marshal(map[string]string{"path": filepath.Join(dir, "workspace", "notes.txt")})
	events := []audit.Event{
		{Kind: "policy", Server: "filesystem", Tool: "read_file", Decision: "allow", Rule: "tool:1", Arguments: args, Replayable: true},
		{Kind: "decision", Server: "filesystem", Tool: "read_file", Decision: "allow", Rule: "tool:1"},
		{Kind: "policy", Server: "filesystem", Tool: "write_file", Decision: "deny", Rule: "default"},
		{Kind: "decision", Server: "filesystem", Tool: "write_file", Decision: "deny", Rule: "default"},
		{Kind: "decision", Server: "git", Tool: "git_status", Decision: "allow", Rule: "tool:1"},
		{Kind: "redaction", Server: "git", Tool: "git_log", Redactions: map[string]int{"github-token": 1}},
		{Kind: "decision", Server: "browser", Tool: "browser_navigate", Decision: "hide", Rule: "pin"},
		{Kind: "decision", Server: "browser", Tool: "browser_evaluate", Decision: "deny", Rule: "default"},
	}
	for i, event := range events {
		event.Session = "screenshot-fixture"
		event.Method = "tools/call"
		if event.Decision == "hide" {
			event.Method = "tools/list"
		}
		event.Time = time.Date(2026, 10, 9, 10, 12+i, 0, 0, time.UTC).Format(time.RFC3339)
		if err := log.Write(event); err != nil {
			return err
		}
	}
	fmt.Println("Prepared local console fixtures in", strings.TrimPrefix(dir, filepath.Dir(dir)+string(os.PathSeparator)))
	return nil
}
