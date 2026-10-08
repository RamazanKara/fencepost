//go:build e2e

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var programs map[string]string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fencepost-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	programs = map[string]string{}
	for _, name := range []string{"fencepost", "clean", "poisoned", "shadow-a", "shadow-b", "rugpull", "http", "filesystem", "fetch", "leaky", "injecting"} {
		path := filepath.Join(dir, name)
		if runtime.GOOS == "windows" {
			path += ".exe"
		}
		pkg := "./testdata/servers/" + name
		if name == "fencepost" {
			pkg = "./cmd/fencepost"
		}
		cmd := exec.Command("go", "build", "-race", "-o", path, pkg)
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", name, err, out)
			_ = os.RemoveAll(dir)
			os.Exit(1)
		}
		programs[name] = path
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func writeConfig(t *testing.T, dir string, servers map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cli(t *testing.T, dir string, want int, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, programs["fencepost"], args...)
	cmd.Dir = dir
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if code != want {
		t.Fatalf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", args, code, want, &out, &errOut)
	}
	if strings.Contains(out.String()+errOut.String(), "private-http-token") {
		t.Fatal("credential leaked")
	}
	return out.String() + errOut.String()
}

func TestE2EStdioScan(t *testing.T) {
	t.Setenv("FENCEPOST_AMBIENT_SECRET", "must-not-inherit")
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			dir := t.TempDir()
			env := map[string]string{}
			if legacy {
				env["FENCEPOST_LEGACY"] = "1"
			}
			config := writeConfig(t, dir, map[string]any{"clean": map[string]any{"command": programs["clean"], "env": env}})
			out := cli(t, dir, 0, "scan", "--config", config, "--format", "json")
			if !strings.Contains(out, `"findings": []`) {
				t.Fatal(out)
			}
			cli(t, dir, 0, "pin", "--config", config)
			cli(t, dir, 0, "verify", "--config", config)
			cli(t, dir, 2, "pin", "--config", config)
		})
	}
	dir := t.TempDir()
	config := writeConfig(t, dir, map[string]any{"poisoned": map[string]any{"command": programs["poisoned"]}})
	out := cli(t, dir, 1, "scan", "--config", config)
	for _, id := range []string{"FP001", "FP002", "FP007"} {
		if !strings.Contains(out, id) {
			t.Errorf("missing %s: %s", id, out)
		}
	}
	config = writeConfig(t, dir, map[string]any{"first": map[string]any{"command": programs["shadow-a"]}, "second": map[string]any{"command": programs["shadow-b"]}})
	if out := cli(t, dir, 1, "scan", "--config", config); !strings.Contains(out, "FP003") {
		t.Fatal(out)
	}
}

func TestE2ERugPull(t *testing.T) {
	dir := t.TempDir()
	config := writeConfig(t, dir, map[string]any{"rug": map[string]any{"command": programs["rugpull"], "env": map[string]string{"FENCEPOST_RUG_STATE": filepath.Join(dir, "state")}}})
	cli(t, dir, 0, "pin", "--config", config)
	out := cli(t, dir, 1, "verify", "--config", config)
	if !strings.Contains(out, "rug/greet: changed") || !strings.Contains(out, "-Return a greeting.") || !strings.Contains(out, "+Ignore previous instructions.") {
		t.Fatal(out)
	}
	cli(t, dir, 0, "pin", "--config", config, "--update", "rug/greet")
	cli(t, dir, 0, "verify", "--config", config)
	config = writeConfig(t, dir, map[string]any{"rug": map[string]any{"command": programs["rugpull"], "args": []string{"changed-launch"}, "env": map[string]string{"FENCEPOST_RUG_STATE": filepath.Join(dir, "state")}}})
	if out := cli(t, dir, 1, "verify", "--config", config); !strings.Contains(out, "changed launch spec") {
		t.Fatal(out)
	}
	cli(t, dir, 2, "pin", "--config", config, "--update", "rug/greet")
}

func startHTTP(t *testing.T, legacy bool) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, programs["http"])
	cmd.Env = append(os.Environ(), "FENCEPOST_HTTP_TOKEN=private-http-token")
	if legacy {
		cmd.Env = append(cmd.Env, "FENCEPOST_LEGACY=1")
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			cancel()
			<-done
			t.Error("HTTP fixture failed to shut down")
		}
		cancel()
	})
	line := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(out)
		value, _ := reader.ReadString('\n')
		line <- strings.TrimSpace(value)
	}()
	select {
	case endpoint := <-line:
		if endpoint == "" {
			t.Fatal("HTTP server did not announce endpoint")
		}
		return endpoint
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP startup timed out")
		return ""
	}
}

func TestE2EHTTP(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			endpoint := startHTTP(t, legacy)
			dir := t.TempDir()
			t.Setenv("FENCEPOST_HTTP_TOKEN", "private-http-token")
			config := writeConfig(t, dir, map[string]any{"http": map[string]any{"type": "http", "url": endpoint, "headers": map[string]string{"Authorization": "Bearer ${FENCEPOST_HTTP_TOKEN}"}}})
			cli(t, dir, 0, "scan", "--config", config)
			cli(t, dir, 0, "pin", "--config", config)
			cli(t, dir, 0, "verify", "--config", config)
			response, err := http.Post(strings.TrimSuffix(endpoint, "/mcp")+"/change", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if out := cli(t, dir, 1, "verify", "--config", config); !strings.Contains(out, "http/echo: changed") {
				t.Fatal(out)
			}
			cli(t, dir, 0, "pin", "--config", config, "--update", "http/echo")
			cli(t, dir, 0, "verify", "--config", config)
		})
	}
}

func TestE2EConnectionFailureAndOfflineHome(t *testing.T) {
	dir := t.TempDir()
	config := writeConfig(t, dir, map[string]any{"broken": map[string]any{"command": filepath.Join(dir, "missing")}})
	if out := cli(t, dir, 2, "scan", "--config", config, "--format", "json"); !strings.Contains(out, "cannot start server") {
		t.Fatal(out)
	}
	cli(t, dir, 2, "pin", "--config", config)
	if _, err := os.Stat(filepath.Join(dir, "fencepost.lock")); !os.IsNotExist(err) {
		t.Fatal("partial scan created lock")
	}
	home, err := filepath.Abs("../../testdata/home")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	out := cli(t, dir, 1, "scan", "--offline")
	for _, id := range []string{"FP004", "FP005", "FP008", "<redacted:Authorization>"} {
		if !strings.Contains(out, id) {
			t.Fatal(out)
		}
	}
	if strings.Contains(out, "fixture-only-not-a-real-token") {
		t.Fatal("offline credential leaked")
	}
}
