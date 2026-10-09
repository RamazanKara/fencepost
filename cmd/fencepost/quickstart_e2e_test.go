//go:build e2e

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestREADMEQuickstart(t *testing.T) {
	var start time.Time
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(data), "<!-- quickstart -->")
	if !ok {
		t.Fatal("missing README quickstart")
	}
	block, _, ok = strings.Cut(block, "<!-- /quickstart -->")
	if !ok {
		t.Fatal("unterminated README quickstart")
	}
	block = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(block), "```sh"), "```"))
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "examples"), 0700); err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("../../examples/denied-call.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "examples", "denied-call.json"), example, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "bin", "fencepost")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for i, line := range strings.Split(block, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var cmd *exec.Cmd
		want := 0
		if i == 0 {
			if strings.Join(fields, " ") != "go build -o bin/ ./cmd/fencepost" {
				t.Fatalf("unexpected build command: %s", line)
			}
			// Keep the documented build output isolated from the checkout.
			cmd = exec.CommandContext(ctx, "go", "build", "-o", filepath.Dir(binary)+string(filepath.Separator), "./cmd/fencepost")
			cmd.Dir = "../.."
		} else {
			if i == 1 {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				start = time.Now()
			}
			if fields[0] != "./bin/fencepost" {
				t.Fatalf("unexpected quickstart command: %s", line)
			}
			cmd = exec.CommandContext(ctx, binary, fields[1:]...)
			cmd.Dir = dir
			if fields[1] == "explain" {
				want = 1
			}
		}
		output, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatalf("%s: exit %d want %d: %s", line, code, want, output)
		}
		if want == 1 && !strings.Contains(string(output), "DENY: no tool rule matched; using server default (default).") {
			t.Fatalf("unexpected explanation: %s", output)
		}
	}
	t.Logf("README walkthrough completed in %s (build setup excluded)", time.Since(start))
}
