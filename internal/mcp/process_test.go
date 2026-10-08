package mcp

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
)

func TestStdioChild(t *testing.T) {
	mode := os.Getenv("FENCEPOST_CHILD_MODE")
	if mode == "" {
		return
	}
	if os.Getenv("FENCEPOST_AMBIENT_SECRET") != "" {
		os.Exit(9)
	}
	if mode == "hang" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := os.WriteFile(os.Getenv("FENCEPOST_CHILD_MARKER"), []byte("stdin closed"), 0600); err != nil {
		os.Exit(8)
	}
	os.Exit(0)
}

func TestProcessLifecycle(t *testing.T) {
	t.Setenv("FENCEPOST_AMBIENT_SECRET", "must-not-inherit")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"graceful", "hang"} {
		t.Run(mode, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "closed")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			p, err := startStdio(ctx, clientconfig.Server{Command: executable, Args: []string{"-test.run=^TestStdioChild$"}, Env: map[string]string{"FENCEPOST_CHILD_MODE": mode, "FENCEPOST_CHILD_MARKER": marker, "GORACE": "atexit_sleep_ms=0"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.close(); err != nil {
				t.Fatal(err)
			}
			if mode == "graceful" {
				if _, err := os.Stat(marker); err != nil {
					t.Fatal("child did not receive clean env and stdin EOF:", err)
				}
			}
			if p.cmd.ProcessState == nil {
				t.Fatal("child was not reaped")
			}
		})
	}
}
