package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"test":{"command":"this-must-never-start","env":{"API_TOKEN":"secret-for-test"},"args":[]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"table", "json", "sarif"} {
		var out, errOut bytes.Buffer
		code := run(context.Background(), []string{"scan", "--offline", "--config", path, "--format", format}, &out, &errOut)
		if code != 1 || errOut.Len() != 0 || !strings.Contains(out.String(), "FP005") || strings.Contains(out.String(), "secret-for-test") {
			t.Fatalf("%s code=%d out=%s err=%s", format, code, &out, &errOut)
		}
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"scan", "--offline", "--config", path, "--fail-on", "critical"}, &out, &errOut); code != 0 {
		t.Fatalf("threshold: %d %s", code, &errOut)
	}
}

func TestCLIUsage(t *testing.T) {
	for _, test := range []struct {
		args []string
		code int
	}{{nil, 0}, {[]string{"--help"}, 0}, {[]string{"proxy"}, 2}, {[]string{"scan", "--format", "wrong"}, 2}, {[]string{"scan", "--fail-on", "wrong"}, 2}, {[]string{"scan", "--help"}, 0}, {[]string{"pin", "--offline"}, 2}, {[]string{"verify", "extra"}, 2}} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), test.args, &out, &errOut); code != test.code {
			t.Errorf("%v: %d", test.args, code)
		}
	}
}
