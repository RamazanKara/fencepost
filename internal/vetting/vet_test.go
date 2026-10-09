package vetting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/pin"
)

func TestLaunchReferenceCustomRegistry(t *testing.T) {
	for _, tc := range []struct {
		command string
		args    []string
		want    string
	}{
		{"npx", []string{"--package", "fixture@1.2.3", "run"}, "npm:fixture@1.2.3"},
		{"npx", []string{"--package", "fixture@1.2.3", "run", "--registry=https://app.example"}, "npm:fixture@1.2.3"},
		{"docker", []string{"run", "fixture:1.2.3", "--registry=https://app.example"}, "oci:fixture:1.2.3"},
		{"npx", []string{"--package=fixture@1.2.3", "--registry=https://private.example", "run"}, ""},
		{"npx", []string{"--package", "fixture@1.2.3", "--registry=https://private.example", "run"}, ""},
		{"uvx", []string{"--from", "fixture==1.2.3", "--index-url", "https://private.example", "run"}, ""},
	} {
		if got := launchReference(clientconfig.Server{Command: tc.command, Args: tc.args}); got != tc.want {
			t.Errorf("%s %v: got %q want %q", tc.command, tc.args, got, tc.want)
		}
	}
}

func TestLocalPackages(t *testing.T) {
	t.Setenv("VET_SECRET_MUST_NOT_LEAK", "present")
	for _, name := range []string{"clean", "postinstall", "typosquat"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "testdata", "packages", name)
			r, err := Vet(context.Background(), path, true, filepath.Join(t.TempDir(), "missing.lock"))
			if err != nil || !r.Complete || len(r.Tools) != 1 || r.Tools[0] != "echo" {
				t.Fatalf("%+v %v", r, err)
			}
			text := strings.Join(r.Reasons, " ")
			if name == "postinstall" && !strings.Contains(text, "postinstall") {
				t.Fatal(text)
			}
			if name == "typosquat" && r.Verdict != "avoid" {
				t.Fatal(r)
			}
			if name == "clean" && len(r.Findings) != 0 {
				t.Fatal(r.Findings)
			}
			if _, err := os.Stat(filepath.Join(path, "POSTINSTALL-RAN")); !os.IsNotExist(err) {
				t.Fatal("install script ran")
			}
		})
	}
}

func TestMaintainerChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fencepost.lock")
	if err := pin.Write(path, pin.Lock{Version: 1, Servers: map[string]pin.Server{}, Packages: map[string]pin.Package{"npm:fencepost-fixture-clean": {Version: "0.9.0", Maintainers: []string{"previous-owner"}}}}); err != nil {
		t.Fatal(err)
	}
	r, err := Vet(context.Background(), "../../testdata/packages/clean", true, path)
	if err != nil || !strings.Contains(strings.Join(r.Reasons, " "), "Maintainers changed since pinned version 0.9.0") {
		t.Fatal(r, err)
	}
}

func TestPackageRiskSignals(t *testing.T) {
	for _, m := range []Metadata{{Name: "@modelcontextprotocol/server-filesytem"}, {Name: "@modelcontextprotocol/server-filesysetm"}, {Name: "mcp-server-fecth"}, {Name: "fresh", Published: time.Now()}, {Name: "hook", Scripts: []string{"postinstall"}}} {
		if len(concerns(m, time.Now())) == 0 {
			t.Fatal(m)
		}
	}
	if got := concerns(Metadata{Name: "@modelcontextprotocol/server-filesystem", Published: time.Now().Add(-30 * 24 * time.Hour)}, time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
}

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegistryMetadata(t *testing.T) {
	client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch r.URL.Host {
		case "registry.npmjs.org":
			body = `{"dist-tags":{"latest":"1.2.3"},"maintainers":[{"name":"current-owner"}],"time":{"1.2.3":"2025-01-01T00:00:00Z"},"versions":{"1.2.3":{"name":"fixture","version":"1.2.3","bin":"server.js","maintainers":[{"name":"old-owner"}],"scripts":{"postinstall":"never execute"}}}}`
		case "pypi.org":
			body = `{"info":{"name":"fixture","version":"1.2.3","maintainer":"python-owner"},"urls":[{"upload_time_iso_8601":"2025-01-01T00:00:00Z"}]}`
		case "registry.modelcontextprotocol.io":
			body = `{"server":{"name":"io.example/fixture","version":"1.2.3","packages":[{"registryType":"npm","identifier":"fixture","version":"1.2.3"}]}}`
		default:
			t.Fatalf("unexpected endpoint %s", r.URL.Host)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	for _, ref := range []string{"fixture", "npm:fixture@1.2.3", "pypi:fixture==1.2.3", "mcp:io.example/fixture"} {
		m, err := metadata(context.Background(), ref, client)
		if err != nil || m.Version != "1.2.3" || m.Published.IsZero() {
			t.Fatal(m, err)
		}
		if m.Kind == "npm" && (len(m.Scripts) != 1 || m.Maintainers[0] != "current-owner") {
			t.Fatal(m)
		}
	}
	for _, ref := range []string{"npm:--help", "npm:foo@../escape", "pypi:--index-url=x", "mcp:../../evil", "https://user:secret@example.com/mcp"} {
		if _, err := metadata(context.Background(), ref, client); err == nil {
			t.Fatal(ref)
		}
	}
}

func TestLocalEntryCannotEscape(t *testing.T) {
	dir := t.TempDir()
	data, _ := json.Marshal(npmPackage{Name: "escape", Version: "1.0.0", Bin: json.RawMessage(`"../../outside.js"`)})
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := metadata(context.Background(), dir, client())
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, _, err := prepare(context.Background(), m, t.TempDir(), true)
	defer cleanup()
	if err == nil {
		t.Fatal("escaped package executable accepted")
	}
}

func TestNoNetworkWithoutIsolation(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, _, err := sandbox(context.Background(), t.TempDir(), false)
	if err == nil {
		t.Fatal("unisolated process would run without --net")
	}
}
