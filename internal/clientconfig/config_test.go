package clientconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMalformedProjects(t *testing.T) {
	for _, raw := range []string{`{"projects":["."]}`, `{"projects":"."}`} {
		t.Run(raw, func(t *testing.T) {
			defer func() {
				if failure := recover(); failure != nil {
					t.Errorf("malformed projects caused a panic: %v", failure)
				}
			}()
			if _, err := Parse([]byte(raw), "config", "."); err == nil {
				t.Error("accepted a non-object projects field")
			}
		})
	}
}

func TestFormats(t *testing.T) {
	for _, test := range []struct {
		file      string
		names     []string
		line      int
		transport string
	}{
		{"claude-desktop.json", []string{"desktop"}, 3, "stdio"},
		{"claude-code-project.json", []string{"project"}, 3, "http"},
		{"claude-code-user.json", []string{"user", "local"}, 3, "stdio"},
		{"claude-code-settings.json", []string{"settings"}, 3, "stdio"},
		{"cursor.json", []string{"cursor"}, 3, "http"},
		{"vscode-mcp.json", []string{"vscode"}, 4, "stdio"},
		{"vscode-settings.json", []string{"vscode-settings"}, 5, "http"},
		{"vscode-dotted-settings.json", []string{"vscode-dotted"}, 3, "stdio"},
		{"windsurf.json", []string{"windsurf"}, 3, "http"},
	} {
		t.Run(test.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../testdata/configs", test.file))
			if err != nil {
				t.Fatal(err)
			}
			servers, err := Parse(data, test.file, "PROJECT")
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, s := range servers {
				names = append(names, s.Name)
				if s.Source != test.file {
					t.Fatal("source lost")
				}
			}
			if !reflect.DeepEqual(names, test.names) || servers[0].Line != test.line || servers[0].Transport != test.transport {
				t.Fatalf("incorrect normalization: %+v", servers)
			}
			if test.file == "vscode-mcp.json" && servers[0].Args[0] != "https://example.invalid/*keep*/" {
				t.Fatal("comment cleanup changed string")
			}
		})
	}
}

func TestOSPaths(t *testing.T) {
	for _, platform := range []string{"windows", "darwin", "linux"} {
		p := Paths{OS: platform, Home: filepath.Join("root", "home"), Project: filepath.Join("root", "project")}
		paths := Candidates(p)
		base := filepath.Join(p.Home, ".config")
		if platform == "windows" {
			base = filepath.Join(p.Home, "AppData", "Roaming")
		}
		if platform == "darwin" {
			base = filepath.Join(p.Home, "Library", "Application Support")
		}
		for _, want := range []string{filepath.Join(base, "Claude", "claude_desktop_config.json"), filepath.Join(base, "Code", "User", "settings.json"), filepath.Join(base, "Code", "User", "mcp.json"), filepath.Join(p.Home, ".claude.json"), filepath.Join(p.Project, ".mcp.json"), filepath.Join(p.Home, ".cursor", "mcp.json"), filepath.Join(p.Project, ".cursor", "mcp.json"), filepath.Join(p.Project, ".vscode", "mcp.json"), filepath.Join(p.Home, ".codeium", "windsurf", "mcp_config.json")} {
			found := false
			for _, got := range paths {
				if got == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%s missing %s", platform, want)
			}
		}
	}
	for _, p := range []Paths{{OS: "windows", Home: "home", AppData: "roaming"}, {OS: "linux", Home: "home", XDG: "xdg"}} {
		base := p.AppData
		if base == "" {
			base = p.XDG
		}
		if got := Candidates(p)[0]; got != filepath.Join(base, "Claude", "claude_desktop_config.json") {
			t.Fatal(got)
		}
	}
}

func TestDiscovery(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	p := Paths{OS: "linux", Home: home, Project: project}
	path := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"test":{"command":"server"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	servers, err := Discover(p, "")
	if err != nil || len(servers) != 1 {
		t.Fatalf("%+v %v", servers, err)
	}
	if _, err := Discover(p, filepath.Join(home, "missing.json")); err == nil {
		t.Fatal("explicit missing config ignored")
	}
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte("broken secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(p, ""); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("bad config not reported safely")
	}
	if servers, err := Discover(p, path); err != nil || len(servers) != 1 {
		t.Fatal("explicit config did not isolate discovery")
	}
}

func TestMalformedAndDisabled(t *testing.T) {
	for _, data := range []string{`[]`, `{"mcpServers":[]}`, `{"mcpServers":{"x":{"args":[]}}}`, `{"mcpServers":{"x":{"command":"x","url":"https://x"}}}`, `{"mcpServers":{"x":{"command":"x","args":"secret"}}}`, `{/* unclosed`, `{"mcpServers":{"x":true}}`} {
		if _, err := Parse([]byte(data), "config", ""); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
	servers, err := Parse([]byte(`{"mcpServers":{"off":{"disabled":true}}}`), "config", "")
	if err != nil || len(servers) != 0 {
		t.Fatal("disabled server not skipped")
	}
}

func TestResolveAndRedact(t *testing.T) {
	t.Setenv("FENCEPOST_TEST_TOKEN", "private-value")
	s := Server{Name: "test", Command: "${COMMAND:-server}", Args: []string{"${env:FENCEPOST_TEST_TOKEN}"}, Env: map[string]string{"KEY": "${FENCEPOST_TEST_TOKEN}", "DEFAULT": "${ABSENT:-fallback}"}, Headers: map[string]string{"Authorization": "Bearer ${env.FENCEPOST_TEST_TOKEN}"}}
	resolved, err := Resolve(s, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Command != "server" || resolved.Args[0] != "private-value" || resolved.Env["DEFAULT"] != "fallback" || resolved.Headers["Authorization"] != "Bearer private-value" {
		t.Fatalf("expansion: %+v", resolved)
	}
	if s.Env["KEY"] != "${FENCEPOST_TEST_TOKEN}" {
		t.Fatal("mutated config")
	}
	if got := Redact("private-value", []Server{s}); got != "<redacted:FENCEPOST_TEST_TOKEN>" {
		t.Fatal(got)
	}
	if _, err := Resolve(Server{Command: "${missing_variable}"}, os.LookupEnv); err == nil {
		t.Fatal("missing variable accepted")
	}
	if _, err := Resolve(Server{Command: "${input:token}"}, os.LookupEnv); err == nil {
		t.Fatal("interactive input accepted")
	}
	s.Env["KEY"] = "ghp_0123456789abcdefghij"
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "ghp_") {
		t.Fatal("serialized raw credential")
	}
	if got := Redact(s.Env["KEY"], []Server{s}); got != "<redacted:KEY>" {
		t.Fatal(got)
	}
}

func TestCleanEnv(t *testing.T) {
	t.Setenv("FENCEPOST_AMBIENT_SECRET", "must-not-inherit")
	env := CleanEnv(map[string]string{"DECLARED_TOKEN": "explicit"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "must-not-inherit") || !strings.Contains(joined, "DECLARED_TOKEN=explicit") {
		t.Fatal("unsafe environment")
	}
}

func TestRedactBearerAndFallback(t *testing.T) {
	servers := []Server{{Headers: map[string]string{"Authorization": "Bearer private-header-value"}, Env: map[string]string{"TOKEN": "${TOKEN:-private-fallback-value}", "MODE": "1"}}}
	got := Redact("1 private-header-value private-fallback-value", servers)
	if got != "1 <redacted:Authorization> <redacted:TOKEN>" {
		t.Fatal(got)
	}
}
