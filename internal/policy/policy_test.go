package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func testPolicy(t *testing.T, rule Argument) *Policy {
	t.Helper()
	data, err := yaml.Marshal(map[string]any{"version": 1, "servers": map[string]any{"s": Server{Default: "deny", Tools: []Tool{{Name: "read_*", Action: "allow", Arguments: []Argument{rule}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "safe"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, Argument{Path: "$.path", PathPrefix: []string{root}})
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{filepath.Join(root, "safe"), true}, {filepath.Join(root, "new", "file"), true},
		{outside, false}, {root + "-other/file", false}, {"safe", false},
		{root + string(filepath.Separator) + ".." + string(filepath.Separator) + "safe", false},
		{root + "/%2e%2e/secret", false}, {root + "/%252e%252e/secret", false},
		{root + "/file\x00", false}, {"file://" + root + "/safe", false},
	} {
		a, _, _ := p.Match("s", "read_file", map[string]any{"path": tc.path})
		if (a == "allow") != tc.allow {
			resolved, err := resolvePath(tc.path)
			t.Errorf("%q: %s; resolved=%q err=%v rule=%+v allowed=%t", tc.path, a, resolved, err, p.Servers["s"].Tools[0].Arguments[0], pathAllowed(tc.path, []string{root}))
		}
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(root, "escape")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		for _, name := range []string{link, filepath.Join(link, "new"), link + "/../safe"} {
			if a, _, _ := p.Match("s", "read_file", map[string]any{"path": name}); a != "deny" {
				t.Fatalf("symlink escape allowed: %s", name)
			}
		}
	})
}

func TestHosts(t *testing.T) {
	p := testPolicy(t, Argument{Path: "$.url", Host: []string{"example.com", "bücher.example", "127.0.0.1", "::1"}})
	for _, tc := range []struct {
		url   string
		allow bool
	}{
		{"https://example.com/a", true}, {"https://EXAMPLE.com.:443/a", true}, {"https://bücher.example/", true}, {"https://xn--bcher-kva.example/", true},
		{"http://127.0.0.1/a", true}, {"http://[::1]/", true},
		{"https://example.com@evil.test/", false}, {"https://evil@example.com/", false}, {"https://example.com.evil.test/", false},
		{"https://еxample.com/", false}, {"http://2130706433/", false}, {"http://0177.0.0.1/", false}, {"http://0x7f000001/", false}, {"http://127.1/", false},
		{"http://[::ffff:127.0.0.1]/", false}, {"http://[fe80::1%25eth0]/", false}, {"http://127。0。0。1/", false},
		{"https://example.com\\@evil.test/", false}, {"https://%65xample.com/", false}, {"file://example.com/", false}, {"https://example.com:99999/", false},
	} {
		a, _, _ := p.Match("s", "read_url", map[string]any{"url": tc.url})
		if (a == "allow") != tc.allow {
			t.Errorf("%s: %s", tc.url, a)
		}
	}
}

func TestRules(t *testing.T) {
	max := 4
	p := testPolicy(t, Argument{Path: "$.items[*].value", Regex: "^[a-z]+$", MaxLength: &max, Enum: []any{"safe", "yes"}})
	for _, tc := range []struct {
		args  map[string]any
		allow bool
	}{
		{map[string]any{"items": []any{map[string]any{"value": "safe"}, map[string]any{"value": "yes"}}}, true},
		{map[string]any{"items": []any{map[string]any{"value": "safe"}, map[string]any{"value": "no"}}}, false},
		{map[string]any{"items": []any{}}, false}, {map[string]any{}, false}, {map[string]any{"items": "safe"}, false},
	} {
		a, _, _ := p.Match("s", "read_file", tc.args)
		if (a == "allow") != tc.allow {
			t.Errorf("%v: %s", tc.args, a)
		}
	}
	if a, _, _ := p.Match("other", "read_file", nil); a != "deny" {
		t.Fatal(a)
	}
	if a, _, _ := p.Match("s", "write_file", nil); a != "deny" {
		t.Fatal(a)
	}
}

func TestInvalidPolicies(t *testing.T) {
	for _, s := range []string{
		"version: 2\nservers: {}", "version: 1\nservers: {s: {default: yep}}", "version: 1\nservers: {s: {default: allow, typo: true}}",
		"version: 1\nservers: {s: {default: deny}}\nsession_budget: -1", "version: 1\nservers: {s: {default: deny}}\n---\n{}",
		"version: 1\nservers: {s: {default: deny, tools: [{name: '[', action: allow}]}}",
		"version: 1\nservers: {s: {default: deny, tools: [{name: '*', action: allow, arguments: [{path: '$.x', host: []}]}]}}",
		"version: 1\nservers: {s: {default: deny}}\napproval: {mode: webhook, webhook_url: 'http://evil.test', hmac_secret_env: KEY}",
	} {
		if _, err := Parse([]byte(s), t.TempDir()); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func FuzzMatcher(f *testing.F) {
	for _, s := range []string{`{"url":"https://example.com"}`, `{"url":"http://2130706433"}`, `{"items":[]}`, `null`} {
		f.Add("read_file", s)
	}
	p, err := Parse([]byte("version: 1\nservers:\n  s:\n    default: deny\n    tools:\n      - name: read_*\n        action: allow\n        arguments:\n          - path: $.url\n            host: [example.com]\n            max_length: 1000\n"), f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, name, raw string) {
		if len(raw) > 64<<10 || len(name) > 1024 {
			t.Skip()
		}
		var args map[string]any
		if json.Unmarshal([]byte(raw), &args) != nil {
			return
		}
		a, _, _ := p.Match("s", name, args)
		if a != "allow" && a != "deny" {
			t.Fatal(a)
		}
	})
}

func TestToolBudgetValidation(t *testing.T) {
	for _, value := range []string{"-1", "1.5", "0.5", "1e2", "true", "null", "'2'", "[]", "{}", "999999999999999999999999"} {
		if _, err := Parse([]byte("version: 1\nservers: {s: {default: deny, tools: [{name: echo, action: allow, budget: "+value+"}]}}"), t.TempDir()); err == nil {
			t.Fatalf("accepted invalid budget %s", value)
		}
	}
	if _, err := Parse([]byte("version: 1\nservers: {s: {default: deny, tools: [{name: echo, action: allow, rate_limit: &fraction 1.5, budget: *fraction}]}}"), t.TempDir()); err == nil {
		t.Fatal("accepted an aliased fractional budget")
	}
	if _, err := Parse([]byte("version: 1\nservers: {s: {default: deny, tools: [{<<: {name: echo, action: allow, budget: 1.5}}]}}"), t.TempDir()); err == nil {
		t.Fatal("accepted a merged fractional budget")
	}
	p, err := Parse([]byte("version: 1\nservers: {s: {default: deny, tools: [{name: echo, action: allow, groups: [admin], budget: 9}, {name: '*', action: allow, rate_limit: 2, budget: 3}]}}"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id     Identity
		budget int
	}{{Identity{}, 3}, {Identity{Groups: []string{"admin"}}, 9}} {
		got, _, _, budget := p.MatchIdentity("s", "echo", nil, tc.id)
		if got != "allow" || budget != tc.budget {
			t.Fatal(got, budget)
		}
	}
}

func FuzzPolicy(f *testing.F) {
	for _, seed := range []string{
		"version: 1\nservers: {s: {default: deny, tools: [{name: '*', action: allow, budget: 3, rate_limit: 5}]}}",
		"version: 1\nservers: {s: {default: allow}}\nsession_budget: -1",
		"version: 1\nservers: {s: {default: allow}}\nsession_budget: 0.5",
		"version: 1\nservers: {s: {default: deny, tools: [{name: echo, action: allow, rate_limit: 0.5}]}}",
		"version: 1\nservers: &s {s: *s}", "version: 1\nversion: 2", "null", "{}", "---\n---",
	} {
		f.Add(seed)
	}
	base := f.TempDir()
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16<<10 {
			t.Skip()
		}
		p, err := Parse([]byte(raw), base)
		if err != nil {
			return
		}
		if p.Version != 1 || p.SessionBudget < 0 {
			t.Fatal("invalid policy accepted")
		}
		for _, server := range p.Servers {
			for _, tool := range server.Tools {
				if tool.Budget < 0 || tool.RateLimit < 0 {
					t.Fatal("negative tool limit accepted")
				}
			}
		}
	})
}

func TestFractionalCallLimits(t *testing.T) {
	for _, raw := range []string{
		"version: 1\nservers: {s: {default: allow}}\nsession_budget: 0.5",
		"version: 1\nservers: {s: {default: deny, tools: [{name: '*', action: allow, rate_limit: 0.5}]}}",
	} {
		if _, err := Parse([]byte(raw), t.TempDir()); err == nil {
			t.Error("fractional call limit silently became unlimited")
		}
	}
}
