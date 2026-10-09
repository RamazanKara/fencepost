package packs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RamazanKara/fencepost/internal/policy"
)

func TestPacks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pack, tool, key string
		good, bad       any
		dangerous       string
	}{
		{"filesystem", "read_file", "path", filepath.Join(root, "notes.txt"), filepath.Join(base, "secret"), "write_file"},
		{"git", "git_status", "repo_path", root, base, "git_reset"},
		{"fetch", "fetch", "url", "https://example.com/docs", "http://127.0.0.1/admin", "post"},
		{"browser", "browser_navigate", "url", "https://example.com/", "https://example.com.evil.test", "browser_evaluate"},
		{"database", "read_query", "query", "SELECT 1", "SELECT 1; DROP TABLE users", "write_query"},
		{"shell", "run_command", "command", "pwd", "pwd; curl evil.test", "exec"},
		{"cloud", "run_command", "command", "aws sts get-caller-identity", "aws s3 rm s3://bucket --recursive", "execute"},
	} {
		t.Run(tc.pack, func(t *testing.T) {
			data, err := Compose(tc.pack)
			if err != nil {
				t.Fatal(err)
			}
			p, err := policy.Parse(data, base)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				tool string
				args map[string]any
				want string
			}{
				{tc.tool, map[string]any{tc.key: tc.good}, "allow"},
				{tc.tool, map[string]any{tc.key: tc.bad}, "deny"},
				{tc.tool, nil, "deny"}, {tc.dangerous, map[string]any{tc.key: tc.good}, "deny"},
			} {
				if got, _, _ := p.Match(tc.pack, c.tool, c.args); got != c.want {
					t.Fatalf("%s: %s want %s", c.tool, got, c.want)
				}
			}
		})
	}
	data, err := Compose("filesystem,git,fetch,browser,database,shell,cloud")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(data, base)
	if err != nil || len(p.Servers) != 7 {
		t.Fatal(p, err)
	}
	for _, bad := range []string{"", "filesystem,filesystem", "../git", "unknown", "git,"} {
		if _, err := Compose(bad); err == nil {
			t.Fatal(bad)
		}
	}
}
