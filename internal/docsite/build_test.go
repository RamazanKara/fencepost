package docsite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildDocumentation(t *testing.T) {
	dir := t.TempDir()
	if err := Build("../..", dir); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"index.html", "docs/policy.html", "docs/PROTOCOL.html", "style.css", ".nojekyll", "schema/policy.schema.json"} {
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Fatal(err)
		}
	}
	index, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(index), `href="docs/policy.html`) || !strings.Contains(string(index), "<table>") {
		t.Fatal("Markdown links or tables missing")
	}
	p, _ := os.ReadFile(filepath.Join(dir, "docs/policy.html"))
	if !strings.Contains(string(p), `id="operator-commands"`) || !strings.Contains(string(p), `href="../style.css"`) {
		t.Fatal("heading anchors or relative assets missing")
	}
}
