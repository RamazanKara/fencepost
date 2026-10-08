package clientconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWrapFormats(t *testing.T) {
	files, err := filepath.Glob("../../testdata/configs/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			before, err := Parse(original, file, "PROJECT")
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := Wrap(original, file, "PROJECT", "/bin/fencepost", "/policy.yaml", "/fencepost.lock")
			if err != nil {
				t.Fatal(err)
			}
			after, err := Parse(wrapped, file, "PROJECT")
			if err != nil || len(after) != len(before) {
				t.Fatal(err, len(before), len(after))
			}
			for _, s := range after {
				if s.Command != "/bin/fencepost" || s.Transport != "stdio" || len(s.Args) < 5 {
					t.Fatalf("%+v", s)
				}
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := Apply(Edit{path, original, wrapped}, false); err != nil {
				t.Fatal(err)
			}
			backup, _ := os.ReadFile(path + ".fencepost.bak")
			if !bytes.Equal(backup, original) {
				t.Fatal("backup changed")
			}
			if err := Apply(Edit{path, wrapped, original}, true); err != nil {
				t.Fatal(err)
			}
			restored, _ := os.ReadFile(path)
			if !bytes.Equal(restored, original) {
				t.Fatal("restore changed")
			}
		})
	}
}

func TestWrapDryRunAndBackupRefusal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	original := []byte(`{"mcpServers":{"s":{"command":"server"}}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	p := Paths{Project: dir}
	edits, err := PlanWrap(p, path, "fencepost", "policy.yaml", "lock", false)
	if err != nil || len(edits) != 1 {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(current, original) {
		t.Fatal("dry run changed config")
	}
	if _, err := os.Stat(path + ".fencepost.bak"); !os.IsNotExist(err) {
		t.Fatal("dry run wrote backup")
	}
	if err := Apply(edits[0], false); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanWrap(p, path, "fencepost", "policy.yaml", "lock", false); err == nil {
		t.Fatal("would overwrite backup")
	}
}
