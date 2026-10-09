package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/RamazanKara/fencepost/internal/policy"
)

func TestPackInitAndLocalCommandBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"init", "--pack", "filesystem,git", "--policy", path}, 0},
		{[]string{"init", "--pack", "filesystem,git", "--policy", path}, 2},
		{[]string{"init", "--pack", "git", "--server", "custom"}, 2},
		{[]string{"init", "--pack", "unknown"}, 2},
		{[]string{"vet"}, 2},
		{[]string{"vet", "--help"}, 0},
		{[]string{"ui", "--help"}, 0},
		{[]string{"ui", "--listen", "0.0.0.0:0"}, 2},
		{[]string{"rules", "update", "--url", "http://untrusted.example/rules"}, 2},
		{[]string{"rules", "update", "--help"}, 0},
	} {
		var out, errs bytes.Buffer
		if code := run(context.Background(), tc.args, &out, &errs); code != tc.code {
			t.Fatalf("%v: %d %s %s", tc.args, code, &out, &errs)
		}
	}
	p, err := policy.Read(path)
	if err != nil || len(p.Servers) != 2 {
		t.Fatal(p, err)
	}
	if _, err := os.Stat("fencepost.yaml"); !os.IsNotExist(err) {
		t.Fatal("failed init created a policy")
	}
}
