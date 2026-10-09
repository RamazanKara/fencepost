//go:build e2e

package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExampleSchemas(t *testing.T) {
	paths, err := filepath.Glob("../../examples/*.yaml")
	if err != nil || len(paths) != 3 {
		t.Fatal(paths, err)
	}
	paths = append(paths, "../../examples/gateway/policy.yaml", "../../examples/agentworkflows/policy.yaml")
	packPaths, err := filepath.Glob("../../packs/*.yaml")
	if err != nil || len(packPaths) != 7 {
		t.Fatal(packPaths, err)
	}
	paths = append(paths, packPaths...)
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data, filepath.Dir(path)); err != nil {
				t.Fatal(err)
			}
			var value any
			if err := yaml.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("python", "-c", `import json,sys,jsonschema; s=json.load(open('../../schema/policy.schema.json')); jsonschema.Draft202012Validator.check_schema(s); jsonschema.Draft202012Validator(s,format_checker=jsonschema.FormatChecker()).validate(json.load(sys.stdin))`)
			cmd.Stdin = bytes.NewReader(encoded)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("policy schema: %v\n%s", err, out)
			}
		})
	}
}
