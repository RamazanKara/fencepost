//go:build e2e

package report

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestSARIFSchema(t *testing.T) {
	result, servers := example()
	var out bytes.Buffer
	if err := SARIF(&out, Clean(result, servers)); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python", "-c", `import json, sys, jsonschema; schema=json.load(open('testdata/sarif-schema-2.1.0.json', encoding='utf-8')); jsonschema.Draft7Validator.check_schema(schema); jsonschema.Draft7Validator(schema).validate(json.load(sys.stdin))`)
	cmd.Stdin = &out
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("SARIF schema validation requires Python and jsonschema==4.26.0: %v\n%s", err, output)
	}
}
