//go:build e2e

package helm

import (
	"os/exec"
	"strings"
	"testing"
)

func TestHelmTemplates(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed")
	}
	for _, test := range []struct {
		name   string
		values []string
		want   string
	}{
		{"defaults", nil, "readOnlyRootFilesystem: true"},
		{"network", []string{"--set", "networkPolicy.enabled=true"}, "kind: NetworkPolicy"},
		{"persistent", []string{"--set", "persistence.enabled=true", "--set", "persistence.existingClaim=audit-data", "--set", "image.repository=registry.example/fencepost"}, "claimName: audit-data"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"template", "test", "./fencepost"}, test.values...)
			out, err := exec.Command(helm, args...).CombinedOutput()
			if err != nil || !strings.Contains(string(out), test.want) {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}
