package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/scan"
)

func example() (scan.Result, []clientconfig.Server) {
	servers := []clientconfig.Server{{Name: "server\x1b[31m", Source: "config.json", Line: 3, Command: "npx", Args: []string{"-y", "pkg"}, Headers: map[string]string{"Authorization": "Bearer secret-fixture-value"}, URL: "http://example.invalid/mcp"}}
	return scan.Audit(servers, nil), servers
}

func TestFormatsAndRedaction(t *testing.T) {
	result, servers := example()
	result.Errors = append(result.Errors, scan.ConnectionError{Server: "server", Source: "config.json", Message: "Bearer secret-fixture-value"})
	result = Clean(result, servers)
	for _, format := range []string{"table", "json", "sarif"} {
		var out bytes.Buffer
		var err error
		switch format {
		case "table":
			err = Table(&out, result, false)
		case "json":
			err = JSON(&out, result)
		case "sarif":
			err = SARIF(&out, result)
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "secret-fixture-value") || strings.Contains(out.String(), "\x1b") {
			t.Fatalf("%s leaked secret/control", format)
		}
		if !strings.Contains(out.String(), "<redacted:Authorization>") {
			t.Fatalf("%s lacks placeholder", format)
		}
		if format != "table" && !json.Valid(out.Bytes()) {
			t.Fatal("invalid JSON")
		}
	}
}

func TestSARIFStructure(t *testing.T) {
	result, servers := example()
	var out bytes.Buffer
	if err := SARIF(&out, Clean(result, servers)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string
			}
			Tool struct {
				Driver struct{ Rules []struct{ ID string } }
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) != 8 {
		t.Fatal("invalid SARIF metadata")
	}
	for _, r := range doc.Runs[0].Results {
		if doc.Runs[0].Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Fatal("bad rule index")
		}
	}
}
