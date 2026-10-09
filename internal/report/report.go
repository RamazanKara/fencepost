package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/scan"
	"github.com/RamazanKara/fencepost/internal/version"
)

func Safe(text string, servers []clientconfig.Server) string {
	text = clientconfig.Redact(text, servers)
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) {
			return '�'
		}
		return r
	}, text)
}

func Clean(result scan.Result, servers []clientconfig.Server) scan.Result {
	clean := result
	clean.Findings = append([]scan.Finding{}, result.Findings...)
	clean.Errors = append([]scan.ConnectionError{}, result.Errors...)
	for i := range clean.Findings {
		f := &clean.Findings[i]
		for _, value := range []*string{&f.Server, &f.Tool, &f.Source, &f.Explanation, &f.Fix} {
			*value = Safe(*value, servers)
		}
	}
	for i := range clean.Errors {
		e := &clean.Errors[i]
		e.Server = Safe(e.Server, servers)
		e.Source = Safe(e.Source, servers)
		e.Message = Safe(e.Message, servers)
	}
	return clean
}

func IsTTY(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func Table(w io.Writer, result scan.Result, color bool) error {
	last := ""
	tab := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, f := range result.Findings {
		group := f.Server + "\x00" + f.Source
		if group != last {
			if err := tab.Flush(); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "\n%s (%s)\n", oneLine(f.Server), oneLine(f.Source)); err != nil {
				return err
			}
			last = group
		}
		severity := strings.ToUpper(f.Severity)
		if color {
			code := "33"
			if scan.Rank(f.Severity) >= 3 {
				code = "31"
			}
			severity = "\x1b[" + code + "m" + severity + "\x1b[0m"
		}
		tool := f.Tool
		if tool == "" {
			tool = "config"
		}
		_, err := fmt.Fprintf(tab, "  %s\t%-6s\t%s\t%s:%d\n", f.RuleID, severity, f.Title, oneLine(tool), max(1, f.Line))
		if err != nil {
			return err
		}
		if f.RuleID == "FP005" {
			if _, err = fmt.Fprintf(tab, "    %s\n", oneLine(f.Explanation)); err != nil {
				return err
			}
		}
	}
	if err := tab.Flush(); err != nil {
		return err
	}
	for _, err := range result.Errors {
		if _, e := fmt.Fprintf(w, "\nERROR %s: %s\n", oneLine(err.Server), oneLine(err.Message)); e != nil {
			return e
		}
	}
	_, err := fmt.Fprintf(w, "\n%d server(s), %d finding(s), %d connection error(s)\n", result.Servers, len(result.Findings), len(result.Errors))
	return err
}

func oneLine(s string) string { return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s) }

func JSON(w io.Writer, result scan.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func SARIF(w io.Writer, result scan.Result) error {
	rules := []any{}
	indices := map[string]int{}
	for i, r := range scan.Rules {
		indices[r.ID] = i
		rules = append(rules, map[string]any{"id": r.ID, "name": strings.ReplaceAll(r.Title, " ", ""), "shortDescription": map[string]string{"text": r.Title}, "fullDescription": map[string]string{"text": r.Explanation}, "help": map[string]string{"text": r.Fix}, "helpUri": "https://github.com/RamazanKara/fencepost/blob/main/docs/rules.md#" + strings.ToLower(r.ID) + "-" + strings.ReplaceAll(strings.ToLower(r.Title), " ", "-"), "properties": map[string]string{"security-severity": securitySeverity(r.Severity)}})
	}
	results := []any{}
	for _, f := range result.Findings {
		path := f.Source
		if abs, err := filepath.Abs(path); err == nil {
			if cwd, err := os.Getwd(); err == nil {
				if rel, err := filepath.Rel(cwd, abs); err == nil && !strings.HasPrefix(rel, "..") {
					path = rel
				}
			}
		}
		path = filepath.ToSlash(path)
		uri := (&url.URL{Path: path}).String()
		if filepath.IsAbs(f.Source) && path == filepath.ToSlash(f.Source) {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			uri = (&url.URL{Scheme: "file", Path: path}).String()
		}
		level := "note"
		if f.Severity == "medium" {
			level = "warning"
		}
		if scan.Rank(f.Severity) >= 3 {
			level = "error"
		}
		results = append(results, map[string]any{"ruleId": f.RuleID, "ruleIndex": indices[f.RuleID], "level": level, "message": map[string]string{"text": f.Server + toolSuffix(f.Tool) + ": " + f.Explanation + " Fix: " + f.Fix}, "locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": uri}, "region": map[string]int{"startLine": max(1, f.Line)}}}}, "properties": map[string]string{"server": f.Server, "tool": f.Tool}})
	}
	notifications := []any{}
	for _, e := range result.Errors {
		notifications = append(notifications, map[string]any{"level": "error", "message": map[string]string{"text": e.Server + ": " + e.Message}})
	}
	document := map[string]any{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "fencepost", "version": version.Version, "informationUri": "https://github.com/RamazanKara/fencepost", "rules": rules}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": len(result.Errors) == 0, "toolExecutionNotifications": notifications}}}}}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

func toolSuffix(tool string) string {
	if tool == "" {
		return ""
	}
	return "/" + tool
}
func securitySeverity(severity string) string {
	switch severity {
	case "high":
		return "8.0"
	case "medium":
		return "5.0"
	case "critical":
		return "9.5"
	}
	return "2.0"
}
