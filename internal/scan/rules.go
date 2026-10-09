package scan

//go:generate go run ../../scripts/rules.go

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/mcp"
)

type Rule struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Explanation string `json:"explanation"`
	Fix         string `json:"fix"`
}

var Rules = []Rule{
	{"FP001", "high", "Hidden instructions", "Descriptions contain instructions directed at the model, sensitive-file access, or data transfer instructions.", "Remove behavioral instructions and describe only the tool's inputs and effects; review the server source."},
	{"FP002", "high", "Deceptive Unicode", "Invisible, bidirectional, or tag characters can conceal instructions; confusable names can impersonate tools.", "Remove invisible controls and use unambiguous ASCII tool names."},
	{"FP003", "medium", "Tool-name shadowing", "Tools on different servers have matching or similar names, or a description refers to another server's tool.", "Rename overlapping tools, remove cross-server instructions, and review which server is trusted."},
	{"FP004", "medium", "Unpinned package launch", "A package launcher can resolve a different package version on the next run.", "Pin an exact package version or immutable container digest and review upgrades."},
	{"FP005", "high", "Plaintext secret", "A config environment variable or header appears to contain a credential.", "Replace the literal with an environment reference and rotate any exposed credential."},
	{"FP006", "medium", "Unconstrained risky capability", "A tool advertises shell execution, file writes, or HTTP fetching without a relevant schema constraint.", "Restrict command, path, or host inputs with an allowlist and enforce the restriction on the server."},
	{"FP007", "low", "Suspicious description payload", "Descriptions exceed 8192 bytes or contain URLs or base64 payloads of at least 256 characters.", "Keep descriptions concise; review linked or encoded content and remove unnecessary payloads."},
	{"FP008", "high", "Remote HTTP without TLS", "The server uses unencrypted HTTP on a non-loopback host.", "Use HTTPS with a valid certificate or a loopback-only endpoint."},
}

func Rank(severity string) int {
	switch severity {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 0
}

type Finding struct {
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Server      string `json:"server"`
	Tool        string `json:"tool,omitempty"`
	Source      string `json:"source"`
	Line        int    `json:"line"`
	Explanation string `json:"explanation"`
	Fix         string `json:"fix"`
}

type Inventory struct {
	Server  clientconfig.Server
	Catalog mcp.Catalog
}
type ConnectionError struct {
	Server  string `json:"server"`
	Source  string `json:"source"`
	Message string `json:"message"`
}
type Result struct {
	Servers  int               `json:"servers"`
	Findings []Finding         `json:"findings"`
	Errors   []ConnectionError `json:"errors"`
}

func Collect(ctx context.Context, servers []clientconfig.Server, timeout time.Duration) ([]Inventory, []ConnectionError) {
	var inventories []Inventory
	errors := []ConnectionError{}
	for _, s := range servers {
		serverCtx, cancel := context.WithTimeout(ctx, timeout)
		client, err := mcp.Connect(serverCtx, s)
		if err == nil {
			catalog, listErr := client.Catalog(serverCtx)
			closeErr := client.Close()
			err = listErr
			if err == nil {
				err = closeErr
			}
			if err == nil {
				inventories = append(inventories, Inventory{s, catalog})
			}
		}
		cancel()
		if err != nil {
			errors = append(errors, ConnectionError{s.Name, s.Source, clientconfig.Redact(err.Error(), servers)})
		}
	}
	return inventories, errors
}

func Audit(servers []clientconfig.Server, inventories []Inventory) Result {
	result := Result{Servers: len(servers), Findings: []Finding{}, Errors: []ConnectionError{}}
	add := func(id string, s clientconfig.Server, tool, detail string) {
		for _, rule := range Rules {
			if rule.ID == id {
				result.Findings = append(result.Findings, Finding{id, rule.Severity, rule.Title, s.Name, tool, s.Source, s.Line, rule.Explanation + " " + detail, rule.Fix})
			}
		}
	}
	for _, s := range servers {
		if unpinned(s.Command, s.Args) {
			add("FP004", s, "", "The launch spec has no immutable package reference.")
		}
		for _, fields := range []map[string]string{s.Env, s.Headers} {
			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if secret(key, fields[key]) {
					add("FP005", s, "", "Configured value: <redacted:"+key+">.")
				}
			}
		}
		if u, err := url.Parse(s.URL); err == nil && strings.EqualFold(u.Scheme, "http") {
			host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
			ip := net.ParseIP(host)
			if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				add("FP008", s, "", "Transport endpoint is not loopback.")
			}
		}
	}
	for _, inv := range inventories {
		checkText := func(tool string, descriptions []string, name string) {
			flags := map[string]bool{}
			if name != "" && confusableName(name) {
				flags["FP002"] = true
			}
			for _, desc := range descriptions {
				if HiddenInstructions(desc) {
					flags["FP001"] = true
				}
				if invisible(desc) {
					flags["FP002"] = true
				}
				if len(desc) > 8192 || link.MatchString(desc) || encodedBlob(desc) {
					flags["FP007"] = true
				}
			}
			for _, id := range []string{"FP001", "FP002", "FP007"} {
				if flags[id] {
					add(id, inv.Server, tool, "Review the advertised definition.")
				}
			}
		}
		checkText("(server instructions)", []string{inv.Catalog.Instructions}, "")
		for _, t := range inv.Catalog.Tools {
			descs := descriptions(t)
			checkText(t.Text("name"), descs, t.Text("name"))
			if risky(t) {
				add("FP006", inv.Server, t.Text("name"), "No restrictive enum, const, or anchored pattern was found for the relevant input.")
			}
		}
		for _, items := range [][]json.RawMessage{inv.Catalog.Prompts, inv.Catalog.Resources} {
			for _, raw := range items {
				var item mcp.Tool
				if json.Unmarshal(raw, &item) == nil {
					checkText(item.Text("name"), descriptions(item), "")
				}
			}
		}
	}
	for i, a := range inventories {
		for j := i + 1; j < len(inventories); j++ {
			b := inventories[j]
			for _, x := range a.Catalog.Tools {
				for _, y := range b.Catalog.Tools {
					nx, ny := x.Text("name"), y.Text("name")
					if similar(nx, ny) {
						add("FP003", a.Server, nx, "Name overlaps a tool on server "+b.Server.Name+".")
						add("FP003", b.Server, ny, "Name overlaps a tool on server "+a.Server.Name+".")
					} else {
						if references(x.Text("description"), b.Server.Name, ny) {
							add("FP003", a.Server, nx, "Description references a tool on server "+b.Server.Name+".")
						}
						if references(y.Text("description"), a.Server.Name, nx) {
							add("FP003", b.Server, ny, "Description references a tool on server "+a.Server.Name+".")
						}
					}
				}
			}
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		return a.Explanation < b.Explanation
	})
	return result
}

var link = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>]+`)
var blob = regexp.MustCompile(`[A-Za-z0-9+/]{256,}={0,2}`)

func encodedBlob(s string) bool {
	for _, match := range blob.FindAllString(s, -1) {
		if _, err := base64.StdEncoding.DecodeString(match); err == nil {
			return true
		}
	}
	return false
}

func invisible(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) || (r >= 0xe0000 && r <= 0xe007f) || r == 0x034f || r == 0x2800 {
			return true
		}
	}
	return false
}

func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if invisible(string(r)) {
			return -1
		}
		return r
	}, s)
}

var confusables = strings.NewReplacer("а", "a", "е", "e", "о", "o", "р", "p", "с", "c", "х", "x", "у", "y", "і", "i", "ј", "j", "ѕ", "s", "ӏ", "l", "Α", "a", "Β", "b", "Ε", "e", "Ι", "i", "Κ", "k", "Μ", "m", "Ν", "n", "Ο", "o", "Ρ", "p", "Τ", "t", "Χ", "x", "ο", "o", "ρ", "p", "ν", "v", "Α", "a")

func skeleton(s string) string {
	s = confusables.Replace(strings.ToLower(stripInvisible(s)))
	s = strings.Map(func(r rune) rune {
		if r >= 0xff01 && r <= 0xff5e {
			r -= 0xfee0
		}
		if r == '_' || r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
	return strings.NewReplacer("0", "o", "1", "l", "rn", "m").Replace(s)
}

func confusableName(s string) bool {
	if invisible(s) {
		return true
	}
	for _, r := range s {
		if r > 127 && (confusables.Replace(string(r)) != string(r) || confusables.Replace(strings.ToLower(string(r))) != strings.ToLower(string(r)) || (r >= 0xff01 && r <= 0xff5e)) {
			return true
		}
	}
	return false
}

func similar(a, b string) bool {
	a, b = skeleton(a), skeleton(b)
	if a == b {
		return true
	}
	if len(a) < 5 || len(b) < 5 {
		return false
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	if len(b)-len(a) > 1 {
		return false
	}
	i, j, edits := 0, 0, 0
	for i < len(a) && j < len(b) {
		if a[i] != b[j] {
			edits++
			if edits > 1 {
				return false
			}
			if len(a) == len(b) {
				if i+1 < len(a) && a[i] == b[j+1] && a[i+1] == b[j] {
					i += 2
					j += 2
					continue
				}
				i++
			}
			j++
		} else {
			i++
			j++
		}
	}
	return edits+len(b)-j <= 1
}

func references(desc, server, tool string) bool {
	desc = strings.ToLower(desc)
	tool = strings.ToLower(tool)
	if strings.Contains(desc, strings.ToLower(server)+"/"+tool) || strings.Contains(desc, strings.ToLower(server)+"."+tool) {
		return true
	}
	if strings.ContainsAny(tool, "_-") || strings.Contains(desc, "tool") {
		return regexp.MustCompile(`\b` + regexp.QuoteMeta(tool) + `\b`).MatchString(desc)
	}
	return false
}

func descriptions(t mcp.Tool) []string {
	var value any
	data, _ := json.Marshal(t)
	_ = json.Unmarshal(data, &value)
	var result []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, child := range x {
				if key == "description" {
					if text, ok := child.(string); ok {
						result = append(result, text)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(value)
	return result
}

var exactVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
var containerVersion = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+)*(?:[-_][0-9A-Za-z._-]+)?$`)
var pythonVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+(?:[a-z]+[0-9]+)?$`)
var digest = regexp.MustCompile(`@sha256:[a-fA-F0-9]{64}$`)

func unpinned(command string, args []string) bool {
	base := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(filepath.Base(command)), ".exe"), ".cmd")
	if base == "cmd" || base == "sh" || base == "bash" || base == "powershell" || base == "pwsh" {
		for i, a := range args {
			if strings.EqualFold(a, "/c") || a == "-c" || strings.EqualFold(a, "-Command") {
				if i+1 < len(args) {
					words := strings.Fields(strings.Join(args[i+1:], " "))
					if len(words) > 0 {
						return unpinned(words[0], words[1:])
					}
				}
			}
		}
		return false
	}
	if base == "docker" {
		if len(args) == 0 || args[0] != "run" {
			return false
		}
		for i := 1; i < len(args); i++ {
			a := args[i]
			if strings.HasPrefix(a, "-") {
				if dockerValueFlags[a] {
					i++
				}
				continue
			}
			if digest.MatchString(a) {
				return false
			}
			last := a[strings.LastIndex(a, "/")+1:]
			_, tag, ok := strings.Cut(last, ":")
			return !ok || !containerVersion.MatchString(tag)
		}
		return true
	}
	if base != "npx" && base != "uvx" {
		return false
	}
	packageOption := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-p" || a == "--package" || a == "--from" {
			if i+1 >= len(args) {
				return true
			}
			i++
			if !pinnedPackage(args[i], base) {
				return true
			}
			packageOption = true
			continue
		}
		if strings.HasPrefix(a, "--package=") || strings.HasPrefix(a, "--from=") {
			_, p, _ := strings.Cut(a, "=")
			if !pinnedPackage(p, base) {
				return true
			}
			packageOption = true
			continue
		}
		if a == "--python" || a == "--index-url" || a == "--index" || a == "--registry" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return !packageOption && !pinnedPackage(a, base)
	}
	return false
}

var dockerValueFlags = map[string]bool{"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true, "--name": true, "--network": true, "-p": true, "--publish": true, "--entrypoint": true, "--user": true, "-u": true, "--workdir": true, "-w": true, "--platform": true, "--pull": true, "--label": true, "-l": true, "--hostname": true, "--add-host": true}

func pinnedPackage(pkg, launcher string) bool {
	if launcher == "uvx" {
		_, v, ok := strings.Cut(pkg, "==")
		return ok && pythonVersion.MatchString(v)
	}
	i := strings.LastIndex(pkg, "@")
	return i > 0 && exactVersion.MatchString(pkg[i+1:])
}

var secretKey = regexp.MustCompile(`(?i)(token|secret|password|api[-_]?key|authorization|credential|private[-_]?key|cookie)`)
var envReference = regexp.MustCompile(`\$\{[^}]+\}`)

func secret(key, value string) bool {
	if clientconfig.IsReference(value) {
		value = envReference.ReplaceAllStringFunc(value, func(ref string) string {
			_, fallback, _ := strings.Cut(ref[2:len(ref)-1], ":-")
			return fallback
		})
	}
	if value == "" || strings.HasPrefix(value, "<") || strings.EqualFold(value, "YOUR_API_KEY") {
		return false
	}
	if clientconfig.TokenPattern.MatchString(value) || strings.Contains(value, "-----BEGIN ") || strings.Contains(value, `"type": "service_account"`) {
		return true
	}
	if secretKey.MatchString(key) && len(strings.TrimSpace(value)) >= 8 && !strings.EqualFold(strings.TrimSpace(value), "Bearer") {
		return true
	}
	if len(value) < 24 || strings.ContainsAny(value, " \t\r\n/\\:") {
		return false
	}
	counts := map[rune]int{}
	length := 0.0
	for _, r := range value {
		counts[r]++
		length++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy >= 3.8
}

func risky(t mcp.Tool) bool {
	text := strings.ToLower(t.Text("name") + " " + t.Text("description"))
	var schema map[string]any
	_ = json.Unmarshal(t["inputSchema"], &schema)
	groups := []struct {
		hint *regexp.Regexp
		keys []string
	}{
		{regexp.MustCompile(`\b(shell|exec|execute|run)[ _-]*(command|shell|script|code)\b|\b(shell execution|execute arbitrary)\b`), []string{"command", "cmd", "script", "code"}},
		{regexp.MustCompile(`\b(write|create|save|overwrite)[ _-]*(file|files)\b|arbitrary file write`), []string{"path", "filepath", "file_path", "filename", "destination"}},
		{regexp.MustCompile(`\b(fetch|http[ _-]*(request|get)|download)[ _-]*(url|uri|http|page|web)?\b`), []string{"url", "uri", "host", "hostname"}},
	}
	for _, g := range groups {
		if g.hint.MatchString(text) && !constrained(schema, g.keys) {
			return true
		}
	}
	return false
}

func constrained(schema map[string]any, keys []string) bool {
	properties, _ := schema["properties"].(map[string]any)
	found := false
	for _, key := range keys {
		p, ok := properties[key].(map[string]any)
		if !ok {
			continue
		}
		found = true
		if v, ok := p["enum"].([]any); ok && len(v) > 0 {
			continue
		}
		if _, ok := p["const"]; ok {
			continue
		}
		pattern, _ := p["pattern"].(string)
		if len(pattern) > 5 && strings.HasPrefix(pattern, "^") && strings.HasSuffix(pattern, "$") && pattern != "^.*$" && pattern != "^.+$" {
			continue
		}
		return false
	}
	return found
}

func RuleTable() string {
	var b strings.Builder
	b.WriteString("| ID | Severity | Rule |\n| --- | --- | --- |\n")
	for _, r := range Rules {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.ID, r.Severity, r.Title)
	}
	return b.String()
}

func RuleDocs() string {
	var b strings.Builder
	b.WriteString("# Scanner rules\n\nGenerated from `internal/scan.Rules` by `go generate ./internal/scan`.\n\n")
	b.WriteString(RuleTable())
	for _, r := range Rules {
		fmt.Fprintf(&b, "\n## %s: %s\n\nSeverity: %s.\n\n%s\n\nFix: %s\n", r.ID, r.Title, r.Severity, r.Explanation, r.Fix)
	}
	b.WriteString("\nThese rules are heuristics, not a proof of safety. Constraints in a schema are hints; the scanner does not execute tools or prove that servers enforce them. Unicode confusable detection covers common Latin, Cyrillic, Greek, and fullwidth lookalikes, not the complete Unicode confusables database. Review findings in context.\n")
	return b.String()
}
