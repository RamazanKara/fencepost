package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version       int               `yaml:"version"`
	Servers       map[string]Server `yaml:"servers"`
	SessionBudget CallLimit         `yaml:"session_budget"`
	Output        Output            `yaml:"output"`
	Approval      Approval          `yaml:"approval"`
	Audit         Audit             `yaml:"audit"`
}

type Server struct {
	Default string `yaml:"default"`
	Tools   []Tool `yaml:"tools"`
}

type Tool struct {
	Name      string     `yaml:"name"`
	Action    string     `yaml:"action"`
	Arguments []Argument `yaml:"arguments,omitempty"`
	RateLimit CallLimit  `yaml:"rate_limit,omitempty"`
	Budget    CallLimit  `yaml:"budget,omitempty"`
	Users     []string   `yaml:"users,omitempty"`
	Groups    []string   `yaml:"groups,omitempty"`
	Clients   []string   `yaml:"clients,omitempty"`
}

// YAML otherwise truncates fractional numbers when decoding into an int.
type CallLimit int

func (b *CallLimit) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag != "!!int" {
		return fmt.Errorf("line %d: call limit must be an integer", n.Line)
	}
	return n.Decode((*int)(b))
}

type Identity struct {
	User   string   `json:"user" yaml:"user"`
	Groups []string `json:"groups,omitempty" yaml:"groups"`
	Client string   `json:"client,omitempty" yaml:"client"`
}

type Argument struct {
	Path       string   `yaml:"path"`
	PathPrefix []string `yaml:"path_prefix,omitempty"`
	Host       []string `yaml:"host,omitempty"`
	Regex      string   `yaml:"regex,omitempty"`
	MaxLength  *int     `yaml:"max_length,omitempty"`
	Enum       []any    `yaml:"enum,omitempty"`
	parts      []string
	pattern    *regexp.Regexp
}

type Output struct {
	RedactSecrets bool   `yaml:"redact_secrets"`
	MaxBytes      int    `yaml:"max_bytes"`
	Injection     string `yaml:"injection"`
}

type Approval struct {
	Mode          string `yaml:"mode"`
	Timeout       string `yaml:"timeout"`
	LocalFile     string `yaml:"local_file"`
	WebhookURL    string `yaml:"webhook_url"`
	HMACSecretEnv string `yaml:"hmac_secret_env"`
}

type Audit struct {
	Path             string `yaml:"path"`
	OTLPEndpoint     string `yaml:"otlp_endpoint"`
	RecordArguments  bool   `yaml:"record_arguments"`
	Stdout           bool   `yaml:"stdout"`
	ExportFile       string `yaml:"export_file"`
	MaxBytes         int64  `yaml:"max_bytes"`
	Backups          int    `yaml:"backups"`
	OTLPLogsEndpoint string `yaml:"otlp_logs_endpoint"`
	Syslog           string `yaml:"syslog"`
}

func Read(filename string) (*Policy, error) {
	if info, err := os.Stat(filename); err == nil && info.IsDir() {
		return readDirectory(filename)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read policy: %w", filename, err)
	}
	base, err := filepath.Abs(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	p, err := Parse(data, base)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	return p, nil
}

func Parse(data []byte, base string) (*Policy, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, yamlError(err, "invalid policy YAML")
	}
	if n := invalidNode(&document, false); n != nil {
		return nil, fmt.Errorf("line %d: null is only allowed inside enum values", n.Line)
	}
	at := func(message string, fields ...string) error { return policyError(&document, message, fields...) }
	p := &Policy{
		Output:   Output{true, 1 << 20, "warn"},
		Approval: Approval{Mode: "local", Timeout: "30s", LocalFile: "fencepost-approval.json"},
		Audit:    Audit{Path: "fencepost-audit.jsonl"},
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(p); err != nil {
		return nil, yamlError(err, "invalid policy type, duplicate key, or unknown field")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, at("policy must contain one YAML document")
	}
	if p.Version != 1 {
		return nil, at("version must be 1", "version")
	}
	if len(p.Servers) == 0 {
		return nil, at("servers must be nonempty", "servers")
	}
	if p.SessionBudget < 0 {
		return nil, at("session_budget must be nonnegative", "session_budget")
	}
	if p.Output.MaxBytes < 512 || p.Output.MaxBytes > 16<<20 {
		return nil, at("max_bytes must be between 512 and 16777216", "output", "max_bytes")
	}
	if p.Output.Injection != "warn" && p.Output.Injection != "block" {
		return nil, at("injection must be warn or block", "output", "injection")
	}
	if p.Approval.Mode != "local" && p.Approval.Mode != "webhook" {
		return nil, at("approval mode must be local or webhook", "approval", "mode")
	}
	duration, err := time.ParseDuration(p.Approval.Timeout)
	if err != nil || duration <= 0 || duration > 10*time.Minute {
		return nil, at("approval timeout must be positive and at most 10m", "approval", "timeout")
	}
	if p.Approval.Mode == "webhook" && (p.Approval.HMACSecretEnv == "" || !SafeEndpoint(p.Approval.WebhookURL)) {
		return nil, at("webhook requires an HTTPS URL (HTTP only on loopback) and hmac_secret_env", "approval", "webhook_url")
	}
	if p.Approval.LocalFile == "" {
		return nil, at("local_file must not be empty", "approval", "local_file")
	}
	if p.Audit.Path == "" {
		return nil, at("audit path must not be empty", "audit", "path")
	}
	if p.Audit.OTLPEndpoint != "" && !SafeEndpoint(p.Audit.OTLPEndpoint) {
		return nil, at("OTLP endpoint requires HTTPS or literal loopback HTTP", "audit", "otlp_endpoint")
	}
	if p.Audit.OTLPLogsEndpoint != "" && !SafeEndpoint(p.Audit.OTLPLogsEndpoint) {
		return nil, at("OTLP logs endpoint requires HTTPS or literal loopback HTTP", "audit", "otlp_logs_endpoint")
	}
	if p.Audit.MaxBytes < 0 || p.Audit.Backups < 0 || p.Audit.Backups > 100 {
		return nil, at("audit max_bytes must be nonnegative; backups must be 0..100", "audit")
	}
	if p.Audit.ExportFile != "" {
		p.Audit.ExportFile = absolute(base, p.Audit.ExportFile)
		if p.Audit.MaxBytes == 0 {
			p.Audit.MaxBytes = 10 << 20
		}
		if p.Audit.Backups == 0 {
			p.Audit.Backups = 5
		}
	}
	p.Approval.LocalFile = absolute(base, p.Approval.LocalFile)
	p.Audit.Path = absolute(base, p.Audit.Path)
	if p.Audit.ExportFile != "" && p.Audit.ExportFile == p.Audit.Path {
		return nil, at("audit export_file must differ from the authoritative log", "audit", "export_file")
	}
	for name, server := range p.Servers {
		if name == "" || !action(server.Default) {
			return nil, at("each server requires a name and default allow, deny, or ask", "servers", name, "default")
		}
		for i := range server.Tools {
			t := &server.Tools[i]
			for _, values := range [][]string{t.Users, t.Groups, t.Clients} {
				if values != nil && len(values) == 0 {
					return nil, at("identity lists must be nonempty", "servers", name, "tools", strconv.Itoa(i))
				}
				for _, value := range values {
					if value == "" {
						return nil, at("identity values must be nonempty", "servers", name, "tools", strconv.Itoa(i))
					}
				}
			}
			if _, err := path.Match(t.Name, ""); err != nil || t.Name == "" {
				return nil, at("invalid tool name glob", "servers", name, "tools", strconv.Itoa(i), "name")
			}
			if !action(t.Action) {
				return nil, at("action must be allow, deny, or ask", "servers", name, "tools", strconv.Itoa(i), "action")
			}
			if t.RateLimit < 0 {
				return nil, at("rate_limit must be nonnegative", "servers", name, "tools", strconv.Itoa(i), "rate_limit")
			}
			if t.Budget < 0 {
				return nil, at("budget must be a nonnegative integer", "servers", name, "tools", strconv.Itoa(i), "budget")
			}
			for j := range t.Arguments {
				a := &t.Arguments[j]
				a.parts, err = parsePath(a.Path)
				if err != nil {
					return nil, at(err.Error(), "servers", name, "tools", strconv.Itoa(i), "arguments", strconv.Itoa(j), "path")
				}
				if a.PathPrefix == nil && a.Host == nil && a.Regex == "" && a.MaxLength == nil && a.Enum == nil {
					return nil, at("argument rule requires a constraint", "servers", name, "tools", strconv.Itoa(i), "arguments", strconv.Itoa(j))
				}
				if (a.PathPrefix != nil && len(a.PathPrefix) == 0) || (a.Host != nil && len(a.Host) == 0) || (a.Enum != nil && len(a.Enum) == 0) || (a.MaxLength != nil && *a.MaxLength < 0) {
					return nil, at("argument allowlists must not be empty; max_length must be nonnegative", "servers", name, "tools", strconv.Itoa(i), "arguments", strconv.Itoa(j))
				}
				if a.Regex != "" {
					a.pattern, err = regexp.Compile(a.Regex)
					if err != nil {
						return nil, at("invalid argument regex", "servers", name, "tools", strconv.Itoa(i), "arguments", strconv.Itoa(j), "regex")
					}
				}
				for k, root := range a.PathPrefix {
					if root == "" {
						return nil, at("empty path_prefix", "servers", name, "tools", strconv.Itoa(i), "arguments", strconv.Itoa(j), "path_prefix", strconv.Itoa(k))
					}
					a.PathPrefix[k] = absolute(base, root)
					if resolved, err := filepath.EvalSymlinks(a.PathPrefix[k]); err == nil {
						a.PathPrefix[k] = resolved
					}
				}
				for k, host := range a.Host {
					a.Host[k], err = canonicalHost(host)
					if err != nil {
						return nil, at("invalid host allowlist entry; use an exact DNS name or canonical IP", "servers", name, "tools", strconv.Itoa(i), "arguments", strconv.Itoa(j), "host", strconv.Itoa(k))
					}
				}
				for k, value := range a.Enum {
					// YAML numbers must have the same representation as JSON arguments.
					raw, err := json.Marshal(value)
					if err != nil {
						return nil, at("enum must contain JSON values", "servers", name, "tools", strconv.Itoa(i), "arguments", strconv.Itoa(j), "enum")
					}
					d := json.NewDecoder(bytes.NewReader(raw))
					d.UseNumber()
					if err := d.Decode(&a.Enum[k]); err != nil {
						return nil, err
					}
				}
			}
		}
		p.Servers[name] = server
	}
	return p, nil
}

func invalidNode(n *yaml.Node, enum bool) *yaml.Node {
	type aliasContext struct {
		node *yaml.Node
		enum bool
	}
	seen := map[aliasContext]bool{}
	var visit func(*yaml.Node, bool) *yaml.Node
	visit = func(n *yaml.Node, enum bool) *yaml.Node {
		if n.Kind == yaml.AliasNode {
			// The same anchor can be used both inside and outside enum values.
			key := aliasContext{n.Alias, enum}
			if seen[key] {
				return nil
			}
			seen[key] = true
			return visit(n.Alias, enum)
		}
		if n.Tag == "!!null" && !enum {
			return n
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				value := n.Content[i+1]
				resolved := value
				if resolved.Kind == yaml.AliasNode {
					resolved = resolved.Alias
				}
				allowed := enum || (n.Content[i].Value == "enum" && resolved.Kind == yaml.SequenceNode)
				if bad := visit(value, allowed); bad != nil {
					return bad
				}
			}
			return nil
		}
		for _, child := range n.Content {
			if bad := visit(child, enum); bad != nil {
				return bad
			}
		}
		return nil
	}
	return visit(n, enum)
}

var yamlLine = regexp.MustCompile(`line ([0-9]+)`)

func yamlError(err error, message string) error {
	line := "1"
	if match := yamlLine.FindStringSubmatch(err.Error()); match != nil {
		line = match[1]
	}
	return fmt.Errorf("line %s: %s", line, message)
}

func policyError(n *yaml.Node, message string, fields ...string) error {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	for _, field := range fields {
		next := n
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				if n.Content[i].Value == field {
					next = n.Content[i+1]
					break
				}
			}
		} else if n.Kind == yaml.SequenceNode {
			if i, err := strconv.Atoi(field); err == nil && i >= 0 && i < len(n.Content) {
				next = n.Content[i]
			}
		}
		n = next
	}
	return fmt.Errorf("line %d: %s", max(1, n.Line), message)
}

func absolute(base, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(base, name)
}

func action(s string) bool { return s == "allow" || s == "deny" || s == "ask" }

func (p *Policy) Match(server, tool string, args map[string]any) (string, string, int) {
	action, rule, rate, _ := p.MatchIdentity(server, tool, args, Identity{})
	return action, rule, rate
}

func (p *Policy) MatchIdentity(server, tool string, args map[string]any, identity Identity) (string, string, int, int) {
	s, ok := p.Servers[server]
	if !ok {
		return "deny", "server", 0, 0
	}
	for i, t := range s.Tools {
		if !identityMatches(t.Users, []string{identity.User}) || !identityMatches(t.Groups, identity.Groups) || !identityMatches(t.Clients, []string{identity.Client}) {
			continue
		}
		if matched, _ := path.Match(t.Name, tool); !matched {
			continue
		}
		rule := fmt.Sprintf("tool:%d", i+1)
		for j, a := range t.Arguments {
			if !a.match(args) {
				return "deny", fmt.Sprintf("%s/argument:%d", rule, j+1), 0, 0
			}
		}
		return t.Action, rule, int(t.RateLimit), int(t.Budget)
	}
	return s.Default, "default", 0, 0
}

func identityMatches(required, actual []string) bool {
	if required == nil {
		return true
	}
	for _, want := range required {
		for _, value := range actual {
			if want == value {
				return true
			}
		}
	}
	return false
}
