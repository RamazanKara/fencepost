package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version       int               `yaml:"version"`
	Servers       map[string]Server `yaml:"servers"`
	SessionBudget int               `yaml:"session_budget"`
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
	RateLimit int        `yaml:"rate_limit,omitempty"`
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
	Path         string `yaml:"path"`
	OTLPEndpoint string `yaml:"otlp_endpoint"`
}

func Read(filename string) (*Policy, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("cannot read policy")
	}
	base, err := filepath.Abs(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	return Parse(data, base)
}

func Parse(data []byte, base string) (*Policy, error) {
	var document yaml.Node
	if yaml.Unmarshal(data, &document) != nil || !validNodes(&document, false) {
		return nil, errors.New("invalid policy YAML; null is only allowed inside enum values")
	}
	p := &Policy{
		Output:   Output{true, 1 << 20, "warn"},
		Approval: Approval{Mode: "local", Timeout: "30s", LocalFile: "fencepost-approval.json"},
		Audit:    Audit{Path: "fencepost-audit.jsonl"},
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(p); err != nil {
		return nil, errors.New("invalid policy YAML or unknown field")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("policy must contain one YAML document")
	}
	if p.Version != 1 || len(p.Servers) == 0 || p.SessionBudget < 0 {
		return nil, errors.New("policy requires version 1, servers, and a nonnegative session_budget")
	}
	if p.Output.MaxBytes < 512 || p.Output.MaxBytes > 16<<20 || (p.Output.Injection != "warn" && p.Output.Injection != "block") {
		return nil, errors.New("output requires max_bytes between 512 and 16777216 and injection warn or block")
	}
	if p.Approval.Mode != "local" && p.Approval.Mode != "webhook" {
		return nil, errors.New("approval mode must be local or webhook")
	}
	duration, err := time.ParseDuration(p.Approval.Timeout)
	if err != nil || duration <= 0 || duration > 10*time.Minute {
		return nil, errors.New("approval timeout must be positive and at most 10m")
	}
	if p.Approval.Mode == "webhook" && (p.Approval.HMACSecretEnv == "" || !SafeEndpoint(p.Approval.WebhookURL)) {
		return nil, errors.New("webhook requires an HTTPS URL (HTTP only on loopback) and hmac_secret_env")
	}
	if p.Approval.LocalFile == "" || p.Audit.Path == "" || (p.Audit.OTLPEndpoint != "" && !SafeEndpoint(p.Audit.OTLPEndpoint)) {
		return nil, errors.New("invalid approval file, audit path, or OTLP endpoint")
	}
	p.Approval.LocalFile = absolute(base, p.Approval.LocalFile)
	p.Audit.Path = absolute(base, p.Audit.Path)
	for name, server := range p.Servers {
		if name == "" || !action(server.Default) {
			return nil, errors.New("each server requires a name and default allow, deny, or ask")
		}
		for i := range server.Tools {
			t := &server.Tools[i]
			if _, err := path.Match(t.Name, ""); err != nil || t.Name == "" || !action(t.Action) || t.RateLimit < 0 {
				return nil, errors.New("invalid tool glob, action, or rate_limit")
			}
			for j := range t.Arguments {
				a := &t.Arguments[j]
				a.parts, err = parsePath(a.Path)
				if err != nil {
					return nil, err
				}
				if a.PathPrefix == nil && a.Host == nil && a.Regex == "" && a.MaxLength == nil && a.Enum == nil {
					return nil, errors.New("argument rule requires a constraint")
				}
				if (a.PathPrefix != nil && len(a.PathPrefix) == 0) || (a.Host != nil && len(a.Host) == 0) || (a.Enum != nil && len(a.Enum) == 0) || (a.MaxLength != nil && *a.MaxLength < 0) {
					return nil, errors.New("argument allowlists must not be empty; max_length must be nonnegative")
				}
				if a.Regex != "" {
					a.pattern, err = regexp.Compile(a.Regex)
					if err != nil {
						return nil, errors.New("invalid argument regex")
					}
				}
				for k, root := range a.PathPrefix {
					if root == "" {
						return nil, errors.New("empty path_prefix")
					}
					a.PathPrefix[k] = absolute(base, root)
					if resolved, err := filepath.EvalSymlinks(a.PathPrefix[k]); err == nil {
						a.PathPrefix[k] = resolved
					}
				}
				for k, host := range a.Host {
					a.Host[k], err = canonicalHost(host)
					if err != nil {
						return nil, errors.New("invalid host allowlist entry; use an exact DNS name or canonical IP")
					}
				}
				for k, value := range a.Enum {
					// YAML numbers must have the same representation as JSON arguments.
					raw, err := json.Marshal(value)
					if err != nil {
						return nil, errors.New("enum must contain JSON values")
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

func validNodes(n *yaml.Node, enum bool) bool {
	if n.Tag == "!!null" && !enum {
		return false
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			value := n.Content[i+1]
			allowed := enum || (n.Content[i].Value == "enum" && value.Kind == yaml.SequenceNode)
			if !validNodes(value, allowed) {
				return false
			}
		}
		return true
	}
	for _, child := range n.Content {
		if !validNodes(child, enum) {
			return false
		}
	}
	return true
}

func absolute(base, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(base, name)
}

func action(s string) bool { return s == "allow" || s == "deny" || s == "ask" }

func (p *Policy) Match(server, tool string, args map[string]any) (string, string, int) {
	s, ok := p.Servers[server]
	if !ok {
		return "deny", "server", 0
	}
	for i, t := range s.Tools {
		if matched, _ := path.Match(t.Name, tool); !matched {
			continue
		}
		rule := fmt.Sprintf("tool:%d", i+1)
		for j, a := range t.Arguments {
			if !a.match(args) {
				return "deny", fmt.Sprintf("%s/argument:%d", rule, j+1), 0
			}
		}
		return t.Action, rule, t.RateLimit
	}
	return s.Default, "default", 0
}
