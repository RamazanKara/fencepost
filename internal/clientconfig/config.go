package clientconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Server struct {
	Name      string            `json:"name"`
	Transport string            `json:"transport"`
	Command   string            `json:"-"`
	Args      []string          `json:"-"`
	Env       map[string]string `json:"-"`
	URL       string            `json:"-"`
	Headers   map[string]string `json:"-"`
	Cwd       string            `json:"-"`
	EnvFile   string            `json:"-"`
	Source    string            `json:"source"`
	Line      int               `json:"line"`
}

type Paths struct {
	OS, Home, Project, AppData, XDG string
}

func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	project, err := os.Getwd()
	return Paths{runtime.GOOS, home, project, os.Getenv("APPDATA"), os.Getenv("XDG_CONFIG_HOME")}, err
}

func Candidates(p Paths) []string {
	config := p.XDG
	if config == "" {
		config = filepath.Join(p.Home, ".config")
	}
	app := config
	if p.OS == "darwin" {
		app = filepath.Join(p.Home, "Library", "Application Support")
	}
	if p.OS == "windows" {
		app = p.AppData
		if app == "" {
			app = filepath.Join(p.Home, "AppData", "Roaming")
		}
	}
	return []string{
		filepath.Join(app, "Claude", "claude_desktop_config.json"),
		filepath.Join(p.Home, ".claude.json"),
		filepath.Join(p.Home, ".claude", "settings.json"),
		filepath.Join(p.Project, ".mcp.json"),
		filepath.Join(p.Home, ".cursor", "mcp.json"),
		filepath.Join(p.Project, ".cursor", "mcp.json"),
		filepath.Join(app, "Code", "User", "mcp.json"),
		filepath.Join(app, "Code", "User", "settings.json"),
		filepath.Join(p.Project, ".vscode", "mcp.json"),
		filepath.Join(p.Project, ".vscode", "settings.json"),
		filepath.Join(p.Home, ".codeium", "windsurf", "mcp_config.json"),
	}
}

func Discover(p Paths, explicit string) ([]Server, error) {
	paths := Candidates(p)
	if explicit != "" {
		paths = []string{explicit}
	}
	var servers []Server
	seen := map[string]bool{}
	for _, path := range paths {
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && explicit == "" {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
		parsed, err := Parse(data, path, p.Project)
		if err != nil {
			return nil, err
		}
		servers = append(servers, parsed...)
	}
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Name != servers[j].Name {
			return servers[i].Name < servers[j].Name
		}
		return servers[i].Source < servers[j].Source
	})
	return servers, nil
}

func child(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func Parse(data []byte, source, project string) ([]Server, error) {
	data = jsonc(data)
	if !json.Valid(data) {
		return nil, fmt.Errorf("%s: invalid JSON/JSONC", source)
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected config object", source)
	}
	root := doc.Content[0]
	groups := []*yaml.Node{child(root, "mcpServers"), child(root, "servers"), child(child(root, "mcp"), "servers"), child(root, "mcp.servers")}
	projects := child(root, "projects")
	if projects != nil {
		for i := 0; i < len(projects.Content); i += 2 {
			if filepath.Clean(projects.Content[i].Value) == filepath.Clean(project) {
				groups = append(groups, child(projects.Content[i+1], "mcpServers"))
			}
		}
	}
	var servers []Server
	for _, group := range groups {
		if group == nil {
			continue
		}
		if group.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s:%d: expected server map", source, group.Line)
		}
		for i := 0; i < len(group.Content); i += 2 {
			key, value := group.Content[i], group.Content[i+1]
			var spec struct {
				Type      string            `yaml:"type"`
				Command   string            `yaml:"command"`
				Args      []string          `yaml:"args"`
				Env       map[string]string `yaml:"env"`
				URL       string            `yaml:"url"`
				ServerURL string            `yaml:"serverUrl"`
				Headers   map[string]string `yaml:"headers"`
				Cwd       string            `yaml:"cwd"`
				EnvFile   string            `yaml:"envFile"`
				Disabled  bool              `yaml:"disabled"`
			}
			if value.Kind != yaml.MappingNode || value.Decode(&spec) != nil {
				return nil, fmt.Errorf("%s:%d: invalid server definition", source, key.Line)
			}
			if spec.Disabled {
				continue
			}
			if spec.URL == "" {
				spec.URL = spec.ServerURL
			}
			transport := spec.Type
			if transport == "" {
				if spec.URL != "" {
					transport = "http"
				} else {
					transport = "stdio"
				}
			}
			if transport == "streamable-http" {
				transport = "http"
			}
			if (transport == "stdio" && spec.Command == "") || (transport == "http" && spec.URL == "") || (spec.Command != "" && spec.URL != "") {
				return nil, fmt.Errorf("%s:%d: expected command or URL for transport", source, key.Line)
			}
			servers = append(servers, Server{key.Value, transport, spec.Command, spec.Args, spec.Env, spec.URL, spec.Headers, spec.Cwd, spec.EnvFile, source, key.Line})
		}
	}
	return servers, nil
}

// Preserve byte offsets and newlines so source locations survive JSONC cleanup.
func jsonc(data []byte) []byte {
	out := bytes.Clone(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	quoted, escaped := false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			continue
		}
		if c != '/' || i+1 >= len(out) {
			continue
		}
		if out[i+1] == '/' {
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		} else if out[i+1] == '*' {
			out[i], out[i+1] = ' ', ' '
			i += 2
			closed := false
			for i < len(out) {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					closed = true
					break
				}
				if out[i] != '\n' && out[i] != '\r' {
					out[i] = ' '
				}
				i++
			}
			if !closed {
				return nil
			}
		}
	}
	quoted, escaped = false, false
	for i, c := range out {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		}
		if c == ',' {
			j := i + 1
			for j < len(out) && strings.ContainsRune(" \r\n\t", rune(out[j])) {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
			}
		}
	}
	return out
}

var variable = regexp.MustCompile(`\$\{([^}]+)\}`)

func IsReference(s string) bool { return variable.MatchString(s) }

func Resolve(s Server, lookup func(string) (string, bool)) (Server, error) {
	var missing bool
	expand := func(value string) string {
		return variable.ReplaceAllStringFunc(value, func(ref string) string {
			key := ref[2 : len(ref)-1]
			key = strings.TrimPrefix(strings.TrimPrefix(key, "env:"), "env.")
			name, fallback, hasDefault := strings.Cut(key, ":-")
			if strings.Contains(name, ":") {
				missing = true
				return ""
			}
			if v, ok := lookup(name); ok {
				return v
			}
			if hasDefault {
				return fallback
			}
			missing = true
			return ""
		})
	}
	s.Command, s.URL, s.Cwd = expand(s.Command), expand(s.URL), expand(s.Cwd)
	s.Args = append([]string(nil), s.Args...)
	for i := range s.Args {
		s.Args[i] = expand(s.Args[i])
	}
	for _, pair := range []struct {
		src map[string]string
		dst *map[string]string
	}{{s.Env, &s.Env}, {s.Headers, &s.Headers}} {
		*pair.dst = make(map[string]string, len(pair.src))
		for k, v := range pair.src {
			(*pair.dst)[k] = expand(v)
		}
	}
	if missing {
		return Server{}, errors.New("unresolved config variable (interactive inputs are unsupported)")
	}
	if s.EnvFile != "" {
		return Server{}, errors.New("envFile is unsupported; declare env values or environment references explicitly")
	}
	return s, nil
}

func CleanEnv(declared map[string]string) []string {
	values := map[string]string{}
	for _, key := range []string{"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "APPDATA", "LOCALAPPDATA"} {
		if v, ok := os.LookupEnv(key); ok {
			values[key] = v
		}
	}
	for key, value := range declared {
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

var TokenPattern = regexp.MustCompile(`(?i)(?:gh[pousr]_[a-z0-9_]{16,}|github_pat_[a-z0-9_]{16,}|xox[baprs]-[a-z0-9-]{10,}|sk-(?:ant-[a-z0-9_-]+|proj-[a-z0-9_-]+|[a-z0-9_-]{16,})|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[a-z0-9_-]{30,}|eyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+|-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+)?PRIVATE KEY-----)`)
var sensitiveName = regexp.MustCompile(`(?i)(token|secret|password|api[-_]?key|authorization|credential|private[-_]?key)`)

func Redact(text string, servers []Server) string {
	type replacement struct{ value, name string }
	var replacements []replacement
	add := func(value, name string) {
		if value != "" && (len(value) >= 8 || sensitiveName.MatchString(name)) {
			replacements = append(replacements, replacement{value, name})
			if scheme, credential, ok := strings.Cut(value, " "); ok && (strings.EqualFold(scheme, "Bearer") || strings.EqualFold(scheme, "Basic")) && credential != "" {
				replacements = append(replacements, replacement{credential, name})
			}
		}
	}
	for _, s := range servers {
		for _, fields := range []map[string]string{s.Env, s.Headers} {
			for k, v := range fields {
				if v != "" && !IsReference(v) {
					add(v, k)
				}
				for _, ref := range variable.FindAllStringSubmatch(v, -1) {
					key := strings.TrimPrefix(strings.TrimPrefix(ref[1], "env:"), "env.")
					key, fallback, _ := strings.Cut(key, ":-")
					add(os.Getenv(key), key)
					add(fallback, key)
				}
			}
		}
	}
	sort.Slice(replacements, func(i, j int) bool {
		if len(replacements[i].value) != len(replacements[j].value) {
			return len(replacements[i].value) > len(replacements[j].value)
		}
		return replacements[i].name < replacements[j].name
	})
	// A single replacer avoids rescanning placeholders created by earlier replacements.
	pairs := make([]string, 0, 2*len(replacements))
	for _, r := range replacements {
		pairs = append(pairs, r.value, "<redacted:"+r.name+">")
	}
	if len(pairs) > 0 {
		text = strings.NewReplacer(pairs...).Replace(text)
	}
	return TokenPattern.ReplaceAllString(text, "<redacted:SECRET>")
}
