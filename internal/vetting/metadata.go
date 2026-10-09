package vetting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Metadata struct {
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Maintainers []string  `json:"maintainers"`
	Published   time.Time `json:"published"`
	Scripts     []string  `json:"scripts,omitempty"`
	Registry    string    `json:"registry,omitempty"`
	Local       string    `json:"-"`
	Entry       string    `json:"-"`
	Image       string    `json:"-"`
	MCPName     string    `json:"-"`
	Reference   string    `json:"-"`
}

type npmPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Maintainers []struct {
		Name string `json:"name"`
	} `json:"maintainers"`
	Scripts map[string]string `json:"scripts"`
	Bin     json.RawMessage   `json:"bin"`
	MCPName string            `json:"mcpName"`
}

func npmMetadata(p npmPackage) (Metadata, error) {
	m := Metadata{Kind: "npm", Name: p.Name, Version: p.Version, MCPName: p.MCPName}
	if !npmName.MatchString(m.Name) || !versionName.MatchString(m.Version) {
		return m, errors.New("invalid npm package name or version")
	}
	for _, who := range p.Maintainers {
		if who.Name != "" {
			m.Maintainers = append(m.Maintainers, who.Name)
		}
	}
	for _, script := range []string{"preinstall", "install", "postinstall", "prepare", "prepublish"} {
		if _, ok := p.Scripts[script]; ok {
			m.Scripts = append(m.Scripts, script)
		}
	}
	if json.Unmarshal(p.Bin, &m.Entry) != nil {
		var bins map[string]string
		if json.Unmarshal(p.Bin, &bins) == nil && len(bins) == 1 {
			for _, entry := range bins {
				m.Entry = entry
			}
		}
	}
	sort.Strings(m.Maintainers)
	return m, nil
}

var npmName = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
var pythonName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var versionName = regexp.MustCompile(`^[0-9][A-Za-z0-9.+_-]*$`)

func fetch(ctx context.Context, client *http.Client, endpoint string, value any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("metadata request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata endpoint returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 16<<20 {
		return errors.New("metadata exceeds 16 MiB")
	}
	if json.Unmarshal(b, value) != nil {
		return errors.New("invalid package metadata")
	}
	return nil
}

func metadata(ctx context.Context, input string, client *http.Client) (Metadata, error) {
	if info, err := os.Stat(input); err == nil && info.IsDir() {
		dir, err := filepath.Abs(input)
		if err != nil {
			return Metadata{}, err
		}
		data, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			return Metadata{}, err
		}
		var p npmPackage
		if json.Unmarshal(data, &p) != nil {
			return Metadata{}, errors.New("invalid local package.json")
		}
		m, err := npmMetadata(p)
		m.Local = dir
		return m, err
	}
	if strings.HasPrefix(input, "mcp:") {
		return registryMetadata(ctx, client, strings.TrimPrefix(input, "mcp:"))
	}
	if strings.HasPrefix(input, "https://registry.modelcontextprotocol.io/") {
		u, err := url.Parse(input)
		if err != nil || u.RawQuery != "" || u.Fragment != "" {
			return Metadata{}, errors.New("invalid registry entry URL")
		}
		var entry registryEntry
		if err := fetch(ctx, client, input, &entry); err != nil {
			return Metadata{}, err
		}
		return fromRegistry(ctx, client, entry, input)
	}
	if strings.HasPrefix(input, "oci:") {
		return imageMetadata(ctx, strings.TrimPrefix(input, "oci:"))
	}
	if strings.HasPrefix(input, "pypi:") {
		name, version, _ := strings.Cut(strings.TrimPrefix(input, "pypi:"), "==")
		if !pythonName.MatchString(name) || (version != "" && !versionName.MatchString(version)) {
			return Metadata{}, errors.New("invalid PyPI reference")
		}
		endpoint := "https://pypi.org/pypi/" + url.PathEscape(name) + "/"
		if version != "" {
			endpoint += url.PathEscape(version) + "/"
		}
		endpoint += "json"
		var p struct {
			Info struct {
				Name, Version, Maintainer, MaintainerEmail, Description string
				Author                                                  string
			} `json:"info"`
			URLs []struct {
				Uploaded time.Time `json:"upload_time_iso_8601"`
			} `json:"urls"`
		}
		if err := fetch(ctx, client, endpoint, &p); err != nil {
			return Metadata{}, err
		}
		m := Metadata{Kind: "pypi", Name: p.Info.Name, Version: p.Info.Version}
		if !pythonName.MatchString(m.Name) || !versionName.MatchString(m.Version) {
			return m, errors.New("invalid PyPI metadata")
		}
		if p.Info.Maintainer != "" {
			m.Maintainers = []string{p.Info.Maintainer}
		} else if p.Info.Author != "" {
			m.Maintainers = []string{p.Info.Author}
		}
		for _, file := range p.URLs {
			if m.Published.IsZero() || file.Uploaded.Before(m.Published) {
				m.Published = file.Uploaded
			}
		}
		hint := regexp.MustCompile(`mcp-name:\s*([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)`).FindStringSubmatch(p.Info.Description)
		if len(hint) > 1 {
			m.MCPName = hint[1]
		}
		return m, nil
	}
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		u, err := url.Parse(input)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
			return Metadata{}, errors.New("invalid MCP URL")
		}
		return Metadata{Kind: "http", Name: u.Hostname(), Entry: input}, nil
	}
	ref := strings.TrimPrefix(input, "npm:")
	name, version := ref, ""
	if i := strings.LastIndex(ref, "@"); i > 0 {
		name, version = ref[:i], ref[i+1:]
	}
	if !npmName.MatchString(name) || (version != "" && !versionName.MatchString(version)) {
		return Metadata{}, errors.New("use npm:name@version, pypi:name==version, oci:image, mcp:name, a URL, or a local npm directory")
	}
	var doc struct {
		Versions    map[string]npmPackage `json:"versions"`
		Tags        map[string]string     `json:"dist-tags"`
		Time        map[string]time.Time  `json:"time"`
		Maintainers []struct {
			Name string `json:"name"`
		} `json:"maintainers"`
	}
	if err := fetch(ctx, client, "https://registry.npmjs.org/"+url.PathEscape(name), &doc); err != nil {
		return Metadata{}, err
	}
	if version == "" {
		version = doc.Tags["latest"]
	}
	p, ok := doc.Versions[version]
	if !ok {
		return Metadata{}, errors.New("npm version not found")
	}
	// Current registry owners, not the historical package.json authors, are the trust signal.
	p.Maintainers = doc.Maintainers
	m, err := npmMetadata(p)
	m.Published = doc.Time[version]
	return m, err
}

type registryEntry struct {
	Server struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Packages []struct {
			Kind    string `json:"registryType"`
			Name    string `json:"identifier"`
			Version string `json:"version"`
		} `json:"packages"`
		Remotes []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"remotes"`
	} `json:"server"`
}

func registryMetadata(ctx context.Context, client *http.Client, name string) (Metadata, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`).MatchString(name) {
		return Metadata{}, errors.New("invalid MCP registry name")
	}
	endpoint := "https://registry.modelcontextprotocol.io/v0.1/servers/" + url.PathEscape(name) + "/versions/latest"
	var entry registryEntry
	if err := fetch(ctx, client, endpoint, &entry); err != nil {
		return Metadata{}, err
	}
	return fromRegistry(ctx, client, entry, endpoint)
}

func fromRegistry(ctx context.Context, client *http.Client, e registryEntry, source string) (Metadata, error) {
	for _, p := range e.Server.Packages {
		var ref string
		switch p.Kind {
		case "npm":
			ref = "npm:" + p.Name + "@" + p.Version
		case "pypi":
			ref = "pypi:" + p.Name + "==" + p.Version
		case "oci":
			name := p.Name
			if p.Version != "" && !strings.Contains(name, "@") && strings.LastIndex(name, ":") <= strings.LastIndex(name, "/") {
				name += ":" + p.Version
			}
			ref = "oci:" + name
		}
		if ref != "" {
			m, err := metadata(ctx, ref, client)
			m.Registry = source
			return m, err
		}
	}
	for _, remote := range e.Server.Remotes {
		if remote.Type == "streamable-http" {
			u, err := url.Parse(remote.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" {
				return Metadata{}, errors.New("invalid remote registry URL")
			}
			return Metadata{Kind: "http", Name: u.Hostname(), Entry: remote.URL, Registry: source}, nil
		}
	}
	return Metadata{}, errors.New("registry entry has no supported npm, PyPI, OCI or Streamable HTTP launch")
}

func registryMatch(ctx context.Context, client *http.Client, m Metadata) (string, error) {
	search := m.MCPName
	if search == "" {
		search = m.Name[strings.LastIndex(m.Name, "/")+1:]
		search = strings.TrimPrefix(search, "server-")
		search = strings.TrimPrefix(search, "mcp-server-")
	}
	cursor := ""
	for page := 0; page < 20; page++ {
		endpoint := "https://registry.modelcontextprotocol.io/v0.1/servers?version=latest&search=" + url.QueryEscape(search) + "&cursor=" + url.QueryEscape(cursor)
		var list struct {
			Servers  []registryEntry `json:"servers"`
			Metadata struct {
				Next string `json:"nextCursor"`
			} `json:"metadata"`
		}
		if err := fetch(ctx, client, endpoint, &list); err != nil {
			return "", err
		}
		for _, entry := range list.Servers {
			for _, p := range entry.Server.Packages {
				if p.Kind == m.Kind && ((p.Name == m.Name && p.Version == m.Version) || (m.Kind == "oci" && (p.Name == m.Reference || p.Name == m.Name))) {
					return "https://registry.modelcontextprotocol.io/v0.1/servers/" + url.PathEscape(entry.Server.Name) + "/versions/" + url.PathEscape(entry.Server.Version), nil
				}
			}
			for _, r := range entry.Server.Remotes {
				if m.Kind == "http" && r.URL == m.Entry {
					return "https://registry.modelcontextprotocol.io/v0.1/servers/" + url.PathEscape(entry.Server.Name) + "/versions/" + url.PathEscape(entry.Server.Version), nil
				}
			}
		}
		if list.Metadata.Next == "" {
			return "", nil
		}
		if cursor == list.Metadata.Next {
			return "", errors.New("registry repeated a page")
		}
		cursor = list.Metadata.Next
	}
	return "", errors.New("registry lookup exceeded 20 pages")
}
