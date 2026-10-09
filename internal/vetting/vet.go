package vetting

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/pin"
	"github.com/RamazanKara/fencepost/internal/scan"
)

type Report struct {
	Package  Metadata       `json:"package"`
	Verdict  string         `json:"verdict"`
	Reasons  []string       `json:"reasons"`
	Sandbox  string         `json:"sandbox"`
	Tools    []string       `json:"tools"`
	Findings []scan.Finding `json:"findings"`
	Complete bool           `json:"complete"`
}

func client() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func Vet(ctx context.Context, input string, network bool, lockPath string) (Report, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r := Report{Verdict: "looks fine", Reasons: []string{}, Tools: []string{}, Findings: []scan.Finding{}}
	m, err := metadata(ctx, input, client())
	if err != nil {
		return r, err
	}
	r.Package = m
	flag := func(verdict, reason string) {
		if r.Verdict != "avoid" {
			r.Verdict = verdict
		}
		r.Reasons = append(r.Reasons, reason)
	}
	for _, reason := range concerns(m, time.Now()) {
		flag(reason.verdict, reason.text)
	}
	if m.Local == "" && m.Registry == "" {
		r.Package.Registry, err = registryMatch(ctx, client(), m)
		if err != nil {
			flag("review", "Official MCP registry lookup was incomplete.")
		}
	}
	if m.Kind == "http" {
		flag("review", "Remote server code and package ownership cannot be inspected locally.")
	}
	if m.Kind == "pypi" || m.Kind == "oci" {
		flag("review", "Maintainer metadata is publisher-supplied; registry account ownership and changes are not attested.")
	}
	if len(m.Maintainers) == 0 {
		flag("review", "Maintainer metadata is unavailable.")
	}
	if m.Local == "" && m.Published.IsZero() {
		flag("review", "Publication date is unavailable.")
	}
	lock, err := pin.Read(lockPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return r, err
	}
	previous, found := lock.Packages[m.Kind+":"+m.Name]
	if found {
		a, b := slices.Clone(previous.Maintainers), slices.Clone(m.Maintainers)
		slices.Sort(a)
		slices.Sort(b)
		if !slices.Equal(a, b) {
			flag("review", "Maintainers changed since pinned version "+previous.Version+".")
		}
	} else {
		r.Reasons = append(r.Reasons, "No pinned maintainer baseline; ownership changes could not be compared.")
	}
	dir, err := os.MkdirTemp("", "fencepost-vet-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(dir)
	s, cleanup, mode, err := prepare(ctx, m, dir, network)
	defer cleanup()
	r.Sandbox = mode
	if strings.Contains(mode, "best effort") || strings.Contains(mode, "host filesystem still accessible") {
		flag("review", "OS filesystem isolation is incomplete.")
	}
	if err != nil {
		flag("review", err.Error())
		return r, nil
	}
	inventories, connectionErrors := scan.Collect(ctx, []clientconfig.Server{s}, 20*time.Second)
	result := scan.Audit([]clientconfig.Server{s}, inventories)
	r.Findings = result.Findings
	for _, f := range result.Findings {
		verdict := "review"
		if scan.Rank(f.Severity) >= scan.Rank("high") {
			verdict = "avoid"
		}
		flag(verdict, f.RuleID+": "+f.Title)
	}
	if len(connectionErrors) > 0 {
		flag("review", "Server tool enumeration failed; this is not a clean scan.")
		return r, nil
	}
	for _, inv := range inventories {
		for _, tool := range inv.Catalog.Tools {
			r.Tools = append(r.Tools, tool.Text("name"))
		}
	}
	r.Complete = true
	if r.Verdict == "looks fine" {
		r.Reasons = append(r.Reasons, "All advertised definitions passed the scan rules; no package risk signals found.")
	}
	return r, nil
}

type concern struct{ verdict, text string }

func concerns(m Metadata, now time.Time) []concern {
	var result []concern
	if len(m.Scripts) > 0 {
		result = append(result, concern{"review", "Install hooks present (not executed): " + strings.Join(m.Scripts, ", ") + "."})
	}
	if !m.Published.IsZero() && now.Sub(m.Published) < 7*24*time.Hour {
		result = append(result, concern{"review", "Package version is less than seven days old."})
	}
	popular := []string{"@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-github", "@playwright/mcp", "mcp-server-git", "mcp-server-fetch", "mcp-server-sqlite"}
	for _, name := range popular {
		if m.Name != name && near(m.Name, name) {
			result = append(result, concern{"avoid", "Name resembles popular server " + name + "; possible typosquat."})
			break
		}
	}
	return result
}

func near(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if strings.TrimPrefix(a, "@modelcontextprotocol/") == strings.TrimPrefix(b, "@modelcontextprotocol/") {
		return true
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	if len(b)-len(a) > 1 {
		return false
	}
	i, j, edits := 0, 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
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
	}
	return edits+len(b)-j <= 1
}

func PinMetadata(ctx context.Context, servers []clientconfig.Server) (map[string]pin.Package, []string) {
	packages := map[string]pin.Package{}
	var warnings []string
	for _, s := range servers {
		ref := launchReference(s)
		if ref == "" {
			continue
		}
		lookup, cancel := context.WithTimeout(ctx, 30*time.Second)
		m, err := metadata(lookup, ref, client())
		cancel()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: package maintainer baseline unavailable", s.Name))
			continue
		}
		packages[m.Kind+":"+m.Name] = pin.Package{Version: m.Version, Maintainers: m.Maintainers}
	}
	return packages, warnings
}

func launchReference(s clientconfig.Server) string {
	for key := range s.Env {
		switch strings.ToUpper(key) {
		case "NPM_CONFIG_REGISTRY", "PIP_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX":
			return ""
		}
	}
	base := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(filepath.Base(s.Command)), ".cmd"), ".exe")
	prefix := map[string]string{"npx": "npm:", "uvx": "pypi:", "docker": "oci:"}[base]
	if prefix == "" {
		return ""
	}
	args := s.Args
	if base == "docker" {
		if len(args) == 0 || args[0] != "run" {
			return ""
		}
		args = args[1:]
	}
	values := map[string]bool{"--python": true, "--index-url": true, "--registry": true, "-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true, "--name": true, "--network": true, "-p": true, "--publish": true, "--entrypoint": true, "--user": true, "-u": true, "--workdir": true, "-w": true, "--platform": true, "--pull": true}
	var reference string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--registry") || strings.HasPrefix(a, "--index") || strings.HasPrefix(a, "--default-index") {
			return ""
		}
		if base != "docker" && (a == "--package" || a == "--from" || a == "-p") {
			if i+1 < len(args) {
				if reference == "" {
					reference = prefix + args[i+1]
				}
				i++
				continue
			}
			return ""
		}
		if base != "docker" && (strings.HasPrefix(a, "--package=") || strings.HasPrefix(a, "--from=")) {
			if reference == "" {
				_, value, _ := strings.Cut(a, "=")
				reference = prefix + value
			}
			continue
		}
		if values[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if reference != "" {
			return reference
		}
		return prefix + a
	}
	return reference
}
