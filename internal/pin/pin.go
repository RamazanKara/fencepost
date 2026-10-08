package pin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/mcp"
	"github.com/RamazanKara/fencepost/internal/scan"
	"gopkg.in/yaml.v3"
)

type Tool struct {
	Hash        string `yaml:"hash"`
	Description string `yaml:"description"`
}

type Server struct {
	LaunchHash string          `yaml:"launchHash"`
	Tools      map[string]Tool `yaml:"tools"`
}

type Lock struct {
	Version int               `yaml:"version"`
	Servers map[string]Server `yaml:"servers"`
}

// Canonical sorts object keys, retains array order, and normalizes numbers exactly.
// It does not round JSON numbers through float64.
func Canonical(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("expected one JSON value")
	}
	var normalize func(any) any
	normalize = func(value any) any {
		switch v := value.(type) {
		case map[string]any:
			for k, child := range v {
				v[k] = normalize(child)
			}
		case []any:
			for i, child := range v {
				v[i] = normalize(child)
			}
		case json.Number:
			return json.Number(canonicalNumber(v.String()))
		}
		return value
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalize(value)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

func canonicalNumber(s string) string {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == 'e' || r == 'E' })
	exponent := new(big.Int)
	if len(parts) > 1 {
		exponent.SetString(strings.TrimPrefix(parts[1], "+"), 10)
	}
	whole, fraction, _ := strings.Cut(parts[0], ".")
	exponent.Sub(exponent, big.NewInt(int64(len(fraction))))
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return "0"
	}
	trimmed := strings.TrimRight(digits, "0")
	exponent.Add(exponent, big.NewInt(int64(len(digits)-len(trimmed))))
	if negative {
		trimmed = "-" + trimmed
	}
	if exponent.Sign() != 0 {
		trimmed += "e" + exponent.String()
	}
	return trimmed
}

func hash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := Canonical(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func ToolHash(tool mcp.Tool) (string, error) {
	fields := map[string]json.RawMessage{}
	for _, key := range []string{"name", "description", "inputSchema", "outputSchema", "annotations"} {
		if value, ok := tool[key]; ok {
			fields[key] = value
		}
	}
	return hash(fields)
}

func Snapshot(inventories []scan.Inventory) (Lock, error) {
	lock := Lock{1, map[string]Server{}}
	servers := make([]clientconfig.Server, 0, len(inventories))
	for _, inv := range inventories {
		servers = append(servers, inv.Server)
	}
	for _, inv := range inventories {
		s := inv.Server
		if _, ok := lock.Servers[s.Name]; ok {
			return Lock{}, errors.New("duplicate server name; use --config to select one configuration before pinning")
		}
		launch, err := hash(map[string]any{"transport": s.Transport, "command": s.Command, "args": s.Args, "env": s.Env, "url": s.URL, "headers": s.Headers, "cwd": s.Cwd, "envFile": s.EnvFile})
		if err != nil {
			return Lock{}, err
		}
		entry := Server{launch, map[string]Tool{}}
		for _, t := range inv.Catalog.Tools {
			toolHash, err := ToolHash(t)
			if err != nil {
				return Lock{}, err
			}
			entry.Tools[t.Text("name")] = Tool{toolHash, clientconfig.Redact(t.Text("description"), servers)}
		}
		lock.Servers[s.Name] = entry
	}
	return lock, nil
}

func Read(path string) (Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	var lock Lock
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if decoder.Decode(&lock) != nil || lock.Version != 1 || lock.Servers == nil {
		return Lock{}, errors.New("invalid or unsupported lockfile")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Lock{}, errors.New("lockfile contains multiple documents")
	}
	for _, s := range lock.Servers {
		if !validHash(s.LaunchHash) || s.Tools == nil {
			return Lock{}, errors.New("invalid server entry in lockfile")
		}
		for _, t := range s.Tools {
			if !validHash(t.Hash) {
				return Lock{}, errors.New("invalid tool hash in lockfile")
			}
		}
	}
	return lock, nil
}

func validHash(hash string) bool {
	data, err := hex.DecodeString(hash)
	return err == nil && len(data) == sha256.Size
}

func Write(path string, lock Lock) error {
	data, err := yaml.Marshal(lock)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".fencepost-lock-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp, path)
}

type Drift struct {
	Server string
	Tool   string
	Kind   string
	Diff   string
}

func Compare(old, current Lock) []Drift {
	var changes []Drift
	for name, previous := range old.Servers {
		now, exists := current.Servers[name]
		if !exists {
			changes = append(changes, Drift{name, "", "removed server", ""})
			continue
		}
		if now.LaunchHash != previous.LaunchHash {
			changes = append(changes, Drift{name, "", "changed launch spec", ""})
		}
		for tool, before := range previous.Tools {
			after, ok := now.Tools[tool]
			if !ok {
				changes = append(changes, Drift{name, tool, "removed", unified(name+"/"+tool, before.Description, "")})
			} else if after.Hash != before.Hash {
				changes = append(changes, Drift{name, tool, "changed", unified(name+"/"+tool, before.Description, after.Description)})
			}
		}
		for tool, after := range now.Tools {
			if _, ok := previous.Tools[tool]; !ok {
				changes = append(changes, Drift{name, tool, "added", unified(name+"/"+tool, "", after.Description)})
			}
		}
	}
	for name := range current.Servers {
		if _, ok := old.Servers[name]; !ok {
			changes = append(changes, Drift{name, "", "added server", ""})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		return a.Kind < b.Kind
	})
	return changes
}

func Update(old, current Lock, target string) (Lock, error) {
	server, tool, ok := strings.Cut(target, "/")
	if !ok || server == "" || tool == "" {
		return Lock{}, errors.New("--update requires server/tool")
	}
	previous, oldExists := old.Servers[server]
	now, newExists := current.Servers[server]
	if !oldExists || !newExists {
		return Lock{}, errors.New("target server must exist in the lockfile and current configuration")
	}
	if previous.LaunchHash != now.LaunchHash {
		return Lock{}, errors.New("launch spec changed; tool update cannot approve a server launch change")
	}
	_, was := previous.Tools[tool]
	after, is := now.Tools[tool]
	if !was && !is {
		return Lock{}, errors.New("update target does not exist")
	}
	updated := Lock{old.Version, map[string]Server{}}
	for name, s := range old.Servers {
		copy := Server{s.LaunchHash, map[string]Tool{}}
		for name, t := range s.Tools {
			copy.Tools[name] = t
		}
		updated.Servers[name] = copy
	}
	if is {
		updated.Servers[server].Tools[tool] = after
	} else {
		delete(updated.Servers[server].Tools, tool)
	}
	return updated, nil
}

func unified(name, before, after string) string {
	if before == after {
		return ""
	}
	lines := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	}
	a, b := lines(before), lines(after)
	var out strings.Builder
	fmt.Fprintf(&out, "--- a/%s/description\n+++ b/%s/description\n@@ -%d,%d +%d,%d @@\n", name, name, min(1, len(a)), len(a), min(1, len(b)), len(b))
	// One full-context hunk remains readable and bounds memory for hostile descriptions.
	for _, line := range a {
		fmt.Fprintf(&out, "-%s\n", line)
	}
	if len(a) > 0 && !strings.HasSuffix(before, "\n") {
		out.WriteString("\\ No newline at end of file\n")
	}
	for _, line := range b {
		fmt.Fprintf(&out, "+%s\n", line)
	}
	if len(b) > 0 && !strings.HasSuffix(after, "\n") {
		out.WriteString("\\ No newline at end of file\n")
	}
	return out.String()
}
