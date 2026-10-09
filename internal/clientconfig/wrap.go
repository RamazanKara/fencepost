package clientconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Edit struct {
	Path          string
	Before, After []byte
}

func Wrap(data []byte, source, project, executable, policyPath, lockPath string) ([]byte, error) {
	servers, err := Parse(data, source, project)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, s := range servers {
		if s.EnvFile != "" {
			return nil, errors.New("envFile is unsupported; declare environment values explicitly")
		}
		if names[s.Name] {
			return nil, errors.New("cannot wrap duplicate server names in one config")
		}
		names[s.Name] = true
		if s.Transport != "stdio" && s.Transport != "http" {
			return nil, errors.New("cannot wrap an unsupported transport")
		}
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(jsonc(data)))
	decoder.UseNumber()
	if decoder.Decode(&root) != nil {
		return nil, errors.New("invalid config")
	}
	var groups []map[string]any
	add := func(v any) {
		if m, ok := v.(map[string]any); ok {
			groups = append(groups, m)
		}
	}
	add(root["mcpServers"])
	add(root["servers"])
	add(root["mcp.servers"])
	if m, ok := root["mcp"].(map[string]any); ok {
		add(m["servers"])
	}
	if projects, ok := root["projects"].(map[string]any); ok {
		for p, v := range projects {
			if filepath.Clean(p) == filepath.Clean(project) {
				if m, ok := v.(map[string]any); ok {
					add(m["mcpServers"])
				}
			}
		}
	}
	for _, group := range groups {
		for name, value := range group {
			spec, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("invalid server config")
			}
			if disabled, _ := spec["disabled"].(bool); disabled {
				continue
			}
			if command, _ := spec["command"].(string); command == executable {
				return nil, errors.New("config already includes fencepost; unwrap before wrapping again")
			}
			args := []string{"proxy", "--server", name, "--config", source + ".fencepost.bak", "--policy", policyPath, "--lock", lockPath}
			env, _ := spec["env"].(map[string]any)
			if env == nil {
				env = map[string]any{}
			}
			var references func(any)
			needed := map[string]string{}
			references = func(value any) {
				switch x := value.(type) {
				case string:
					for _, ref := range variable.FindAllString(x, -1) {
						key := strings.TrimPrefix(strings.TrimPrefix(ref[2:len(ref)-1], "env:"), "env.")
						key, _, _ = strings.Cut(key, ":-")
						needed[key] = ref
					}
				case map[string]any:
					for _, child := range x {
						references(child)
					}
				case []any:
					for _, child := range x {
						references(child)
					}
				}
			}
			references(spec)
			for key, ref := range needed {
				if _, exists := env[key]; !exists {
					env[key] = ref
				}
			}
			if len(env) > 0 {
				spec["env"] = env
			}
			for _, key := range []string{"url", "serverUrl", "headers", "envFile", "args", "command", "type"} {
				delete(spec, key)
			}
			spec["command"], spec["args"], spec["type"] = executable, args, "stdio"
		}
	}
	result, err := json.MarshalIndent(root, "", "  ")
	return append(result, '\n'), err
}

func PlanWrap(p Paths, explicit, executable, policyPath, lockPath string, unwrap bool) ([]Edit, error) {
	paths := Candidates(p)
	if explicit != "" {
		paths = []string{explicit}
	}
	seen := map[string]bool{}
	var edits []Edit
	for _, path := range paths {
		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		before, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && explicit == "" {
			continue
		}
		if err != nil {
			return nil, err
		}
		var after []byte
		if unwrap {
			after, err = os.ReadFile(path + ".fencepost.bak")
			if errors.Is(err, os.ErrNotExist) && explicit == "" {
				continue
			}
		} else {
			servers, parseErr := Parse(before, path, p.Project)
			if parseErr != nil {
				return nil, parseErr
			}
			if len(servers) == 0 {
				continue
			}
			if _, err := os.Stat(path + ".fencepost.bak"); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("backup already exists or cannot be inspected")
			}
			after, err = Wrap(before, path, p.Project, executable, policyPath, lockPath)
		}
		if err != nil {
			return nil, err
		}
		edits = append(edits, Edit{path, before, after})
	}
	return edits, nil
}

func Apply(edit Edit, unwrap bool) error {
	current, err := os.ReadFile(edit.Path)
	if err != nil {
		return err
	}
	if string(current) != string(edit.Before) {
		return errors.New("config changed after the diff was prepared")
	}
	if !unwrap {
		backup, err := os.OpenFile(edit.Path+".fencepost.bak", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = backup.Write(edit.Before)
		if err == nil {
			err = backup.Sync()
		}
		closeErr := backup.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	info, err := os.Stat(edit.Path)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(edit.Path), ".fencepost-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(info.Mode().Perm()); err == nil {
		_, err = f.Write(edit.After)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), edit.Path); err != nil {
		return err
	}
	if unwrap {
		return os.Remove(edit.Path + ".fencepost.bak")
	}
	return nil
}

func Diff(edit Edit) string {
	servers, _ := Parse(edit.Before, edit.Path, "")
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n@@ full file (credentials masked) @@\n", edit.Path, edit.Path)
	for _, pair := range []struct {
		prefix string
		data   []byte
	}{{"-", edit.Before}, {"+", edit.After}} {
		masked := string(pair.data)
		var root any
		_ = json.Unmarshal(jsonc(pair.data), &root)
		var mask func(any)
		mask = func(value any) {
			if object, ok := value.(map[string]any); ok {
				for key, child := range object {
					if key == "env" || key == "headers" {
						if fields, ok := child.(map[string]any); ok {
							for name, value := range fields {
								if s, ok := value.(string); ok && s != "" {
									raw, _ := json.Marshal(s)
									placeholder, _ := json.Marshal("<redacted:" + name + ">")
									masked = strings.ReplaceAll(masked, string(raw), string(placeholder))
								}
							}
						}
					}
					mask(child)
				}
			}
		}
		mask(root)
		for _, line := range strings.Split(strings.TrimSuffix(Redact(masked, servers), "\n"), "\n") {
			fmt.Fprintln(&b, pair.prefix+line)
		}
	}
	return b.String()
}
