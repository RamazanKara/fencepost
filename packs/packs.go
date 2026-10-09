package packs

import (
	"embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var files embed.FS

func Compose(names string) ([]byte, error) {
	servers := map[string]any{}
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "/\\.") {
			return nil, fmt.Errorf("invalid pack name %q", name)
		}
		data, err := files.ReadFile(name + ".yaml")
		if err != nil {
			return nil, fmt.Errorf("unknown pack %q; choose filesystem, git, fetch, browser, database, shell, cloud", name)
		}
		var pack struct {
			Servers map[string]any `yaml:"servers"`
		}
		if err := yaml.Unmarshal(data, &pack); err != nil {
			return nil, err
		}
		for server, rules := range pack.Servers {
			if _, exists := servers[server]; exists {
				return nil, fmt.Errorf("pack repeats server %q", server)
			}
			servers[server] = rules
		}
	}
	return yaml.Marshal(struct {
		Version int            `yaml:"version"`
		Servers map[string]any `yaml:"servers"`
		Output  map[string]any `yaml:"output"`
	}{1, servers, map[string]any{"redact_secrets": true, "max_bytes": 1048576, "injection": "block"}})
}
