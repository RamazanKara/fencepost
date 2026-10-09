package policy

import (
	"fmt"
	"math/rand"
	"testing"
	"testing/quick"
)

func TestMatchProperties(t *testing.T) {
	actions := []string{"allow", "deny", "ask"}
	property := func(seed uint64, pick uint8) bool {
		name := fmt.Sprintf("read_%x", seed)
		first, fallback := actions[int(pick)%3], actions[(int(pick)+1)%3]
		p := &Policy{Servers: map[string]Server{"s": {Default: fallback, Tools: []Tool{
			{Name: name, Action: first, RateLimit: 7},
			{Name: "read_*", Action: fallback},
		}}}}
		got, rule, rate := p.Match("s", name, nil)
		if got != first || rule != "tool:1" || rate != 7 {
			return false
		}
		got, rule, rate = p.Match("unknown", name, nil)
		if got != "deny" || rule != "server" || rate != 0 {
			return false
		}
		got, rule, rate = p.Match("s", name+"/nested", nil)
		return got == fallback && rule == "default" && rate == 0
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000, Rand: rand.New(rand.NewSource(1))}); err != nil {
		t.Fatal(err)
	}
}

func TestArgumentProperties(t *testing.T) {
	max := 4
	p := testPolicy(t, Argument{Path: "$.items[*].value", Regex: "^[a-z]+$", MaxLength: &max, Enum: []any{"safe", "yes"}})
	server := p.Servers["s"]
	server.Default = "allow"
	server.Tools = append(server.Tools, Tool{Name: "*", Action: "allow"})
	p.Servers["s"] = server
	property := func(input []uint8) bool {
		items := make([]any, len(input))
		allowed := len(input) > 0
		for i, v := range input {
			switch v % 5 {
			case 0:
				items[i] = map[string]any{"value": "safe"}
			case 1:
				items[i] = map[string]any{"value": "yes"}
			case 2:
				items[i] = map[string]any{"value": "outside"}
				allowed = false
			case 3:
				items[i] = map[string]any{}
				allowed = false
			case 4:
				items[i] = "safe"
				allowed = false
			}
		}
		got, rule, _ := p.Match("s", "read_file", map[string]any{"items": items})
		if allowed {
			return got == "allow" && rule == "tool:1"
		}
		return got == "deny" && rule == "tool:1/argument:1"
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000, Rand: rand.New(rand.NewSource(2))}); err != nil {
		t.Fatal(err)
	}
}
