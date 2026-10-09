package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/RamazanKara/fencepost/internal/policy"
)

type Filter struct {
	User, Server, Tool, Decision string
	From, Until                  time.Time
}

func Query(path string, filter Filter, out io.Writer) error {
	var events []Event
	_, err := Verify(path, func(e Event) {
		if (filter.User != "" && e.User != filter.User) || (filter.Server != "" && e.Server != filter.Server) || (filter.Tool != "" && e.Tool != filter.Tool) || (filter.Decision != "" && e.Decision != filter.Decision) {
			return
		}
		stamp, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil || (!filter.From.IsZero() && stamp.Before(filter.From)) || (!filter.Until.IsZero() && stamp.After(filter.Until)) {
			return
		}
		events = append(events, e)
	})
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := json.NewEncoder(out).Encode(e); err != nil {
			return err
		}
	}
	return nil
}

type Diff struct {
	Time   string `json:"time"`
	User   string `json:"user,omitempty"`
	Server string `json:"server"`
	Tool   string `json:"tool"`
	Before string `json:"before"`
	After  string `json:"after"`
	Rule   string `json:"rule"`
	Note   string `json:"note,omitempty"`
}

func PolicyDiff(path string, p *policy.Policy, out io.Writer) (int, error) {
	var events []Event

	_, err := Verify(path, func(e Event) {
		if e.Kind == "policy" || (e.Kind == "decision" && e.Method == "tools/call") {
			events = append(events, e)
		}
	})
	if err != nil {
		return 0, err
	}
	return PolicyDiffEvents(events, p, out)
}

func PolicyDiffEvents(events []Event, p *policy.Policy, out io.Writer) (int, error) {
	modern := map[string]bool{}
	for _, e := range events {
		if e.Kind == "policy" {
			modern[e.Session] = true
		}
	}
	count := 0
	for _, e := range events {
		if e.Kind != "policy" && (e.Kind != "decision" || e.Method != "tools/call") {
			continue
		}
		if e.Kind != "policy" && (modern[e.Session] || (e.Rule != "default" && e.Rule != "server" && !strings.HasPrefix(e.Rule, "tool:"))) {
			continue
		}
		args := map[string]any{}
		if len(e.Arguments) > 0 {
			d := json.NewDecoder(bytes.NewReader(e.Arguments))
			d.UseNumber()
			if d.Decode(&args) != nil {
				return count, fmt.Errorf("invalid recorded arguments")
			}
		}
		action, rule, _, _ := p.MatchIdentity(e.Server, e.Tool, args, policy.Identity{User: e.User, Groups: e.Groups, Client: e.Client})
		note := ""
		if (len(e.Arguments) > 0 && !e.Replayable) || (len(e.Arguments) == 0 && strings.Contains(rule, "/argument:")) {
			action, note = "unknown", "arguments were not recorded intact; constraints cannot be replayed"
		}
		if action == e.Decision {
			continue
		}
		if err := json.NewEncoder(out).Encode(Diff{Time: e.Time, User: e.User, Server: e.Server, Tool: e.Tool, Before: e.Decision, After: action, Rule: rule, Note: note}); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
