package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/approval"
	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/mcp"
	"github.com/RamazanKara/fencepost/internal/pin"
	"github.com/RamazanKara/fencepost/internal/policy"
)

type Request struct {
	Message      mcp.Message
	Context      context.Context
	cancel       context.CancelFunc
	method, tool string
	args         map[string]any
	generation   int
}

type Engine struct {
	Policy                          *policy.Policy
	Log                             *audit.Log
	ServerName, SessionID, lockPath string
	mu                              sync.Mutex
	pending                         map[string]*Request
	trusted                         map[string]bool
	pinned                          bool
	generation                      int
	used                            int
	rates                           map[string][]time.Time
	rateSweep                       time.Time
	always                          map[string]bool
}

func New(p *policy.Policy, log *audit.Log, server, lockPath string) (*Engine, error) {
	e := &Engine{Policy: p, Log: log, ServerName: server, SessionID: approval.Token()[:16], lockPath: lockPath, pending: map[string]*Request{}, trusted: map[string]bool{}, rates: map[string][]time.Time{}, always: map[string]bool{}}
	if _, err := pin.Read(lockPath); err == nil {
		e.pinned = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot read pin baseline")
	}
	return e, nil
}

func (e *Engine) record(kind, method, tool, decision, rule string, redactions map[string]int) error {
	if e.Log == nil {
		return nil
	}
	return e.Log.Write(audit.Event{Session: e.SessionID, Kind: kind, Server: e.ServerName, Method: method, Tool: tool, Decision: decision, Rule: rule, Redactions: redactions})
}

func (e *Engine) Begin(ctx context.Context, m mcp.Message) (*Request, error) {
	// Re-encode the parsed envelope so duplicate JSON keys cannot produce different
	// routing decisions in the proxy and the upstream parser.
	m, err := mcp.Encode(m.Fields)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Request{Message: m, Context: ctx, cancel: cancel, method: m.String("method")}
	reject := func(err error) (*Request, error) {
		cancel()
		if auditErr := e.record("request", r.method, r.tool, "", "", nil); auditErr != nil {
			return nil, auditErr
		}
		if auditErr := e.record("decision", r.method, r.tool, "deny", "invalid_request", nil); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	if r.method == "tools/call" {
		var params map[string]any
		d := json.NewDecoder(bytes.NewReader(m.Fields["params"]))
		d.UseNumber()
		if d.Decode(&params) != nil {
			return reject(errors.New("invalid tool call"))
		}
		r.tool, _ = params["name"].(string)
		r.args, _ = params["arguments"].(map[string]any)
		_, hasArgs := params["arguments"]
		if r.tool == "" || (hasArgs && r.args == nil) {
			return reject(errors.New("invalid tool arguments"))
		}
		if r.args == nil {
			r.args = map[string]any{}
		}
		m.Fields["params"], _ = json.Marshal(params)
		r.Message, err = mcp.Encode(m.Fields)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	e.mu.Lock()
	if r.method == "tools/list" {
		var params struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(m.Fields["params"], &params)
		if params.Cursor == "" {
			e.trusted = map[string]bool{}
			e.generation++
		}
	}
	r.generation = e.generation
	if r.method == "notifications/cancelled" {
		var params struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(m.Fields["params"], &params) == nil {
			id := mcp.Message{Fields: map[string]json.RawMessage{"id": params.RequestID}}
			if pending := e.pending[id.ID()]; pending != nil {
				pending.cancel()
			}
		}
	}
	if r.method != "" && m.Fields["id"] != nil {
		if e.pending[m.ID()] != nil || len(e.pending) >= 1024 {
			e.mu.Unlock()
			return reject(errors.New("duplicate request ID or too many pending requests"))
		}
		e.pending[m.ID()] = r
	}
	e.mu.Unlock()
	if err := e.record("request", r.method, r.tool, "", "", nil); err != nil {
		e.finish(r)
		return nil, err
	}
	return r, nil
}

func (e *Engine) finish(r *Request) {
	e.mu.Lock()
	if e.pending[r.Message.ID()] == r {
		delete(e.pending, r.Message.ID())
	}
	e.mu.Unlock()
	r.cancel()
}

func (e *Engine) Check(r *Request) (*mcp.Message, error) {
	if r.method != "tools/call" {
		if r.Message.Fields["id"] == nil || r.method == "" {
			r.cancel()
		}
		return nil, nil
	}
	deny := func(reason, rule string) (*mcp.Message, error) {
		e.finish(r)
		err := e.record("decision", r.method, r.tool, "deny", rule, nil)
		m := Error(r.Message, -32001, reason)
		return &m, err
	}
	if r.Message.Fields["id"] == nil {
		return deny("Tool calls require a request ID.", "notification")
	}
	action, rule, rate := e.Policy.Match(e.ServerName, r.tool, r.args)
	if action == "deny" {
		if strings.Contains(rule, "/argument:") {
			return deny("Tool arguments are outside the permitted scope.", rule)
		}
		return deny("Fencepost policy does not permit this tool.", rule)
	}
	e.mu.Lock()
	if !e.pinned {
		if _, err := os.Stat(e.lockPath); !errors.Is(err, os.ErrNotExist) {
			e.pinned = true
		}
	}
	trusted := !e.pinned || e.trusted[r.tool]
	always := e.always[r.tool]
	e.mu.Unlock()
	if !trusted {
		return deny("Tool definition is untrusted or changed; review it and run fencepost pin --update, then list tools again.", "pin")
	}
	approvedAlways := false
	if action == "ask" && !always {
		if err := e.record("decision", r.method, r.tool, "ask", rule, nil); err != nil {
			e.finish(r)
			return nil, err
		}
		args, _, _ := scrubValue(r.args, "", true)
		data, _ := json.Marshal(args)
		answer := approval.Ask(r.Context, e.Policy.Approval, approval.Request{Session: e.SessionID, Server: e.ServerName, Tool: r.tool, Arguments: data})
		if answer == "deny" {
			return deny("Approval was denied or timed out.", "approval")
		}
		approvedAlways = answer == "always"
		if action, rule, _ := e.Policy.Match(e.ServerName, r.tool, r.args); action == "deny" {
			return deny("Tool arguments changed while awaiting approval.", rule)
		}
	}
	e.mu.Lock()
	reason, hit := "", ""
	if r.Context.Err() != nil {
		reason, hit = "Tool call was cancelled.", "cancelled"
	} else if e.pinned && !e.trusted[r.tool] {
		reason, hit = "Tool definition changed; list tools again after reviewing the pin.", "pin"
	} else if e.Policy.SessionBudget > 0 && e.used >= e.Policy.SessionBudget {
		reason, hit = "Session tool-call budget exhausted.", "budget"
	}
	now := time.Now()
	if reason == "" && rate > 0 {
		if !now.Before(e.rateSweep) {
			for tool, times := range e.rates {
				if len(times) == 0 || !times[len(times)-1].After(now.Add(-time.Minute)) {
					delete(e.rates, tool)
				}
			}
			e.rateSweep = now.Add(time.Minute)
		}
		times := e.rates[r.tool]
		i := 0
		for i < len(times) && !times[i].After(now.Add(-time.Minute)) {
			i++
		}
		times = times[i:]
		if len(times) >= rate {
			reason, hit = "Tool call rate limit exceeded.", "rate"
		} else {
			times = append(times, now)
		}
		e.rates[r.tool] = times
	}
	if reason == "" {
		e.used++
		if approvedAlways {
			e.always[r.tool] = true
		}
	}
	e.mu.Unlock()
	if reason != "" {
		return deny(reason, hit)
	}
	if err := e.record("decision", r.method, r.tool, "allow", rule, nil); err != nil {
		e.finish(r)
		return nil, err
	}
	return nil, nil
}

func Error(request mcp.Message, code int, message string) mcp.Message {
	fields := map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": code, "message": message}}
	if id := request.Fields["id"]; id != nil {
		fields["id"] = id
	}
	m, _ := mcp.Encode(fields)
	return m
}

func (e *Engine) Server(m mcp.Message) (mcp.Message, error) {
	method := m.String("method")
	if method != "" {
		if method == "notifications/tools/list_changed" {
			e.mu.Lock()
			e.trusted = map[string]bool{}
			e.generation++
			e.mu.Unlock()
		}
		return m, e.record("upstream_request", method, "", "", "", nil)
	}
	e.mu.Lock()
	r := e.pending[m.ID()]
	e.mu.Unlock()
	if r == nil {
		return e.output(m, "")
	}
	defer e.finish(r)
	if r.method == "tools/list" && m.Fields["result"] != nil {
		return e.filterTools(m, r.generation)
	}
	if r.method == "tools/call" {
		return e.output(m, r.tool)
	}
	return m, nil
}

func (e *Engine) filterTools(m mcp.Message, generation int) (mcp.Message, error) {
	var result map[string]json.RawMessage
	var tools []mcp.Tool
	if json.Unmarshal(m.Fields["result"], &result) != nil || json.Unmarshal(result["tools"], &tools) != nil || tools == nil {
		return Error(m, -32603, "Invalid upstream tool list."), nil
	}
	lock, err := pin.Read(e.lockPath)
	e.mu.Lock()
	pinned := e.pinned
	e.mu.Unlock()
	if err != nil && (!errors.Is(err, os.ErrNotExist) || pinned) {
		return Error(m, -32001, "Pin baseline is unavailable."), nil
	}
	if err != nil {
		return m, nil
	}
	visible := make([]mcp.Tool, 0, len(tools))
	seen := map[string]bool{}
	trusted := map[string]bool{}
	for _, t := range tools {
		name := t.Text("name")
		if name == "" || seen[name] {
			return Error(m, -32603, "Invalid upstream tool list."), nil
		}
		seen[name] = true
		hash, err := pin.ToolHash(t)
		if err != nil {
			return m, err
		}
		if pinnedTool, ok := lock.Servers[e.ServerName].Tools[name]; ok && hash == pinnedTool.Hash {
			visible = append(visible, t)
			trusted[name] = true
		} else {
			trusted[name] = false
			if err := e.record("decision", "tools/list", name, "hide", "pin", nil); err != nil {
				return m, err
			}
		}
	}
	e.mu.Lock()
	e.pinned = true
	if generation == e.generation {
		for name, valid := range trusted {
			if valid {
				e.trusted[name] = true
			} else {
				delete(e.trusted, name)
			}
		}
	}
	e.mu.Unlock()
	result["tools"], _ = json.Marshal(visible)
	m.Fields["result"], _ = json.Marshal(result)
	return mcp.Encode(m.Fields)
}

func (e *Engine) Fail() []mcp.Message {
	e.mu.Lock()
	requests := e.pending
	e.pending = map[string]*Request{}
	e.mu.Unlock()
	var messages []mcp.Message
	for _, r := range requests {
		r.cancel()
		messages = append(messages, Error(r.Message, -32002, "Upstream server disconnected; restart the connection."))
		_ = e.record("decision", r.method, r.tool, "deny", "upstream", nil)
	}
	return messages
}

func (e *Engine) Forget(m mcp.Message) {
	e.mu.Lock()
	r := e.pending[m.ID()]
	e.mu.Unlock()
	if r != nil {
		e.finish(r)
	}
}
