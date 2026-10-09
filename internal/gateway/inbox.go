package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/approval"
	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/policy"
	"github.com/RamazanKara/fencepost/internal/scan"
)

type InboxConfig struct {
	Groups        []string `yaml:"groups"`
	WebhookURL    string   `yaml:"webhook_url"`
	HMACSecretEnv string   `yaml:"hmac_secret_env"`
}
type item struct {
	approval.Request
	Decision string `json:"decision"`
	Approver string `json:"approver,omitempty"`
	Reason   string `json:"reason,omitempty"`
	reply    chan string
	expires  time.Time
}
type inbox struct {
	mu         sync.Mutex
	items      map[string]*item
	history    []item
	config     InboxConfig
	base, csrf string
	log        *audit.Log
}

func newInbox(config InboxConfig, base string, log *audit.Log) *inbox {
	return &inbox{items: map[string]*item{}, config: config, base: base, csrf: approval.Token(), log: log}
}

func (i *inbox) ask(ctx context.Context, config policy.Approval, request approval.Request) string {
	timeout, _ := time.ParseDuration(config.Timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request.ID, request.Time = approval.Token(), time.Now().Unix()
	if len(request.Arguments) > 64<<10 {
		return "deny"
	}
	p := &item{Request: request, Decision: "pending", reply: make(chan string, 1), expires: time.Now().Add(timeout)}
	i.mu.Lock()
	if len(i.items) >= 128 {
		i.mu.Unlock()
		return "deny"
	}
	i.items[request.ID] = p
	i.mu.Unlock()
	defer func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		if p.Decision == "pending" {
			p.Decision = "expired"
		}
		delete(i.items, request.ID)
		copy := *p
		copy.reply = nil
		i.history = append(i.history, copy)
		if len(i.history) > 256 {
			i.history = i.history[1:]
		}
	}()
	if i.config.WebhookURL != "" {
		go i.notify(ctx, request)
	}
	select {
	case answer := <-p.reply:
		if ctx.Err() != nil || !time.Now().Before(p.expires) {
			return "deny"
		}
		return answer
	case <-ctx.Done():
		return "deny"
	}
}

func (i *inbox) notify(ctx context.Context, request approval.Request) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	data, _ := json.Marshal(struct {
		approval.Request
		URL string `json:"approval_url"`
	}{request, i.base + "/approvals"})
	req, err := http.NewRequestWithContext(ctx, "POST", i.config.WebhookURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fencepost-Signature", approval.Signature([]byte(os.Getenv(i.config.HMACSecretEnv)), data))
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	decision := "sent"
	if err != nil {
		decision = "failed"
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			decision = "failed"
		}
	}
	if i.log != nil {
		_ = i.log.Write(audit.Event{Kind: "approval_webhook", Session: request.Session, Server: request.Server, Tool: request.Tool, User: request.User, Decision: decision})
	}
}

func (i *inbox) serve(w http.ResponseWriter, r *http.Request, identity policy.Identity) {
	allowed := false
	for _, group := range identity.Groups {
		allowed = allowed || slices.Contains(i.config.Groups, group)
	}
	if !allowed {
		http.Error(w, "Approver group required", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method == "POST" && r.URL.Path == "/approvals/decision" {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if r.ParseForm() != nil || r.PostForm.Get("csrf") != i.csrf {
			http.Error(w, "Invalid form", 400)
			return
		}
		decision, reason := r.PostForm.Get("decision"), r.PostForm.Get("reason")
		if (decision != "allow" && decision != "deny") || len(reason) == 0 || len(reason) > 1024 {
			http.Error(w, "Choose allow or deny and supply a reason of 1..1024 bytes", 400)
			return
		}
		reason, _ = scan.RedactSecrets("", reason)
		i.mu.Lock()
		defer i.mu.Unlock()
		p := i.items[r.PostForm.Get("id")]
		if p == nil || !time.Now().Before(p.expires) {
			http.Error(w, "Request expired", 404)
			return
		}
		if p.Decision != "pending" {
			http.Error(w, "Already decided", http.StatusConflict)
			return
		}
		if i.log != nil {
			if err := i.log.Write(audit.Event{Kind: "approval", Session: p.Session, Server: p.Server, Tool: p.Tool, User: p.User, Groups: p.Groups, Client: p.Client, Decision: decision, Approver: identity.User, Reason: reason}); err != nil {
				http.Error(w, "Audit unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		p.Decision, p.Approver, p.Reason = decision, identity.User, reason
		p.reply <- decision
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
		return
	}
	if r.Method != "GET" || (r.URL.Path != "/approvals" && r.URL.Path != "/approvals/pending") {
		http.NotFound(w, r)
		return
	}
	i.mu.Lock()
	items := make([]item, 0, len(i.items))
	for _, p := range i.items {
		items = append(items, *p)
	}
	history := append([]item(nil), i.history...)
	i.mu.Unlock()
	sort.Slice(items, func(a, b int) bool { return items[a].Time < items[b].Time })
	if r.URL.Path == "/approvals/pending" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = inboxPage.Execute(w, struct {
		User, CSRF       string
		Pending, History []item
	}{identity.User, i.csrf, items, history})
}

var inboxPage = template.Must(template.New("inbox").Funcs(template.FuncMap{"json": func(raw json.RawMessage) string { return string(raw) }}).Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Fencepost approval inbox</title>
<style>body{font:16px system-ui;max-width:900px;margin:3rem auto;padding:0 1rem;color:#18251c;background:#f5f6f4}article{background:white;border:1px solid #c8d2cb;padding:1.5rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}textarea{width:100%;box-sizing:border-box}button{padding:.7rem;margin:.4rem 0}</style>
<h1>Approval inbox</h1><p>Signed in as {{.User}}. <a href="/approvals">Refresh</a></p>
{{range .Pending}}<article><h2>{{.Server}} / {{.Tool}}</h2><p>Requested by {{.User}} via {{.Client}} · {{.Decision}}</p><pre>{{json .Arguments}}</pre>
<form method="post" action="/approvals/decision"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}"><label>Reason<textarea name="reason" required maxlength="1024"></textarea></label><button name="decision" value="allow">Approve once</button> <button name="decision" value="deny">Deny</button></form></article>{{else}}<p>No pending requests.</p>{{end}}
<h2>Recent decisions</h2>{{range .History}}<article><b>{{.Server}} / {{.Tool}}: {{.Decision}}</b><p>{{.Approver}} · {{.Reason}}</p></article>{{else}}<p>No recent decisions.</p>{{end}}</html>`))
