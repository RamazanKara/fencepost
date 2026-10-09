package approval

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"

	"github.com/RamazanKara/fencepost/internal/scan"
)

type pending struct {
	Request
	reply chan string
}
type Channel struct {
	mu            sync.Mutex
	origin, token string
	pending       map[string]*pending
}

func New(origin, token string) *Channel {
	return &Channel{origin: origin, token: token, pending: map[string]*pending{}}
}

func (c *Channel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(c.origin)
	if r.Host != u.Host || !hmac.Equal([]byte(bearer(r)), []byte(c.token)) || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != c.origin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	switch {
	case r.Method == "POST" && r.URL.Path == "/request":
		var request Request
		body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
		if err != nil || len(body) > 64<<10 || json.Unmarshal(body, &request) != nil || request.ID == "" || !json.Valid(request.Arguments) {
			http.Error(w, "Invalid request", 400)
			return
		}
		// The channel is also a boundary: sanitize even a caller that bypasses the proxy.
		var args any
		decoder := json.NewDecoder(bytes.NewReader(request.Arguments))
		decoder.UseNumber()
		_ = decoder.Decode(&args)
		request.Arguments, _ = json.Marshal(scrub(args, ""))
		request.Server, _ = scan.RedactSecrets("", request.Server)
		request.Tool, _ = scan.RedactSecrets("", request.Tool)
		p := &pending{Request: request, reply: make(chan string, 1)}
		c.mu.Lock()
		if len(c.pending) >= 128 || c.pending[request.ID] != nil {
			c.mu.Unlock()
			http.Error(w, "Busy", http.StatusTooManyRequests)
			return
		}
		c.pending[request.ID] = p
		c.mu.Unlock()
		defer func() { c.mu.Lock(); delete(c.pending, request.ID); c.mu.Unlock() }()
		select {
		case answer := <-p.reply:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(Response{answer})
		case <-r.Context().Done():
		}
	case r.Method == "POST" && r.URL.Path == "/decision":
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "Invalid form", 400)
			return
		}
		decision := r.PostForm.Get("decision")
		if decision != "allow" && decision != "always" && decision != "deny" {
			http.Error(w, "Invalid decision", 400)
			return
		}
		c.mu.Lock()
		p := c.pending[r.PostForm.Get("id")]
		c.mu.Unlock()
		if p == nil {
			http.Error(w, "Request expired", 404)
			return
		}
		select {
		case p.reply <- decision:
		default:
			http.Error(w, "Already decided", http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/?token="+c.token, http.StatusSeeOther)
	case r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/pending"):
		c.mu.Lock()
		items := make([]Request, 0, len(c.pending))
		for _, p := range c.pending {
			items = append(items, p.Request)
		}
		c.mu.Unlock()
		sort.Slice(items, func(i, j int) bool { return items[i].Time < items[j].Time })
		if r.URL.Path == "/pending" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(items)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, struct {
			Token string
			Items []Request
		}{c.token, items})
	default:
		http.NotFound(w, r)
	}
}

func scrub(v any, key string) any {
	switch x := v.(type) {
	case string:
		s, _ := scan.RedactSecrets(key, x)
		return s
	case map[string]any:
		result := make(map[string]any, len(x))
		for k, child := range x {
			cleanKey, _ := scan.RedactSecrets("", k)
			result[cleanKey] = scrub(child, k)
		}
		return result
	case []any:
		for i, child := range x {
			x[i] = scrub(child, key)
		}
	}
	return v
}

var page = template.Must(template.New("approval").Funcs(template.FuncMap{"json": func(raw json.RawMessage) string { return string(raw) }}).Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="refresh" content="3"><title>Fencepost approvals</title>
<style>body{font:16px system-ui;max-width:760px;margin:3rem auto;padding:0 1rem;background:#f5f6f4;color:#18251c}article{background:white;padding:1.5rem;margin:1rem 0;border:1px solid #c8d2cb;border-radius:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere}button{padding:.65rem;margin:.25rem;border:1px solid #52685a;border-radius:4px;cursor:pointer}button[value=allow]{background:#164b32;color:white}</style>
<h1>Fencepost approvals</h1><p>Review the server, tool, and arguments before allowing a call. Requests expire automatically.</p>
{{range .Items}}<article><h2>{{.Server}} / {{.Tool}}</h2><pre>{{json .Arguments}}</pre><form method="post" action="/decision?token={{$.Token}}"><input type="hidden" name="id" value="{{.ID}}"><button name="decision" value="allow">Approve once</button><button name="decision" value="always">Always for this session</button><button name="decision" value="deny">Deny</button></form></article>{{else}}<p>No pending requests.</p>{{end}}</html>`))
