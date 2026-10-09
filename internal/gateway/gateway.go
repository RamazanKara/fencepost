package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/policy"
	"github.com/RamazanKara/fencepost/internal/proxy"
)

type connection struct {
	handler http.Handler
	close   func()
	used    time.Time
	active  int
}

type Gateway struct {
	config      Config
	auth        *authenticator
	policy      *policy.Source
	log         *audit.Log
	inbox       *inbox
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	mu          sync.Mutex
	connections map[string]*connection
}

func New(ctx context.Context, c Config, base string, stdout, diagnostics io.Writer) (*Gateway, error) {
	if err := c.validate(base); err != nil {
		return nil, err
	}
	source, err := policy.LoadSource(ctx, c.Policy, base)
	if err != nil {
		return nil, err
	}
	auth, err := newAuthenticator(ctx, c.Auth)
	if err != nil {
		return nil, err
	}
	log, err := audit.OpenConfigured(source.Current().Audit, stdout)
	if err != nil {
		auth.client.CloseIdleConnections()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &Gateway{config: c, auth: auth, policy: source, log: log, ctx: ctx, cancel: cancel, done: make(chan struct{}), connections: map[string]*connection{}}
	g.inbox = newInbox(c.Approval, c.PublicURL, log)
	go func() {
		defer close(g.done)
		source.Poll(ctx, func(err error) {
			fmt.Fprintf(diagnostics, "Policy refresh rejected; retaining last verified policy: %v\n", err)
		})
	}()
	return g, nil
}

func (g *Gateway) Close() error {
	g.cancel()
	<-g.done
	g.mu.Lock()
	for key, c := range g.connections {
		c.close()
		delete(g.connections, key)
	}
	g.mu.Unlock()
	g.auth.client.CloseIdleConnections()
	return g.log.Close()
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	u, _ := url.Parse(g.config.PublicURL)
	if r.Host != u.Host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != g.config.PublicURL) {
		http.Error(w, "Unexpected host or origin", http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" && r.URL.Path != "/callback" {
		http.Error(w, "Query parameters are not accepted", 400)
		return
	}
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		w.WriteHeader(204)
		return
	}
	if r.URL.Path == "/login" || r.URL.Path == "/callback" {
		g.auth.browser(w, r, g.config.PublicURL)
		return
	}
	path := r.URL.Path
	metadata := strings.HasPrefix(path, "/.well-known/oauth-protected-resource/")
	if metadata {
		path = strings.TrimPrefix(path, "/.well-known/oauth-protected-resource")
	}
	browser := path == "/approvals" || strings.HasPrefix(path, "/approvals/")
	server := strings.TrimPrefix(path, "/mcp/")
	upstream, found := g.config.Servers[server]
	if !browser && (!strings.HasPrefix(path, "/mcp/") || !found) {
		http.NotFound(w, r)
		return
	}
	resource := g.config.PublicURL + path
	if browser {
		resource = g.config.PublicURL + "/approvals"
	}
	metadataURL := g.config.PublicURL + "/.well-known/oauth-protected-resource" + strings.TrimPrefix(resource, g.config.PublicURL)
	if metadata {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		issuers := []string{}
		if g.config.Auth.Issuer != "" {
			issuers = append(issuers, g.config.Auth.Issuer)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": issuers, "bearer_methods_supported": []string{"header"}})
		return
	}
	identity, err := g.auth.identity(r, resource, browser)
	if err != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q, error=\"invalid_token\"", metadataURL))
		if browser && r.Method == "GET" && r.Header.Get("Authorization") == "" && g.config.Auth.BrowserClientID != "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	if browser {
		g.inbox.serve(w, r, identity)
		return
	}
	if r.Method != "POST" && r.Method != "GET" && r.Method != "DELETE" {
		w.WriteHeader(405)
		return
	}
	encoded, _ := json.Marshal(identity)
	key := server + "\n" + string(encoded)
	g.mu.Lock()
	for k, c := range g.connections {
		if c.active == 0 && time.Since(c.used) > 30*time.Minute {
			c.close()
			delete(g.connections, k)
		}
	}
	c := g.connections[key]
	if c == nil {
		if len(g.connections) >= 256 {
			g.mu.Unlock()
			http.Error(w, "Gateway busy", http.StatusServiceUnavailable)
			return
		}
		c = &connection{}
		if upstream.URL != "" {
			h, err := proxy.NewHTTP(g.policy.Current(), g.log, server, g.config.Lock, upstream.URL, upstream.Headers)
			if err != nil {
				g.mu.Unlock()
				http.Error(w, "Upstream configuration unavailable", http.StatusServiceUnavailable)
				return
			}
			h.Configure(identity, g.policy.Current, g.inbox.ask)
			c.handler, c.close = h, h.Close
		} else {
			e, err := proxy.New(g.policy.Current(), g.log, server, g.config.Lock)
			if err != nil {
				g.mu.Unlock()
				http.Error(w, "Pin baseline unavailable", http.StatusServiceUnavailable)
				return
			}
			e.Identity, e.PolicySource, e.Approve = identity, g.policy.Current, g.inbox.ask
			h := proxy.NewStdioHTTP(g.ctx, e, clientconfig.Server{Name: server, Command: upstream.Command, Args: upstream.Args, Env: upstream.Env, Cwd: upstream.Cwd})
			c.handler, c.close = h, h.Close
		}
		g.connections[key] = c
	}
	c.active++
	c.used = time.Now()
	g.mu.Unlock()
	defer func() { g.mu.Lock(); c.active--; c.used = time.Now(); g.mu.Unlock() }()
	r = r.Clone(r.Context())
	r.Header.Del("Origin")
	c.handler.ServeHTTP(w, r)
}

func Serve(ctx context.Context, g *Gateway, diagnostics io.Writer) error {
	listener, err := net.Listen("tcp", g.config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintf(diagnostics, "Fencepost gateway listening on %s\n", listener.Addr())
	server := &http.Server{Handler: g, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
