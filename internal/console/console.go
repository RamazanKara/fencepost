package console

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/approval"
	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/pin"
	"github.com/RamazanKara/fencepost/internal/policy"
	"github.com/RamazanKara/fencepost/internal/scan"
	"github.com/RamazanKara/fencepost/schema"
)

//go:embed web/*
var assets embed.FS

type Options struct{ Config, Policy, Lock string }

type Handler struct {
	origin, token string
	options       Options
	mu            sync.Mutex
}

func New(origin, token string, options Options) *Handler {
	return &Handler{origin: origin, token: token, options: options}
}

func Serve(ctx context.Context, address string, options Options, out io.Writer) error {
	listener, err := approval.Listen(address)
	if err != nil {
		return err
	}
	defer listener.Close()
	info, err := os.Lstat(options.Policy)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("console policy must be a regular local file")
	}
	if _, err := policy.Read(options.Policy); err != nil {
		return err
	}
	origin, token := "http://"+listener.Addr().String(), approval.Token()
	fmt.Fprintf(out, "%s/?token=%s\n", origin, token)
	server := &http.Server{Handler: New(origin, token, options), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
	if "http://"+r.Host != h.origin || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != h.origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "Forbidden origin", http.StatusForbidden)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/" && r.URL.Query().Has("token") {
		if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(h.token)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "fencepost_console", Value: h.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	cookie, err := r.Cookie("fencepost_console")
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(h.token)) != 1 {
		http.Error(w, "Open the private URL printed by fencepost ui.", http.StatusUnauthorized)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if err := h.api(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/favicon.ico" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	switch name {
	case "index.html", "app.js", "style.css":
	default:
		http.NotFound(w, r)
		return
	}
	web, _ := fs.Sub(assets, "web")
	http.FileServer(http.FS(web)).ServeHTTP(w, r)
}

func jsonResponse(w http.ResponseWriter, value any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(value)
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (h *Handler) api(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		switch r.URL.Path {
		case "/api/state":
			state, err := h.state()
			if err != nil {
				return err
			}
			return jsonResponse(w, state)
		case "/api/policy":
			data, err := os.ReadFile(h.options.Policy)
			if err != nil {
				return errors.New("cannot read policy file")
			}
			return jsonResponse(w, map[string]string{"text": string(data), "hash": hash(data)})
		case "/api/schema":
			w.Header().Set("Content-Type", "application/schema+json")
			_, err := w.Write(schema.Policy)
			return err
		default:
			http.NotFound(w, r)
			return nil
		}
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil
	}
	if r.URL.Path != "/api/policy/validate" && r.URL.Path != "/api/policy/test" && r.URL.Path != "/api/policy/save" {
		http.NotFound(w, r)
		return nil
	}
	if r.Header.Get("Origin") != h.origin {
		http.Error(w, "Same-origin policy request required", http.StatusForbidden)
		return nil
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Expected application/json", http.StatusUnsupportedMediaType)
		return nil
	}
	var input struct {
		Text string `json:"text"`
		Hash string `json:"hash"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		return errors.New("invalid policy request")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("expected one policy request")
	}
	base, err := filepath.Abs(filepath.Dir(h.options.Policy))
	if err != nil {
		return err
	}
	p, err := policy.Parse([]byte(input.Text), base)
	if err != nil {
		return err
	}
	switch r.URL.Path {
	case "/api/policy/validate":
		return jsonResponse(w, map[string]string{"message": "Policy is valid. Schema fields and runtime constraints passed."})
	case "/api/policy/test":
		active, err := policy.Read(h.options.Policy)
		if err != nil {
			return err
		}
		events, err := recent(active.Audit.Path)
		if err != nil {
			return err
		}
		var output strings.Builder
		count, err := audit.PolicyDiffEvents(events, p, &output)
		if err != nil {
			return err
		}
		return jsonResponse(w, map[string]any{"message": fmt.Sprintf("%d changed or unknown decisions across the latest %d audit events. Live counters, pins and approvals are not simulated.", count, len(events)), "results": output.String()})
	case "/api/policy/save":
		h.mu.Lock()
		defer h.mu.Unlock()
		info, err := os.Lstat(h.options.Policy)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("policy must be a regular local file")
		}
		before, err := os.ReadFile(h.options.Policy)
		if err != nil {
			return err
		}
		if input.Hash != hash(before) {
			http.Error(w, "Policy changed on disk. Reload before saving.", http.StatusConflict)
			return nil
		}
		f, err := os.CreateTemp(base, ".policy-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if err = f.Chmod(0600); err == nil {
			_, err = f.WriteString(input.Text)
		}
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		if err := os.Rename(f.Name(), h.options.Policy); err != nil {
			return err
		}
		return jsonResponse(w, map[string]string{"message": "Policy saved. Restart standalone proxies to apply it; gateways reload on their next poll.", "hash": hash([]byte(input.Text))})
	}
	return nil
}

func recent(path string) ([]audit.Event, error) {
	events := []audit.Event{}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if _, headErr := os.Stat(path + ".head"); errors.Is(headErr, os.ErrNotExist) {
			return events, nil
		}
	}
	_, err := audit.Verify(path, func(e audit.Event) {
		if len(events) == 200 {
			copy(events, events[1:])
			events = events[:199]
		}
		events = append(events, e)
	})
	if err != nil {
		return nil, errors.New("audit verification failed; no unverified calls are displayed")
	}
	return events, nil
}

type serverView struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Wrapped   bool   `json:"wrapped"`
	Pin       string `json:"pin"`
	Tools     int    `json:"tools"`
}
type state struct {
	Servers []serverView  `json:"servers"`
	Events  []audit.Event `json:"events"`
}

func (h *Handler) state() (state, error) {
	result := state{Servers: []serverView{}}
	p, err := policy.Read(h.options.Policy)
	if err != nil {
		return result, err
	}
	result.Events, err = recent(p.Audit.Path)
	if err != nil {
		return result, err
	}
	paths, err := clientconfig.DefaultPaths()
	if err != nil {
		return result, err
	}
	servers, err := clientconfig.Discover(paths, h.options.Config)
	if err != nil {
		return result, err
	}
	for _, s := range servers {
		row := serverView{Name: s.Name, Transport: s.Transport, Pin: "No baseline"}
		lockPath := h.options.Lock
		base := strings.TrimSuffix(strings.ToLower(filepath.Base(s.Command)), ".exe")
		if strings.HasPrefix(base, "fencepost") && len(s.Args) > 0 && s.Args[0] == "proxy" {
			row.Wrapped = true
			var original string
			for i := 1; i+1 < len(s.Args); i++ {
				switch s.Args[i] {
				case "--config":
					original = s.Args[i+1]
				case "--lock":
					lockPath = s.Args[i+1]
				}
			}
			if original != "" {
				upstreams, err := clientconfig.Discover(paths, original)
				if err != nil {
					return result, errors.New("cannot read wrapped server backup")
				}
				for _, upstream := range upstreams {
					if upstream.Name == s.Name {
						s = upstream
						row.Transport = s.Transport
						break
					}
				}
			}
		}
		lock, err := pin.Read(lockPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, errors.New("cannot read pin baseline")
		}
		if pinned, ok := lock.Servers[s.Name]; ok {
			row.Pin, row.Tools = "Pinned; not checked live", len(pinned.Tools)
			current, err := pin.Snapshot([]scan.Inventory{{Server: s}})
			if err != nil {
				return result, err
			}
			if current.Servers[s.Name].LaunchHash != pinned.LaunchHash {
				row.Pin = "Launch drift"
			}
		}
		for _, e := range result.Events {
			if e.Server == s.Name && e.Rule == "pin" && (e.Decision == "hide" || e.Decision == "deny") {
				row.Pin = "Drift recorded"
			}
		}
		result.Servers = append(result.Servers, row)
	}
	return result, nil
}
