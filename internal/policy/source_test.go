package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryMergeAndIdentity(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"10-base.yaml": "version: 1\nservers:\n  s:\n    default: deny\n    tools:\n      - {name: '*', action: deny}\noutput:\n  max_bytes: 2048\n",
		"20-team.yml":  "servers:\n  s:\n    tools:\n      - {name: echo, action: allow, users: [alice], groups: [engineering], clients: [workflow]}\noutput:\n  injection: block\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Output.MaxBytes != 2048 || p.Output.Injection != "block" || len(p.Servers["s"].Tools) != 1 {
		t.Fatalf("%+v", p)
	}
	for _, test := range []struct {
		id   Identity
		want string
	}{
		{Identity{User: "alice", Groups: []string{"engineering"}, Client: "workflow"}, "allow"},
		{Identity{User: "bob", Groups: []string{"engineering"}, Client: "workflow"}, "deny"},
		{Identity{User: "alice", Groups: []string{"sales"}, Client: "workflow"}, "deny"},
		{Identity{User: "alice", Groups: []string{"engineering"}, Client: "spoof"}, "deny"},
		{Identity{}, "deny"},
	} {
		action, _, _, _ := p.MatchIdentity("s", "echo", nil, test.id)
		if action != test.want {
			t.Errorf("%+v: %s", test.id, action)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "30-invalid.yaml"), []byte("servers:\n  s:\n    unexpected: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestSignedPolicyFetch(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("version: 1\nservers: {s: {default: deny}}\n")
	etag, mode := "\"one\"", "valid"
	conditional := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conditional = r.Header.Get("If-None-Match")
		if mode == "unchanged" {
			w.WriteHeader(304)
			return
		}
		if mode == "redirect" {
			http.Redirect(w, r, "https://example.invalid", http.StatusFound)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Fencepost-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(private, data)))
		if mode == "tampered" {
			_, _ = w.Write([]byte(strings.ReplaceAll(string(data), "deny", "allow")))
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := &Source{config: SourceConfig{Source: server.URL}, base: t.TempDir(), key: public, client: client}
	ctx := context.Background()
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	first := s.Current()
	mode = "unchanged"
	if err := s.Refresh(ctx); err != nil || conditional != etag || s.Current() != first {
		t.Fatal(err, conditional)
	}
	mode = "tampered"
	etag = "\"two\""
	if err := s.Refresh(ctx); err == nil || s.Current() != first || s.etag != "\"one\"" {
		t.Fatal("tampered policy replaced trusted state", err)
	}
	mode = "valid"
	data = []byte("version: 1\nservers: {s: {default: allow}}\n")
	if err := s.Refresh(ctx); err != nil || s.Current().Servers["s"].Default != "allow" {
		t.Fatal(err)
	}
	second := s.Current()
	if err := s.Refresh(ctx); err != nil || s.Current() != second {
		t.Fatal("unchanged body reset policy", err)
	}
	mode = "redirect"
	if err := s.Refresh(ctx); err == nil || s.Current() != second {
		t.Fatal("redirect accepted")
	}
	mode = "valid"
	data = []byte("version: 2\n")
	if err := s.Refresh(ctx); err == nil || s.Current() != second {
		t.Fatal("invalid signed policy accepted")
	}
	if _, err := LoadSource(ctx, SourceConfig{Source: "http://127.0.0.1/policy"}, t.TempDir()); err == nil {
		t.Fatal("unsigned HTTP policy accepted")
	}
}
