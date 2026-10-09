package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/approval"
	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

func TestGatewayECSigningKeys(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		x, y  []byte
		valid bool
	}{
		{"valid", point[1:33], point[33:], true},
		{"short", point[1:32], point[33:], false},
		{"off-curve", make([]byte, 32), make([]byte, 32), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "ec", "kty": "EC", "crv": "P-256", "alg": "ES256", "x": base64.RawURLEncoding.EncodeToString(test.x), "y": base64.RawURLEncoding.EncodeToString(test.y)}}})
			}))
			defer s.Close()
			a := &authenticator{config: AuthConfig{Issuer: "https://issuer.example"}, keysURL: s.URL, client: s.Client()}
			err := a.refresh(context.Background())
			if !test.valid {
				if err == nil {
					t.Fatal("invalid EC key accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": a.config.Issuer, "sub": "alice", "aud": "https://gateway.example/mcp/tools", "exp": time.Now().Add(time.Minute).Unix(), "client_id": "workflow"})
			token.Header["kid"] = "ec"
			raw, err := token.SignedString(private)
			if err != nil {
				t.Fatal(err)
			}
			identity, _, err := a.validate(context.Background(), raw, "https://gateway.example/mcp/tools")
			if err != nil || identity.User != "alice" {
				t.Fatal(identity, err)
			}
		})
	}
}

type testIssuer struct {
	*httptest.Server
	private             ed25519.PrivateKey
	mu                  sync.Mutex
	audience, challenge string
}

func fakeIssuer(t *testing.T) *testIssuer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	i := &testIssuer{private: private}
	i.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": i.URL, "jwks_uri": i.URL + "/jwks", "authorization_endpoint": i.URL + "/authorize", "token_endpoint": i.URL + "/token", "code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "key", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(public)}}})
		case "/token":
			_ = r.ParseForm()
			i.mu.Lock()
			aud, challenge := i.audience, i.challenge
			i.mu.Unlock()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("resource") != aud || r.Form.Get("grant_type") != "authorization_code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
				http.Error(w, "PKCE or resource mismatch", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": i.token("reviewer", aud, []string{"approvers"}, nil), "token_type": "Bearer"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(i.Close)
	return i
}

func (i *testIssuer) token(user, audience string, groups []string, change func(jwt.MapClaims)) string {
	c := jwt.MapClaims{"iss": i.URL, "sub": user, "aud": audience, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "client_id": "workflow", "groups": groups}
	if change != nil {
		change(c)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	token.Header["kid"] = "key"
	raw, _ := token.SignedString(i.private)
	return raw
}

func testGateway(t *testing.T, issuer *testIssuer, upstream string) (*Gateway, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	data := `version: 1
servers:
  remote:
    default: deny
    tools:
      - {name: echo, action: allow, groups: [engineering], clients: [agentworkflows]}
      - {name: write, action: ask, groups: [engineering]}
approval: {timeout: 5s}
audit: {record_arguments: true}
`
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FENCEPOST_GATEWAY_TEST_KEY", strings.Repeat("ci-test-", 6))
	s := httptest.NewUnstartedServer(nil)
	c := Config{PublicURL: "http://" + s.Listener.Addr().String(), Policy: policy.SourceConfig{Source: "policy.yaml"}, Servers: map[string]Upstream{"remote": {URL: upstream}}, Auth: AuthConfig{Issuer: issuer.URL, ClientNames: map[string]string{"workflow": "agentworkflows"}, BrowserClientID: "inbox", APIKeys: []APIKey{{Env: "FENCEPOST_GATEWAY_TEST_KEY", Identity: policy.Identity{User: "ci", Client: "agentworkflows", Groups: []string{"engineering"}}}}}, Approval: InboxConfig{Groups: []string{"approvers"}}}
	g, err := New(context.Background(), c, dir, io.Discard, io.Discard)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	s.Config.Handler = g
	s.Start()
	t.Cleanup(func() {
		g.cancel()
		s.Close()
		if err := g.Close(); err != nil {
			t.Error(err)
		}
	})
	return g, s, dir
}

func gatewayRequest(t *testing.T, client *http.Client, method, endpoint, token, body string) (int, http.Header, string) {
	t.Helper()
	r, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(data)
}

func TestGatewayOIDCAndIsolation(t *testing.T) {
	i := fakeIssuer(t)
	var calls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-User") != "" {
			t.Error("gateway credentials leaked upstream")
		}
		var message map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&message)
		w.Header().Set("Content-Type", "application/json")
		if string(message["method"]) == `"initialize"` {
			w.Header().Set("Mcp-Session-Id", "upstream-session")
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": map[string]any{"content": []any{}}})
	}))
	defer up.Close()
	g, s, dir := testGateway(t, i, up.URL)
	resource := s.URL + "/mcp/remote"
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	status, headers, _ := gatewayRequest(t, s.Client(), "POST", resource, "", call)
	if status != 401 || !strings.Contains(headers.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp/remote") {
		t.Fatal(status, headers)
	}
	status, _, body := gatewayRequest(t, s.Client(), "GET", s.URL+"/.well-known/oauth-protected-resource/mcp/remote", "", "")
	if status != 200 || !strings.Contains(body, resource) || !strings.Contains(body, i.URL) {
		t.Fatal(status, body)
	}
	for name, edit := range map[string]func(jwt.MapClaims){
		"audience":       func(c jwt.MapClaims) { c["aud"] = s.URL + "/mcp/other" },
		"expired":        func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"missing-expiry": func(c jwt.MapClaims) { delete(c, "exp") },
		"issuer":         func(c jwt.MapClaims) { c["iss"] = "https://evil.invalid" },
		"future":         func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			raw := i.token("alice", resource, []string{"engineering"}, edit)
			status, _, _ := gatewayRequest(t, s.Client(), "POST", resource, raw, call)
			if status != 401 {
				t.Fatal(status)
			}
		})
	}
	valid := i.token("alice", resource, []string{"engineering"}, nil)
	badParts := strings.Split(valid, ".")
	badParts[2] = strings.Repeat("A", len(badParts[2]))
	status, _, _ = gatewayRequest(t, s.Client(), "POST", resource, strings.Join(badParts, "."), call)
	if status != 401 || calls.Load() != 0 {
		t.Fatal("invalid token reached upstream", status, calls.Load())
	}
	status, _, body = gatewayRequest(t, s.Client(), "POST", resource, valid, call)
	if status != 200 || strings.Contains(body, `"error"`) || calls.Load() != 1 {
		t.Fatal(status, body, calls.Load())
	}
	sales := i.token("bob", resource, []string{"sales"}, nil)
	_, _, body = gatewayRequest(t, s.Client(), "POST", resource, sales, call)
	if !strings.Contains(body, "does not permit") || calls.Load() != 1 {
		t.Fatal(body, calls.Load())
	}
	_, _, body = gatewayRequest(t, s.Client(), "POST", resource, os.Getenv("FENCEPOST_GATEWAY_TEST_KEY"), call)
	if strings.Contains(body, `"error"`) || calls.Load() != 2 {
		t.Fatal(body)
	}
	status, headers, _ = gatewayRequest(t, s.Client(), "POST", resource, valid, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`)
	if status != 200 {
		t.Fatal(status)
	}
	r, _ := http.NewRequest("GET", resource, nil)
	r.Header.Set("Authorization", "Bearer "+sales)
	r.Header.Set("Mcp-Session-Id", headers.Get("Mcp-Session-Id"))
	resp, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("cross-user session accepted", resp.StatusCode)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("version: 1\nservers: {remote: {default: deny}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := g.policy.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, body = gatewayRequest(t, s.Client(), "POST", resource, valid, call)
	if !strings.Contains(body, "does not permit") {
		t.Fatal("policy refresh not enforced", body)
	}
}

func TestGatewayInboxBrowserFlow(t *testing.T) {
	i := fakeIssuer(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&m)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": map[string]any{"content": []any{}}})
	}))
	defer up.Close()
	g, s, dir := testGateway(t, i, up.URL)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	status, headers, _ := gatewayRequest(t, client, "GET", s.URL+"/login", "", "")
	if status != 303 {
		t.Fatal(status)
	}
	authURL, _ := url.Parse(headers.Get("Location"))
	q := authURL.Query()
	i.mu.Lock()
	i.audience, i.challenge = q.Get("resource"), q.Get("code_challenge")
	i.mu.Unlock()
	if q.Get("code_challenge_method") != "S256" || q.Get("resource") != s.URL+"/approvals" {
		t.Fatal(q)
	}
	callback := s.URL + "/callback?" + url.Values{"state": {q.Get("state")}, "code": {"ok"}, "iss": {i.URL}}.Encode()
	status, _, _ = gatewayRequest(t, client, "GET", callback, "", "")
	if status != 303 {
		t.Fatal("sign-in failed", status)
	}
	status, _, _ = gatewayRequest(t, client, "GET", callback, "", "")
	if status != 400 {
		t.Fatal("callback replay accepted")
	}
	resource := s.URL + "/mcp/remote"
	requester := i.token("alice", resource, []string{"engineering"}, nil)
	done := make(chan string, 1)
	go func() {
		r, _ := http.NewRequest("POST", resource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"text":"<script>alert(1)</script>"}}}`))
		r.Header.Set("Authorization", "Bearer "+requester)
		resp, err := s.Client().Do(r)
		if err != nil {
			done <- err.Error()
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		done <- string(data)
	}()
	var pending []item
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, _, body := gatewayRequest(t, client, "GET", s.URL+"/approvals/pending", "", "")
		if status != 200 {
			t.Fatal(status, body)
		}
		_ = json.Unmarshal([]byte(body), &pending)
		if len(pending) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatal("missing pending request")
	}
	status, _, body := gatewayRequest(t, client, "GET", s.URL+"/approvals", "", "")
	if status != 200 || strings.Contains(body, "<script>") || !strings.Contains(body, "alice") {
		t.Fatal(status, body)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(body)
	if len(csrf) != 2 {
		t.Fatal("missing CSRF token")
	}
	form := url.Values{"id": {pending[0].ID}, "decision": {"allow"}, "reason": {"reviewed by team"}, "csrf": {csrf[1]}}
	r, _ := http.NewRequest("POST", s.URL+"/approvals/decision", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", s.URL)
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatal(resp.StatusCode)
	}
	select {
	case result := <-done:
		if strings.Contains(result, `"error"`) {
			t.Fatal(result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approval did not complete")
	}
	var events []audit.Event
	_, err = audit.Verify(filepath.Join(dir, "fencepost-audit.jsonl"), func(e audit.Event) {
		if e.Kind == "approval" {
			events = append(events, e)
		}
	})
	if err != nil || len(events) != 1 || events[0].Approver != "reviewer" || events[0].Reason != "reviewed by team" {
		t.Fatal(err, events)
	}
	unprivileged := i.token("alice", s.URL+"/approvals", []string{"engineering"}, nil)
	status, _, _ = gatewayRequest(t, client, "GET", s.URL+"/approvals", unprivileged, "")
	if status != 403 {
		t.Fatal("non-approver read inbox", status)
	}
	_, _, body = gatewayRequest(t, client, "GET", s.URL+"/approvals", "", "")
	if !strings.Contains(body, "reviewer") || !strings.Contains(body, "reviewed by team") {
		t.Fatal(body)
	}
	var diff bytes.Buffer
	p, err := policy.Parse([]byte("version: 1\nservers: {remote: {default: deny}}\n"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := audit.PolicyDiff(g.policy.Current().Audit.Path, p, &diff); err != nil || n != 1 || !strings.Contains(diff.String(), `"before":"ask"`) {
		t.Fatal(n, err, diff.String())
	}
}

func TestInboxWebhookAndTimeout(t *testing.T) {
	secret := strings.Repeat("test-secret-", 4)
	t.Setenv("FENCEPOST_INBOX_WEBHOOK_TEST", secret)
	seen := make(chan bool, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		seen <- r.Header.Get("X-Fencepost-Signature") == approval.Signature([]byte(secret), data) && bytes.Contains(data, []byte("approval_url"))
		w.WriteHeader(204)
	}))
	defer hook.Close()
	in := newInbox(InboxConfig{WebhookURL: hook.URL, HMACSecretEnv: "FENCEPOST_INBOX_WEBHOOK_TEST"}, "https://gateway.example", nil)
	answer := in.ask(context.Background(), policy.Approval{Timeout: "200ms"}, approval.Request{User: "alice", Server: "s", Tool: "write", Arguments: json.RawMessage("{}")})
	if answer != "deny" {
		t.Fatal(answer)
	}
	select {
	case valid := <-seen:
		if !valid {
			t.Fatal("unsigned webhook")
		}
	default:
		t.Fatal("webhook missing")
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.items) != 0 || len(in.history) != 1 || in.history[0].Decision != "expired" {
		t.Fatal(fmt.Sprint(in.history))
	}
}
