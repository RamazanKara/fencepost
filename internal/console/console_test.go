package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/fencepost/internal/audit"
)

func fixture(t *testing.T) *Handler {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	config := filepath.Join(dir, "mcp.json")
	for path, data := range map[string]string{policyPath: "version: 1\nservers: {filesystem: {default: deny}}\n", config: `{"mcpServers":{"filesystem":{"command":"must-not-start"}}}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return New("http://127.0.0.1:8787", strings.Repeat("a", 64), Options{Config: config, Policy: policyPath, Lock: filepath.Join(dir, "missing.lock")})
}

func request(h *Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, h.origin+path, strings.NewReader(body))
	r.Header.Set("Origin", h.origin)
	r.Header.Set("Content-Type", "application/json")
	if auth {
		r.AddCookie(&http.Cookie{Name: "fencepost_console", Value: h.token})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandlerAuthentication(t *testing.T) {
	h := fixture(t)
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/state", "/api/policy", "/api/schema", "/api/policy/save"} {
		if w := request(h, "GET", path, "", false); w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	w := request(h, "GET", "/?token="+h.token, "", false)
	if w.Code != 303 || len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].HttpOnly || w.Header().Get("Location") != "/" {
		t.Fatal(w)
	}
	for _, path := range []string{"/", "/app.js", "/api/state", "/api/policy", "/api/schema"} {
		if w := request(h, "GET", path, "", true); w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for _, header := range []string{"Host", "Origin", "Sec-Fetch-Site"} {
		r := httptest.NewRequest("GET", h.origin+"/api/state", nil)
		r.AddCookie(&http.Cookie{Name: "fencepost_console", Value: h.token})
		switch header {
		case "Host":
			r.Host = "attacker.example"
		case "Origin":
			r.Header.Set(header, "https://attacker.example")
		default:
			r.Header.Set(header, "cross-site")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(header, w.Code)
		}
	}
	if w := request(h, "GET", "/api/state?token="+h.token, "", false); w.Code != 401 {
		t.Fatal("query token authenticated API")
	}
}

func TestPolicyValidationReplaySaveAndConflict(t *testing.T) {
	h := fixture(t)
	log, err := audit.Open(filepath.Join(filepath.Dir(h.options.Policy), "fencepost-audit.jsonl"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Write(audit.Event{Kind: "policy", Method: "tools/call", Server: "filesystem", Tool: "read_file", Decision: "deny", Rule: "default", Session: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var original struct{ Text, Hash string }
	if err := json.Unmarshal(request(h, "GET", "/api/policy", "", true).Body.Bytes(), &original); err != nil {
		t.Fatal(err)
	}
	valid := "version: 1\nservers: {filesystem: {default: allow}}\n"
	body := func(text, hash string) string {
		b, _ := json.Marshal(map[string]string{"text": text, "hash": hash})
		return string(b)
	}
	if w := request(h, "POST", "/api/policy/validate", body("version: 1\nservers: {x: {default: allow, typo: true}}", original.Hash), true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w := request(h, "POST", "/api/policy/test", body(valid, original.Hash), true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `\"after\":\"allow\"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(h, "POST", "/api/policy/save", body(valid, original.Hash), true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(h, "POST", "/api/policy/save", body(original.Text, original.Hash), true); w.Code != 409 {
		t.Fatal(w.Code)
	}
	got, _ := os.ReadFile(h.options.Policy)
	if string(got) != valid {
		t.Fatal(string(got))
	}
	logPath := filepath.Join(filepath.Dir(h.options.Policy), "fencepost-audit.jsonl")
	if err := os.WriteFile(logPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "GET", "/api/state", "", true); w.Code == 200 {
		t.Fatal("unverified audit shown")
	}
}
