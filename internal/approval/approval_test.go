package approval

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/policy"
)

func localChannel(t *testing.T) (*httptest.Server, policy.Approval, string) {
	t.Helper()
	c := New("", Token())
	s := httptest.NewUnstartedServer(c)
	c.origin = "http://" + s.Listener.Addr().String()
	s.Start()
	t.Cleanup(s.Close)
	path := filepath.Join(t.TempDir(), "approval.json")
	data, _ := json.Marshal(Address{s.URL, c.token})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return s, policy.Approval{Mode: "local", Timeout: "1s", LocalFile: path}, c.token
}

func TestApprovalPage(t *testing.T) {
	s, config, token := localChannel(t)
	for _, decision := range []string{"allow", "always", "deny"} {
		t.Run(decision, func(t *testing.T) {
			result := make(chan string, 1)
			go func() {
				result <- Ask(context.Background(), config, Request{Server: "<script>alert(1)</script>", Tool: "read", Arguments: json.RawMessage(`{"token":"ghp_abcdefghijklmnopqrstuvwxyz123456","password":"tiny","text":"Authorization: Bearer opaque","ghp_abcdefghijklmnopqrstuvwxyz123456":"value"}`)})
			}()
			var pending []Request
			deadline := time.Now().Add(time.Second)
			for len(pending) == 0 && time.Now().Before(deadline) {
				r, err := http.Get(s.URL + "/pending?token=" + token)
				if err != nil {
					t.Fatal(err)
				}
				err = json.NewDecoder(r.Body).Decode(&pending)
				_ = r.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if len(pending) == 0 {
					time.Sleep(time.Millisecond)
				}
			}
			if len(pending) != 1 {
				t.Fatal("approval not queued")
			}
			r, err := http.Get(s.URL + "/?token=" + token)
			if err != nil {
				t.Fatal(err)
			}
			page, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if strings.Contains(string(page), "<script>") || strings.Contains(string(page), "ghp_") || strings.Contains(string(page), "tiny") || strings.Contains(string(page), "opaque") || !strings.Contains(string(page), "Approve once") {
				t.Fatal(string(page))
			}
			response, err := http.PostForm(s.URL+"/decision?token="+token, url.Values{"id": {pending[0].ID}, "decision": {decision}})
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if got := <-result; got != decision {
				t.Fatal(got)
			}
		})
	}
	config.Timeout = "20ms"
	if answer := Ask(context.Background(), config, Request{Arguments: json.RawMessage(`{}`)}); answer != "deny" {
		t.Fatal(answer)
	}
	for _, tc := range []struct{ token, origin, host string }{{"bad", "", ""}, {token, "https://evil.test", ""}, {token, "", "evil.test"}} {
		r, _ := http.NewRequest("GET", s.URL+"/?token="+tc.token, nil)
		r.Header.Set("Origin", tc.origin)
		if tc.host != "" {
			r.Host = tc.host
		}
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal(response.StatusCode)
		}
	}
}

func TestWebhook(t *testing.T) {
	secret := strings.Repeat("s", 32)
	t.Setenv("FENCEPOST_TEST_HMAC", secret)
	for _, signed := range []bool{true, false} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if r.Header.Get("X-Fencepost-Signature") != Signature([]byte(secret), body) {
				t.Error("missing request signature")
			}
			var request Request
			_ = json.Unmarshal(body, &request)
			if request.ID == "" || time.Now().Unix()-request.Time > 5 {
				t.Error("missing replay metadata")
			}
			response := []byte(`{"decision":"allow"}`)
			if signed {
				w.Header().Set("X-Fencepost-Signature", Signature([]byte(secret), append([]byte(request.ID+"\n"), response...)))
			}
			_, _ = w.Write(response)
		}))
		got := Ask(context.Background(), policy.Approval{Mode: "webhook", Timeout: "1s", WebhookURL: s.URL, HMACSecretEnv: "FENCEPOST_TEST_HMAC"}, Request{Arguments: json.RawMessage(`{}`)})
		s.Close()
		if (got == "allow") != signed {
			t.Fatalf("signed=%t: %s", signed, got)
		}
	}
}

func TestLoopbackOnly(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "localhost:0", "[::]:0", "192.0.2.1:0"} {
		if l, err := Listen(address); err == nil {
			_ = l.Close()
			t.Fatal(address)
		}
	}
}
