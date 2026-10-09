package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInvalidArgumentsDoNotCorruptLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Write(Event{Kind: "policy", Arguments: json.RawMessage(`{`)}); err == nil {
		t.Error("invalid arguments were accepted")
	}
	if err := l.Write(Event{Kind: "request"}); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(path, nil); err != nil || n != 1 {
		t.Fatalf("rejected event damaged the log: %d %v", n, err)
	}
}

func TestOTLPRejectedSpans(t *testing.T) {
	for _, body := range []string{`{"partialSuccess":{"rejectedSpans":"1"}}`, `{"partialSuccess":{"errorMessage":"rejected"}}`, `{`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer s.Close()
			l, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"), s.URL)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Write(Event{Kind: "decision", Decision: "allow"}); err != nil {
				_ = l.Close()
				t.Fatal(err)
			}
			if err := l.Close(); err == nil {
				t.Error("collector rejection was reported as successful export")
			}
		})
	}
}

func TestChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, e := range []Event{{Kind: "request", Method: "tools/call", Server: "s", Tool: "t"}, {Kind: "decision", Decision: "deny"}, {Kind: "redaction", Redactions: map[string]int{"github-token": 2}}} {
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := Verify(path, nil); err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	s, err := Statistics(path)
	if err != nil || s.Calls["s/t"] != 1 || s.Denies != 1 || s.Redactions != 2 {
		t.Fatalf("%+v %v", s, err)
	}
	var tail bytes.Buffer
	if err := Tail(path, 1, &tail); err != nil || !strings.Contains(tail.String(), "redaction") {
		t.Fatal(err, tail.String())
	}
	original, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(original, []byte{'\n'})
	for name, changed := range map[string][]byte{
		"edit":    bytes.ReplaceAll(original, []byte(`"deny"`), []byte(`"allow"`)),
		"middle":  append(bytes.Clone(lines[0]), lines[2]...),
		"tail":    bytes.Join(lines[:2], nil),
		"reorder": bytes.Join([][]byte{lines[1], lines[0], lines[2]}, nil),
		"empty":   nil,
		"spacing": bytes.Replace(original, []byte(`{"entry"`), []byte(`{ "entry"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(path, nil); err == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
}

func TestConcurrentWritersAndSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := a
			if i%2 == 0 {
				l = b
			}
			if err := l.Write(Event{Kind: "request", Tool: "ghp_abcdefghijklmnopqrstuvwxyz123456"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, err := Verify(path, nil); err != nil || n != 20 {
		t.Fatal(n, err)
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("abcdefghijklmnopqrstuvwxyz")) {
		t.Fatal("secret logged")
	}
}

func TestOTLP(t *testing.T) {
	var mu sync.Mutex
	count := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid OTLP request")
		}
		if _, ok := body["resourceSpans"].([]any); !ok {
			t.Error("missing resourceSpans")
		}
		mu.Lock()
		count++
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer s.Close()
	l, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"), s.URL+"/v1/traces")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Event{Kind: "decision", Decision: "allow", Tool: "echo"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatal(count)
	}
}
