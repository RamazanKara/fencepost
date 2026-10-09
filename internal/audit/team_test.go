package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/policy"
)

func TestAuditExportAlias(t *testing.T) {
	for _, suffix := range []string{"", ".head", ".writing"} {
		t.Run("audit"+suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			l, err := Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			alias := strings.ToUpper(path + suffix)
			if runtime.GOOS != "windows" {
				alias = path + ".alias"
				if err := os.Link(path+suffix, alias); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			}
			if _, err := os.Stat(alias); err != nil {
				t.Fatal(err)
			}
			l, err = OpenConfigured(policy.Audit{Path: path, ExportFile: alias, MaxBytes: 1024, Backups: 1}, io.Discard)
			if err == nil {
				_ = l.Close()
				t.Fatal("export accepted an alias of the authoritative audit log")
			}
			if n, err := Verify(path, nil); err != nil || n != 0 {
				t.Fatal(n, err)
			}
		})
	}
}

func TestPolicyDiffAndQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []Event{
		{Time: "2026-10-09T08:00:00Z", Kind: "policy", User: "alice", Server: "s", Tool: "echo", Decision: "allow", Arguments: json.RawMessage(`{"text":"hello"}`), Replayable: true},
		{Time: "2026-10-09T09:00:00Z", Kind: "policy", User: "bob", Server: "s", Tool: "echo", Decision: "allow"},
	} {
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse([]byte("version: 1\nservers:\n  s:\n    default: deny\n    tools:\n      - name: echo\n        action: allow\n        arguments: [{path: $.text, enum: [goodbye]}]\n"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	n, err := PolicyDiff(path, p, &out)
	if err != nil || n != 2 || !strings.Contains(out.String(), `"after":"deny"`) || !strings.Contains(out.String(), `"after":"unknown"`) {
		t.Fatal(n, err, out.String())
	}
	out.Reset()
	if err := Query(path, Filter{User: "alice", Server: "s", Tool: "echo", Decision: "allow", From: time.Date(2026, 10, 9, 7, 0, 0, 0, time.UTC), Until: time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)}, &out); err != nil || bytes.Count(out.Bytes(), []byte("\n")) != 1 {
		t.Fatal(err, out.String())
	}
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(data, []byte("alice"), []byte("evil!"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Query(path, Filter{}, &out); err == nil || out.Len() != 0 {
		t.Fatal("unverified output returned")
	}
}

func TestAuditExports(t *testing.T) {
	logs := make(chan []byte, 16)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		logs <- data
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer collector.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	dir := t.TempDir()
	var stdout bytes.Buffer
	config := policy.Audit{Path: filepath.Join(dir, "audit"), Stdout: true, ExportFile: filepath.Join(dir, "rotating"), MaxBytes: 600, Backups: 3, OTLPLogsEndpoint: collector.URL, Syslog: "udp://" + udp.LocalAddr().String()}
	l, err := OpenConfigured(config, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := l.Write(Event{Kind: "decision", Decision: "deny", User: "alice", Server: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(stdout.Bytes(), []byte("\n")) != 3 {
		t.Fatal(stdout.String())
	}
	if _, err := os.Stat(config.ExportFile + ".1"); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(config.Path, nil); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	for range 3 {
		select {
		case data := <-logs:
			var decoded map[string]any
			if json.Unmarshal(data, &decoded) != nil || decoded["resourceLogs"] == nil || decoded["resourceSpans"] != nil {
				t.Fatal(string(data))
			}
		case <-time.After(time.Second):
			t.Fatal("missing OTLP log")
		}
	}
	_ = udp.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	n, _, err := udp.ReadFrom(buffer)
	if err != nil || !strings.HasPrefix(string(buffer[:n]), "<14>1 ") || !bytes.Contains(buffer[:n], []byte(`"hash"`)) {
		t.Fatal(err, string(buffer[:n]))
	}
}
