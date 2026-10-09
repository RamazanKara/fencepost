//go:build soak

package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/policy"
)

func TestSoak10Minutes(t *testing.T) {
	baseline := runtime.NumGoroutine()
	dir := t.TempDir()
	p, err := policy.Parse([]byte("version: 1\nservers: {s: {default: deny, tools: [{name: 'echo_*', action: allow, rate_limit: 100}]}}\n"), dir)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(p.Audit.Path, "")
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		result := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`
		if r.Header.Get("Accept") == "text/event-stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, ": heartbeat\n\ndata: %s\n\n", result)
		} else {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, result)
		}
	}))
	var proxies []*HTTP
	var servers []*httptest.Server
	for range 4 {
		h, err := NewHTTP(p, log, "s", filepath.Join(dir, "absent.lock"), upstream.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		proxies = append(proxies, h)
		servers = append(servers, httptest.NewServer(h))
	}
	client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var calls atomic.Int64
	var workers sync.WaitGroup
	for i, server := range servers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for n := 0; ; n++ {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				// Fresh names exercise wildcard rate buckets instead of a fixed tool set.
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_%d_%d","arguments":{}}}`, i, n)
				r, err := http.NewRequest("POST", server.URL, strings.NewReader(body))
				if err != nil {
					t.Error(err)
					cancel()
					return
				}
				if n%2 == 0 {
					r.Header.Set("Accept", "text/event-stream")
				}
				response, err := client.Do(r)
				if err != nil {
					t.Error(err)
					cancel()
					return
				}
				data, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != 200 || !strings.Contains(string(data), `"text":"hello"`) {
					t.Errorf("invalid response: %s, %v", data, err)
					cancel()
					return
				}
				calls.Add(1)
			}
		}()
	}
	t.Logf("pid=%d baseline_goroutines=%d", os.Getpid(), baseline)
	samples := time.NewTicker(time.Minute)
	defer samples.Stop()
	var warmHeap uint64
	var warmGoroutines int
	for minute := 1; minute <= 10; minute++ {
		select {
		case <-samples.C:
		case <-ctx.Done():
		}
		runtime.GC()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		goroutines := runtime.NumGoroutine()
		t.Logf("minute=%d calls=%d heap_bytes=%d goroutines=%d", minute, calls.Load(), mem.HeapAlloc, goroutines)
		if minute == 2 {
			warmHeap, warmGoroutines = mem.HeapAlloc, goroutines
		}
		if minute > 2 && (mem.HeapAlloc > warmHeap+(32<<20) || goroutines > warmGoroutines+8) {
			t.Errorf("growth after warmup: heap=%d goroutines=%d", mem.HeapAlloc, goroutines)
		}
	}
	cancel()
	workers.Wait()
	client.CloseIdleConnections()
	for i, server := range servers {
		server.Close()
		proxies[i].Close()
		if pending := len(proxies[i].base.pending); pending != 0 {
			t.Errorf("pending requests: %d", pending)
		}
	}
	upstream.Close()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if count, err := audit.Verify(p.Audit.Path, nil); err != nil || count != calls.Load()*2 {
		t.Fatalf("audit entries=%d calls=%d err=%v", count, calls.Load(), err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("final_calls=%d final_goroutines=%d", calls.Load(), runtime.NumGoroutine())
	if calls.Load() < 10000 {
		t.Error("insufficient traffic")
	}
	if runtime.NumGoroutine() > baseline {
		t.Error("goroutines remain after shutdown")
	}
}
