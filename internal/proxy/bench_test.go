package proxy

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/mcp"
	"github.com/RamazanKara/fencepost/internal/policy"
)

func BenchmarkSmallCall(b *testing.B) {
	for _, logging := range []bool{false, true} {
		name := "policy"
		if logging {
			name = "policy+audit"
		}
		b.Run(name, func(b *testing.B) {
			dir := b.TempDir()
			p, err := policy.Parse([]byte("version: 1\nservers: {s: {default: allow}}\n"), dir)
			if err != nil {
				b.Fatal(err)
			}
			var log *audit.Log
			if logging {
				log, err = audit.Open(p.Audit.Path, "")
				if err != nil {
					b.Fatal(err)
				}
				defer log.Close()
			}
			e, err := New(p, log, "s", filepath.Join(dir, "absent.lock"))
			if err != nil {
				b.Fatal(err)
			}
			request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`)
			response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`)
			samples := make([]int64, 0, min(b.N, 100000))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := benchmarkNow()
				m, err := mcp.Parse(request)
				if err != nil {
					b.Fatal(err)
				}
				r, err := e.Begin(context.Background(), m)
				if err != nil {
					b.Fatal(err)
				}
				denied, err := e.Check(r)
				if err != nil || denied != nil {
					b.Fatal(err, denied)
				}
				m, err = mcp.Parse(response)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := e.Server(m); err != nil {
					b.Fatal(err)
				}
				if len(samples) < cap(samples) {
					samples = append(samples, benchmarkNanoseconds(benchmarkNow()-start))
				}
			}
			b.StopTimer()
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "p99-ns")
		})
	}
}
