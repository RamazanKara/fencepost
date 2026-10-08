# Proxy performance

Measured on 2026-10-08 on the Windows 11 runner, AMD Ryzen 7 8845HS, windows/amd64, Go 1.27.2, default `GOMAXPROCS=16`. Three runs of 10,000 calls each:

```sh
go test ./internal/proxy -run '^$' -bench BenchmarkSmallCall -benchtime=10000x -count=3
```

| Call path | Mean per call, runs 1 / 2 / 3 | p99, runs 1 / 2 / 3 | Allocations |
| --- | --- | --- | --- |
| Policy + output, without audit | 54.010 / 55.268 / 56.243 µs | 176.5 / 179.9 / 208.0 µs | 210 per call |
| Policy + output + synchronous audit | 150.298 / 154.835 / 153.859 µs | 490.1 / 462.3 / 465.2 µs | 302–303 per call |

The largest measured p99 with audit enabled was **0.4901 ms**, below the 1 ms small-message target. These results include framing JSON parsing, request normalization, allow-policy matching, pin-file existence checking, result scanning/rewriting, two audit appends, and checkpoint updates. They exclude upstream execution, network/stdio transport scheduling, filesystem/IDN argument rules, human/webhook approval, and shutdown fsync. The benchmark uses a 100-byte request and a 78-byte response with a short text result and no lockfile. The memory figures reported by the runs were approximately 10.1 KB/call without audit and 16.6 KB/call with audit.

`internal/proxy/bench_test.go` records individual samples and reports `p99-ns`, in addition to Go's usual mean and allocations. Windows samples use `QueryPerformanceCounter`; this Go toolchain's Windows `time.Now`/`nanotime` read the coarse shared interrupt clock, which quantized earlier samples to roughly 0.5–1.5 ms. Other platforms use Go's monotonic clock. Timer-call overhead remains included in the samples. The benchmark is run without `-race`; correctness tests and fixture binaries use `-race` separately.

Audit logging holds persistent file/checkpoint handles and serializes writers with native file locks. Each request and decision is written synchronously to the OS cache, and the checkpoint is updated before an allowed call is forwarded. This avoids creating/renaming a file on every event. The first implementation used checkpoint replacement per entry and measured about 33 ms p99 on this runner; it was replaced before these final measurements. Power-loss durability requires more than this latency measurement; files are synced on orderly shutdown and torn tails fail verification.

Each stdio frame or SSE event is limited to 16 MiB. The proxy transforms and flushes one event at a time, including keepalives and progress. It never buffers a whole SSE stream. Output rules need a complete JSON event to scan strings and preserve valid structured content; result caps replace oversized payloads with a small valid result. Large-message, saturated multi-process audit contention, remote-network, and production workload p99 were not measured. No universal latency guarantee is inferred from this laptop benchmark.
