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

## 0.1.0 hardening run (2026-10-09)

The full local release gate is not green on this runner. Lint reported zero issues. All unit packages passed one race run, but subsequent runs hit existing HTTP negotiation/approval deadlines; the final serialized run hung in `TestPendingApprovalAndSessionGrant` and reached the 10-minute test timeout. Its pipe read at `internal/proxy/engine_test.go:344` remained blocked. That existing test was left unchanged. The documented README walkthrough passed its own e2e test in 4.07 seconds after build setup. The complete `make e2e` rerun subsequently passed: CLI/fixtures 322.862 seconds, report/schema 19.883 seconds, and policy/schema 8.725 seconds, with the race detector enabled. The final checks used Go 1.27.2, `GOFLAGS="-buildvcs=false -p=1"`, and `GOMAXPROCS=4` to work around the unwritable module cache and limit host contention. `make build` passed for all six targets. `make release` produced six stamped binaries and verified SHA256SUMS, then failed because Docker was unavailable. The Windows amd64 binary reported the expected version/commit/date; the Docker image and other platform runtimes were not tested.

Both fuzz targets passed 60-second runs with four workers: `FuzzFraming` executed 662,092 cases and `FuzzMatcher` executed 2,332,069. No failures or regression corpus entries were produced. Deterministic property tests cover policy ordering, default/unknown-server decisions, wildcard constraints, audit appends/reopens, and detection of edits, deletion, reordering, duplication, and truncation.

The `soak` build tag enables `TestSoak10Minutes`. Four workers send fresh tool names through four loopback HTTP proxy instances sharing one synchronous audit log. They alternate JSON and SSE responses with keepalives, targeting one call per worker per 10 ms. Calls pass through a rate-limited wildcard rule and output scanning. A 60-second sweep removes expired rate buckets; rejected definitions no longer accumulate in the persistent trust map.

```sh
go test -race -tags=soak ./internal/proxy -run TestSoak10Minutes -count=1 -timeout=15m -v
```

| Measurement | Result |
| --- | --- |
| Synthetic traffic | 600 seconds; 92,520 successful calls (154.2/second) |
| Audit records verified | 185,040 |
| Goroutines before / steady load / after cleanup | 2 / 38–39 / 2 |
| Retained heap at minute 2 / minute 10 | 10,596,992 / 5,216,912 bytes (10.11 / 4.98 MiB) |
| Largest sampled retained heap | 11,235,608 bytes (10.72 MiB) |
| RSS near minute 1 / minute 2 | 298.85 / 294.92 MiB |
| RSS near minute 5 / end of traffic | 312.23 / 363.01 MiB |
| Largest sampled RSS, including verification | 363.01 MiB |
| Last RSS sample before exit | 340.39 MiB |
| Total test, including verification/cleanup | 685.42 seconds |

RSS is the Windows working set (`Get-Process` / `WorkingSet64`), sampled every five seconds. The nearest end-of-traffic sample was at 601.0 seconds, and the last sample at 684.3 seconds. RSS includes the race detector, runtime, synthetic upstream/clients, and four listeners. Heap was sampled after GC each minute. RSS rose about 68 MiB after warmup while retained heap fell; runtime/race allocations need not return immediately to the OS. No goroutines or pending calls remained, and the audit chain verified. The audit file intentionally grows on disk.

This checks ten minutes of this workload, not an infinite-duration memory bound. Approvals, legacy-session churn, failures, hostile maximum-size frames, subprocess lifetimes, and OS isolation were not soaked. Checks allow at most 32 MiB additional retained heap and eight goroutines above the two-minute warmup. Other local validation processes ran concurrently, so throughput is not a production capacity measurement. Docker and non-Windows execution require separate hosts.

### Current latency rerun

The same 10,000-call benchmark was rerun three times on 2026-10-09 without `-race`, while other local validation work was active:

| Call path | Mean per call, runs 1 / 2 / 3 | p99, runs 1 / 2 / 3 | Allocations |
| --- | --- | --- | --- |
| Policy + output | 525.566 / 704.540 / 633.535 µs | 5.4413 / 12.6528 / 8.3384 ms | 210 per call |
| Policy + output + audit | 881.096 / 674.551 / 1071.831 µs | 13.5077 / 8.7951 / 14.7667 ms | 302–303 per call |

The earlier sub-1-ms p99 was **not reproduced** in this run. Host activity was substantial, so these measurements do not isolate a code regression, but the current result does not meet that earlier latency target. An idle-runner measurement remains necessary before claiming that target for 0.1.0.
