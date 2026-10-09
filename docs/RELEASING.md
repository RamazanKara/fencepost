# Local release: 0.1.0

GitHub Actions is unavailable for release publishing. The single CI workflow remains a convenience; local checks are the release gate.

1. Use Go 1.27.2, GNU Make, a C compiler for the race detector, Python with `jsonschema==4.26.0`, and Docker configured for Linux containers.
2. Run `make lint test e2e build`. Tests and e2e fixture binaries use `-race`; cross-built distribution binaries use `CGO_ENABLED=0`.
3. Run both fuzz targets for 60 seconds and the soak:
   ```sh
   go test ./internal/mcp -run '^$' -fuzz FuzzFraming -fuzztime=60s
   go test ./internal/policy -run '^$' -fuzz FuzzMatcher -fuzztime=60s
   go test -race -tags=soak ./internal/proxy -run TestSoak10Minutes -count=1 -timeout=15m -v
   ```
   Record heap, goroutines, process RSS, and limitations in [PERF.md](PERF.md). The soak prints its PID; on Windows sample `(Get-Process -Id PID).WorkingSet64` for RSS (working set).
4. Scan the working tree and all local history with Gitleaks, reviewing synthetic fixture matches:
   ```sh
   gitleaks dir . --redact
   gitleaks git . --log-opts='--all --full-history' --redact
   ```
   Also inspect author metadata, private usernames, home directories, and machine paths, which secret detectors do not cover. Do not paste suspected live credentials into reports. These scans cover local objects/refs; fetch other refs separately if needed.
5. Check the dated changelog, `internal/version/version.go`, README, Dockerfile default, and release examples all say 0.1.0. Retain Apache-2.0 and upstream notices.
6. Commit the reviewed changes yourself, with no unrelated files in `dist/`, then run:
   ```sh
   make release
   ```
   It cross-builds Linux, macOS, and Windows for amd64 and arm64 into `dist/`, writes `SHA256SUMS`, and builds local image `fencepost:0.1.0`. Version, full commit (with `-dirty` for a dirty tree), and UTC build date are embedded via ldflags. `fencepost version` displays them. The container uses the matching Linux binary for Docker's native architecture. Unexpected old release files in `dist/` are rejected; move them aside before rebuilding. A Docker failure leaves the six binaries and checksums available but fails the release target.
7. Verify checksums with `cd dist` then `sha256sum -c SHA256SUMS`, or PowerShell `Get-FileHash`. Smoke-test the native binary and `docker run --rm fencepost:0.1.0 version`. Cross-compilation alone does not verify execution on all six platforms.

Create and push the intended `v0.1.0` tag yourself after review. With that tag available remotely, publish explicitly:

```sh
gh release create v0.1.0 dist/* --notes-file CHANGELOG.md --verify-tag
```

PowerShell does not expand wildcards for native applications; pass `(Get-ChildItem dist -File).FullName` in place of `dist/*`. Nothing in `make release` tags, commits, pushes, uploads, or calls `gh`.

The distroless image runs as a non-root user and includes no shell or MCP server executables. Mount a reviewed policy and a writable `/data` directory for audit/approval state. Executables for stdio servers must be supplied separately; the image also supports offline scans and remote-server configurations. The HTTP listener remains loopback-only inside the container.

On a runner with an unwritable Go module cache, automatic VCS metadata discovery can repeatedly fail and delay fixture builds. Prefer a writable cache. For local checks, `GOFLAGS=-buildvcs=false` disables that optional Go build-info lookup. Fencepost's version, commit, and date are still explicitly embedded by the release script. On this Windows laptop the serialized rerun used `$env:GOFLAGS='-buildvcs=false -p=1'` and `$env:GOMAXPROCS='4'` to limit concurrent builds and tests. The first default e2e attempt timed out while building fixtures, before CLI tests ran; another parallel unit run hit existing HTTP negotiation and approval deadlines. The serialized unit run still timed out in `TestPendingApprovalAndSessionGrant`; the complete e2e rerun passed. See [PERF.md](PERF.md) for results and remaining release blockers, and keep these environment limits with the test results when comparing runs.
