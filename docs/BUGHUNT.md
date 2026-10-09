# Bug hunt — 2026-10-09

Reviewed baseline `f28c4ee99c9225b1c1ef4af89fdbf11a98fb090d` on Windows 11. This pass fixes 12 reproduced bugs without adding dependencies, flags, or public interfaces.

## Systems reviewed

| System | Review coverage |
| --- | --- |
| CLI and local workflows | Argument/error handling, init/doctor/explain, wrapping and backups, process cleanup, exit statuses. |
| Client configuration | Discovery, JSONC parsing, project maps, environment resolution, redaction, preservation during wrap/unwrap. |
| Policy and policy sources | Strict YAML validation, aliases, numeric limits, path/host matching, signed sources, directory merge and reload. |
| MCP transports | Message framing, stdio subprocesses, HTTP/SSE streams, session headers, cancellation and resource cleanup. |
| Proxy engine | Request bookkeeping, approvals, budgets/rate limits, pin enforcement, output filtering, audit failures and concurrency. |
| Gateway | Configuration, JWT/authentication, sessions, policy reload, approval inbox and shutdown. |
| Audit | Hash-chain writes/verification, checkpoints/locking, export/rotation, OTLP, syslog, query/replay. |
| Scanner and pinning | Rule boundaries, Unicode/secrets, package commands, snapshots/drift, custom rule bundles and reports. |
| Package vetting | Metadata/registry selection, ownership baselines, sandbox launch and cleanup, error paths. |
| Local console | API authorization and save conflicts; browser startup, theme, editor, filters, responsive/locale behavior and accessibility markup. |
| Documentation and deployment | Documentation generation, schemas/examples/packs, build script, Docker and Helm configuration. |

No Android, Capacitor, WebGL, Canvas, or audio implementation is present; those native lifecycle/resource checks and an APK rebuild do not apply. Browser event listeners are installed once and the console has no recurring application timer.

## Fixed bugs

The regression for each finding failed before its production fix. Positive controls and the existing suite check preserved behavior.

### BH-01: HTTP request cancellation and SSE disconnect cleanup

Severity: **High**.

Root cause: HTTP upstream requests used the connection context instead of the engine request context; SSE completion did not always forget pending state.

Fix: Use the per-request context, clean pending entries on stream exit, and avoid a duplicate error after a valid response.

Test: TestHTTPCancellation (notification, disconnect), existing HTTP/SSE tests.

### BH-02: Stdio relay hangs during a blocked upstream write

Severity: **Medium**.

Root cause: The relay could not reach its cancellation select or deferred pipe cleanup while synchronously writing a non-tool request.

Fix: Close relay pipes from a context cancellation callback, guarded by sync.OnceFunc.

Test: TestRelayCancellationWhileUpstreamBlocked.

### BH-03: YAML aliases bypass null validation

Severity: **Medium**.

Root cause: Null checking traversed node contents but did not traverse alias targets, accepting null fields outside enum values.

Fix: Traverse aliases with context-aware cycle/revisit protection while retaining valid null enum values.

Test: TestNullAliases, TestEnumAliases, and existing YAML/fuzz seed tests.

### BH-04: Malformed client projects map panics

Severity: **Medium**.

Root cause: Project children were indexed in key/value pairs without checking that projects was a mapping.

Fix: Reject non-mapping projects at the parsing boundary.

Test: TestMalformedProjects (sequence, scalar).

### BH-05: Wrapping config corrupts unrelated JSON numbers

Severity: **Medium**.

Root cause: Unmarshal converted arbitrary JSON numbers to float64, rounding integers above 2^53 and rejecting large exponents.

Fix: Use json.Decoder.UseNumber during the existing wrapping rewrite.

Test: TestWrapPreservesNumbers (9007199254740993, 1e400).

### BH-06: Invalid audit payload corrupts the hash chain

Severity: **High**.

Root cause: Audit writing ignored json.Marshal errors and could append a null entry while updating the chain head.

Fix: Return serialization errors before modifying the log or head.

Test: TestInvalidArgumentsDoNotCorruptLog.

### BH-07: OTLP trace collector rejection is reported as success

Severity: **Medium**.

Root cause: The exporter discarded HTTP 200 response bodies, including partialSuccess rejection details.

Fix: Read a bounded response and report malformed/rejected/partial failure responses; release idle connections when the worker exits.

Test: TestOTLPRejectedSpans; existing TestOTLP.

### BH-08: Approval pages expose secrets used as object keys

Severity: **Medium**.

Root cause: Approval argument scrubbing redacted values but copied keys verbatim.

Fix: Redact keys with the existing secret detector while using the original key to scrub its value.

Test: TestApprovalPage extended with a credential-shaped key.

### BH-09: Scanner misses Windows uppercase launchers

Severity: **Medium**.

Root cause: Executable suffixes were removed before case folding; CMD /C was matched case-sensitively.

Fix: Normalize executable case before trimming suffixes and accept case-insensitive /c.

Test: TestPackagePins: NPX.CMD, UVX.EXE, CMD.EXE /C; pinned control.

### BH-10: Vetting associates custom-registry packages with public metadata

Severity: **Medium**.

Root cause: Launch parsing returned as soon as --package/--from selected a package, before later registry options were inspected.

Fix: Continue parsing launcher options before choosing the public registry reference.

Test: TestLaunchReferenceCustomRegistry; default-registry and application-argument controls.

### BH-11: Audit export can alias and corrupt the authoritative log

Severity: **High**.

Root cause: String path checks did not detect aliases of the authoritative log, checkpoint, or writer-lock file. An export could append to or rotate those files.

Fix: Compare the opened export file against all three audit file identities before starting the exporter and reject any collision.

Test: TestAuditExportAlias: log, .head and .writing aliases (case aliases on Windows; hard links on other systems).

### BH-12: Console fails to initialize when browser storage is disabled

Severity: **Medium**.

Root cause: An uncaught localStorage access at startup aborted initialization and event listener registration.

Fix: Make theme persistence optional while retaining system-theme fallback and the theme toggle.

Test: scripts/ui-test.mjs restricted-storage browser regression plus the existing UI matrix.

## Verification

- `go test -race -timeout 180s ./...`: passed, exit 0, including all new Go regressions.
- `git diff --check`: passed.
- `go vet ./...`: passed.
- `go test -v -race -tags=e2e ./cmd/fencepost`: passed, including the README quickstart (228.039 seconds with fixture build setup). The `internal/report` and `internal/policy` integration packages also passed with `-race -tags=e2e`, including Python/jsonschema validation.
- `go test -v -tags=e2e ./deploy/helm`: all three Helm template cases passed.
- `go test -v ./internal/policy -run TestPaths/symlink`: passed on Windows; the symlink check was not skipped.
- `go run scripts/ui-fixture.go` and `npm run test:ui`: passed using installed Edge, including the blocked-storage regression and 56 screenshots at 1280/360/393 CSS pixels, light/dark themes, and EN/DE browser language settings. Representative desktop and mobile screenshots were visually inspected. Edge's date formatter resolved to `de-DE` in both language contexts; this run does not establish `en-US` date formatting.
- `go run scripts/build.go`: passed for Linux, macOS and Windows on amd64 and arm64 (six binaries).
- `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run` with `GOTOOLCHAIN=go1.27.2`: passed, zero issues.

The first run also exposed environment issues. The sandbox denied some path-resolution operations under the user's default temporary directory. Setting `TEMP` and `TMP` to a writable workspace test directory resolved those failures without changing path enforcement. Go's module/build caches were redirected to writable temporary directories. The checkout converted generated `docs/rules.md` to CRLF; `go generate ./internal/scan` restored the expected LF content without a tracked content change. Existing Python/jsonschema and Helm installations are used for schema and template checks.

The first CLI integration attempt used an extra 180-second timeout and was stopped during the 11 fixture-binary builds. The rerun with the repository's normal timeout passed. The standalone linter used `GOTOOLCHAIN=go1.27.2`; automatic selection initially chose Go 1.26.9. Its first run was blocked by sandbox path resolution of the temporary checkout's working directory. The same patch passed lint in a disposable checkout under the writable workspace.

## Device-only suspicions and limits

- Windows descendant-process cleanup needs a dedicated launcher/process-tree reproduction. `internal/mcp/process_windows.go` kills the direct process, so descendants started by a launcher may survive cancellation. This was not reproduced or changed in this pass.
- Physical mobile browser keyboard behavior, rotation, screen-reader operation, suspension/resumption, browser back navigation and process death were not exercised. Responsive desktop-browser checks do not establish those outcomes. There is no native Android application to test or rebuild.
- Cross-compilation does not execute Linux/macOS process, sandbox, or filesystem behavior. The hard-link branch of the new audit alias regression needs execution on those systems.
- Scanner rules remain heuristic; this review is not a claim that every malicious definition or launch syntax is detected.

## Delivery and write restrictions

Direct edits to `internal/proxy/http_test.go` in the original worktree were denied. Cache creation under the original `.cache` directory was also denied. Work therefore continued in a local temporary checkout of the same baseline. The requested fallback is a `git diff` patch containing these fixes, regression tests, and this report. No commits, pushes, PRs, or `gh` commands were made.
