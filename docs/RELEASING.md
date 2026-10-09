# Local release: 0.3.0

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
5. Check the dated changelog, `internal/version/version.go`, README, Dockerfile default, and release examples all say 0.3.0. Retain Apache-2.0 and upstream notices.
6. Commit the reviewed changes yourself, with no unrelated files in `dist/`, then run:
   ```sh
   make release
   ```
   It cross-builds Linux, macOS, and Windows for amd64 and arm64 into `dist/`, writes `SHA256SUMS`, and builds local image `fencepost:0.3.0`. Version, full commit (with `-dirty` for a dirty tree), and UTC build date are embedded via ldflags. `fencepost version` displays them. The image builds the same source for Docker's native architecture and embeds the release version. Unexpected old release files in `dist/` are rejected; move them aside before rebuilding. A Docker failure leaves the six binaries and checksums available but fails the release target.
7. Verify checksums with `cd dist` then `sha256sum -c SHA256SUMS`, or PowerShell `Get-FileHash`. Smoke-test the native binary and `docker run --rm fencepost:0.3.0 version`. Cross-compilation alone does not verify execution on all six platforms.

Create and push the intended `v0.3.0` tag yourself after review. With that tag available remotely, publish explicitly:

```sh
gh release create v0.3.0 dist/* --notes-file CHANGELOG.md --verify-tag
```

PowerShell does not expand wildcards for native applications; pass `(Get-ChildItem dist -File).FullName` in place of `dist/*`. Nothing in `make release` tags, commits, pushes, uploads, or calls `gh`.

The distroless image runs as a non-root user and includes no shell or MCP server executables. Mount a reviewed policy and a writable `/data` directory for audit/approval state. Executables for stdio servers must be supplied separately; the image also supports offline scans and remote-server configurations. Gateway mode may bind a private container interface; terminate HTTPS and restrict backend access as described in gateway.md.

On a runner with an unwritable Go module cache, automatic VCS metadata discovery can repeatedly fail and delay fixture builds. Prefer a writable cache. For local checks, `GOFLAGS=-buildvcs=false` disables that optional Go build-info lookup. Fencepost's version, commit, and date are still explicitly embedded by the release script. During v0.1.0 verification on this Windows laptop, the serialized rerun used `$env:GOFLAGS='-buildvcs=false -p=1'` and `$env:GOMAXPROCS='4'` to limit concurrent builds and tests. The first default e2e attempt timed out while building fixtures, before CLI tests ran; another parallel unit run hit existing HTTP negotiation and approval deadlines. The serialized unit run still timed out in `TestPendingApprovalAndSessionGrant`; the complete e2e rerun passed. See [PERF.md](PERF.md) for results and remaining release blockers, and keep these environment limits with the test results when comparing runs.


For a local GoReleaser build without publishing, install GoReleaser and run `goreleaser build --snapshot --clean`. The six binaries go under `dist/goreleaser`; the snapshot marks commit metadata accordingly. To produce local archives and checksums, run `goreleaser release --snapshot --clean --skip=publish`. Publishing is disabled in the repository configuration. `make image` independently builds `fencepost:0.3.0`; no registry is required except to pull the public builder/base images. Upload/tag/push only when separately authorized.

## Console and docs release gate

Run `npm ci` and `make ui-test` with Playwright Chromium or installed Edge on Windows. Review **every** PNG in `docs/screens/`, including both themes and desktop/phone states. The screenshots contain deterministic fixture records, not user audit data. Run `make lint test e2e build` again after code fixes. Node.js 22+ is also needed by vet fixture tests.

`make docs` generates `site/` locally from README, the changelog, contribution/security references and `docs/`, preserving tables, heading anchors, code blocks, relative links, screenshots and downloadable examples/schema/packs. Goldmark is a build dependency only; it is not linked into the firewall binary. Preview with a static HTTP server. `site/.nojekyll` allows direct branch publishing without Actions.

To publish, copy **the contents** of `site/` into a separate checkout on `gh-pages`, commit there and push that branch locally. Do not publish the working tree, audit files, `.ui-fixture`, or the rules signing private key. For a first deployment, initialize a fresh directory with `git init -b gh-pages`, copy the site contents, add this repository as origin, then commit/push. For subsequent deployments use the existing branch checkout and inspect its diff. No workflow or automatic deployment is needed.

After pushing, an authorized operator can enable branch-based Pages:

```sh
gh api --method POST repos/RamazanKara/fencepost/pages -f 'source[branch]=gh-pages' -f 'source[path]=/'
```

Use PATCH instead of POST when Pages already exists. Repository permissions/organization policy may prohibit enabling Pages. Check the actual published URL before reporting success; the expected project URL is `https://ramazankara.github.io/fencepost/`.

The Ed25519 public key and signed initial rules bundle are in `internal/rulebundle/`. Preserve the corresponding private key outside Git and upload only the signed `bundle.json` as `rules.json` when publishing an update feed. Do not advertise an update URL until its signature and download have been tested. See [the bundle format](rule-updates.md).

On a read-only runner, work in a writable copy, run the complete checks there and hand off a binary `git diff --no-index` patch including new files and screenshots. If `.git` is read-only, pull cannot update FETCH_HEAD. Never report a completed pull, commit, release, Pages enablement or push from such a run. Runner instructions prohibiting Git/`gh` writes take precedence over this operator procedure.
