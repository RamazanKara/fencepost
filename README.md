# Fencepost

Fencepost audits MCP servers and enforces tool-call policy between an AI agent and its servers. It checks descriptions and launch settings, pins trusted definitions, filters calls, redacts results, and records a hash-chained audit log. It runs as a single Go binary with no CGO dependency.

## 30-second quickstart

With Go 1.27.2, from this checkout:

```sh
CGO_ENABLED=0 go build -o bin/fencepost ./cmd/fencepost
./bin/fencepost scan
```

On PowerShell, set `$env:CGO_ENABLED='0'`, build to `bin/fencepost.exe`, and run `.\bin\fencepost.exe scan`.

`scan` discovers Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf configs in your home directory and current project. Online scans start configured commands, which may install packages, and enumerate server definitions. Use `fencepost scan --offline` to audit config without connecting. A clean environment limits inherited variables; it does not sandbox the server's filesystem or network access.

```sh
fencepost scan --config ./mcp.json --format json
fencepost scan --format sarif > fencepost.sarif
fencepost scan --fail-on high
fencepost pin --config ./mcp.json
fencepost verify --config ./mcp.json
fencepost pin --config ./mcp.json --update filesystem/read_file
```

Exit codes: **0** for success, **1** for findings at or above `--fail-on` (default `medium`) or lock drift, **2** for invalid input or an incomplete scan. JSON and SARIF include connection errors. A failed connection never counts as a clean scan.

`pin` writes `fencepost.lock` in the working directory and refuses to overwrite an existing baseline. `verify` compares launch specs and tool definitions, with unified description diffs. `pin --update server/tool` approves just that tool's change, addition, or removal. It does not approve launch changes or unrelated tool drift. Review and deliberately replace the baseline to approve launch or server changes. Keep the lockfile under version control when its descriptions are suitable for sharing; remove the root ignore entry to do so.

## Protect tool calls

Create `fencepost.yaml` next to your project. Match the server/tool names and argument names to your server. This example allows reads under `workspace`, asks before writes, and denies everything else:

```yaml
version: 1
session_budget: 100
servers:
  filesystem:
    default: deny
    tools:
      - name: read_file
        action: allow
        rate_limit: 60
        arguments:
          - path: $.path
            path_prefix: [./workspace]
      - name: write_file
        action: ask
        arguments:
          - path: $.path
            path_prefix: [./workspace]
output:
  redact_secrets: true
  max_bytes: 1048576
  injection: warn
```

```sh
fencepost policy check
fencepost pin --config ./mcp.json
fencepost wrap --config ./mcp.json           # review the diff
fencepost wrap --config ./mcp.json --write   # writes a .fencepost.bak backup
fencepost approve                          # open the private loopback URL it prints
```

Restart the MCP client after wrapping. The backup is the proxy's original-server configuration; keep it available and private. `fencepost unwrap --config ./mcp.json --write` restores the original bytes. Without `--write`, both commands only show a diff. JSONC comments are preserved in the backup; rewritten configs use formatted JSON.

Manual proxy commands are also available:

```sh
fencepost proxy --server filesystem -- /path/to/mcp-server --server-option
fencepost proxy --server remote --listen 127.0.0.1:8787 --upstream https://mcp.example.com/mcp
```

A denied call reaches the agent as a brief JSON-RPC error with its original ID:

```json
{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"Tool arguments are outside the permitted scope."}}
```

Changed pinned tools are hidden until reviewed and updated using the original config, for example `fencepost pin --config ./mcp.json.fencepost.bak --update filesystem/read_file`. Refresh the client's tool list afterward. Approval timeouts deny, and upstream crashes are not restarted automatically.

Use `fencepost log tail`, `fencepost log verify`, and `fencepost log stats` to inspect the default `fencepost-audit.jsonl`. Keep its `.head` checkpoint alongside it. See [all policy fields and AgentWorkflows setup](docs/policy.md), [the threat model](docs/threat-model.md), and [example laptop, CI, and team policies](examples/). Filesystem and host checks constrain tool arguments; OS isolation is still needed to constrain a server's actual filesystem and network access.

## Sample offline scan

Real output from Windows 11, with `USERPROFILE=testdata\home`, `APPDATA=testdata\home\AppData\Roaming`, and `XDG_CONFIG_HOME=testdata\home\.config`, running `fencepost scan --offline` from this checkout. The fixture contains a dummy credential; the command exited **1**.

```text
packages (testdata\home\.cursor\mcp.json)
  FP004  MEDIUM  Unpinned package launch  config:3

remote (testdata\home\.cursor\mcp.json)
  FP005  HIGH    Plaintext secret  config:7
    A config environment variable or header appears to contain a credential. Configured value: <redacted:Authorization>.
  FP008  HIGH    Remote HTTP without TLS  config:7

2 server(s), 3 finding(s), 0 connection error(s)
```

## Rules

| ID | Severity | Rule |
| --- | --- | --- |
| FP001 | high | Hidden instructions |
| FP002 | high | Deceptive Unicode |
| FP003 | medium | Tool-name shadowing |
| FP004 | medium | Unpinned package launch |
| FP005 | high | Plaintext secret |
| FP006 | medium | Unconstrained risky capability |
| FP007 | low | Suspicious description payload |
| FP008 | high | Remote HTTP without TLS |

Read [rule explanations and fix hints](docs/rules.md). These are review heuristics: legitimate descriptions can contain URLs, similar names can be intentional, and a restrictive schema does not prove that a server enforces it. Passing a scan is not a guarantee that a server is safe.

## Protocol and configuration

The scanner targets MCP **2026-07-28** and supports **2025-11-25** initialization. It handles stdio and Streamable HTTP with JSON or SSE responses, follows list pagination, and preserves unknown definition fields. See [protocol details, limits, and config provenance](docs/PROTOCOL.md).

All client formats are tested with fixtures. They have not been verified against running client applications. Claude Desktop's Linux path, Claude Code's settings-file compatibility, historical VS Code settings, and Windsurf's historical path include inferred compatibility behavior. The protocol document identifies each case. OAuth, interactive inputs, deprecated separate HTTP+SSE endpoints, and dynamic config helpers are not supported in this stage.

Use environment references such as `${TOKEN}` or `${env:TOKEN}` for credentials. Reports mask known credential values as `<redacted:ENV_NAME>` and do not echo process stderr or server error bodies. Offline scanning does not resolve or expose the referenced environment values.

## Development

Requirements: Go 1.27.2, GNU Make, a C compiler for Go's race detector, and Python 3 with `jsonschema==4.26.0` for SARIF and policy schema checks. Release builds use `CGO_ENABLED=0`; the race detector's compiler requirement is only for tests. Application dependencies are `gopkg.in/yaml.v3` for YAML/config locations and `golang.org/x/net/idna` (with `x/text`) for validated Unicode host normalization.

```sh
python -m pip install jsonschema==4.26.0
make lint test e2e build
```

`lint` runs `go vet` and golangci-lint 2.14.0 with Staticcheck and unused-code checks. The linter is downloaded as an isolated Go tool; it is not an application dependency. `test` runs `go test -race ./...`. `e2e` builds the CLI and ten Go fixture servers with `-race`, exercises scanning, pinning, proxy enforcement, and wrapping over both transports, and validates SARIF and example policy schemas. `build` produces linux/darwin/windows binaries for amd64 and arm64 in `bin/`.

Run bounded fuzzing locally (CI runs seeds only) and benchmark the call path:

```sh
go test ./internal/mcp -run '^$' -fuzz FuzzFraming -fuzztime=10s
go test ./internal/policy -run '^$' -fuzz FuzzMatcher -fuzztime=10s
go test ./internal/proxy -run '^$' -bench BenchmarkSmallCall -benchmem
```

Measured latency and scope are recorded in [docs/PERF.md](docs/PERF.md).

Regenerate the rule reference with `go generate ./internal/scan`. Tests check that it matches the rule registry. Verbatim descriptions captured from official reference servers, with source hashes and upstream licensing notices, are in `testdata/reference/`.

The CI workflow runs lint, tests, end-to-end checks, and cross-builds in one Ubuntu job on pushes to `main` or manual dispatch. No publishing or release automation is included.

## License

[Apache-2.0](LICENSE). Captured reference-server material and the SARIF schema retain their upstream notices.
