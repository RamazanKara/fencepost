# Fencepost

Fencepost audits the MCP servers configured on a developer's machine. It checks tool and parameter descriptions for suspicious instructions, checks launch and connection settings, and records trusted tool definitions so later changes are visible. It runs as a single Go binary with no CGO dependency. This first stage includes `scan`, `pin`, and `verify`; policy enforcement through `proxy` comes in the next stage.

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

Requirements: Go 1.27.2, GNU Make, a C compiler for Go's race detector, and Python 3 with `jsonschema==4.26.0` for validation against the official SARIF schema. Release builds use `CGO_ENABLED=0`; the race detector's compiler requirement is only for tests. The only application dependency is `gopkg.in/yaml.v3`, for YAML lockfiles and config source locations.

```sh
python -m pip install jsonschema==4.26.0
make lint test e2e build
```

`lint` runs `go vet` and golangci-lint 2.14.0 with Staticcheck and unused-code checks. The linter is downloaded as an isolated Go tool; it is not an application dependency. `test` runs `go test -race ./...`. `e2e` builds the CLI and six Go fixture servers, exercises scan/pin/verify over both transports and protocol revisions, and validates SARIF against its full JSON Schema. `build` produces linux/darwin/windows binaries for amd64 and arm64 in `bin/`.

Regenerate the rule reference with `go generate ./internal/scan`. Tests check that it matches the rule registry. Verbatim descriptions captured from official reference servers, with source hashes and upstream licensing notices, are in `testdata/reference/`.

The CI workflow runs lint, tests, end-to-end checks, and cross-builds in one Ubuntu job on pushes to `main` or manual dispatch. No publishing or release automation is included.

## License

[Apache-2.0](LICENSE). Captured reference-server material and the SARIF schema retain their upstream notices.
