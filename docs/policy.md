# Policy proxy

For authenticated multi-server operation, central sources, identity rules, team approvals and audit exports, see [the gateway guide](gateway.md).

`fencepost proxy` applies a version 1 YAML policy to MCP tool calls. It requires a policy file; missing or invalid policy is an error. `fencepost policy check --policy fencepost.yaml` checks field names, types, actions, globs, regular expressions, JSON paths, timeouts, and endpoint restrictions. [The JSON Schema](../schema/policy.schema.json) supports editor validation; runtime checking additionally validates Go regex syntax, glob syntax, IDNs, and timeout bounds. Unknown servers are denied. Only `tools/call` is subject to tool permissions; protocol discovery, prompts, resources, and client capabilities remain available.

```yaml
version: 1
session_budget: 100
servers:
  filesystem:
    default: deny
    tools:
      - name: read_*
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
          - path: $.content
            max_length: 100000
output:
  redact_secrets: true
  max_bytes: 1048576
  injection: warn
approval:
  mode: local
  timeout: 30s
  local_file: fencepost-approval.json
audit:
  path: fencepost-audit.jsonl
```

All policy filesystem paths are relative to the policy file's directory. Environment interpolation is not performed in policies. Explicit `null` is only permitted within enum values. CLI `--lock` defaults to `fencepost.lock` in the working directory; wrapping writes an absolute lock path into the client config.

## Operator commands

```sh
fencepost init --server filesystem --policy fencepost.yaml
fencepost explain fencepost.yaml examples/denied-call.json
fencepost doctor --config ./mcp.json --policy fencepost.yaml
```

`init` exclusively creates a mode-0600 starter file and never prompts or overwrites. The starter permits only `read_file` inside `./workspace`; create that directory beside the policy before use. All other tools and unknown servers deny.

`explain` accepts one JSON object with `server`, `name`, and optional `arguments` (an object). It uses the same ordered matcher as the proxy and prints the deciding tool/argument index or server default. It exits 0 for allow, 1 for deny or required approval, and 2 for invalid input. It neither invokes a tool nor requests approval. Live rate/budget usage, pins, and approval state are not simulated.

`doctor` lists discovery candidates, parses present configs and the policy, checks file access, and briefly creates/removes a temporary file in each runtime output directory. It never launches configured commands. Unix checks reject group/other-writable files and checked directories and require private config/runtime files to exclude group/other access. On Windows it checks effective read/create access and explicitly reports that ownership and other accounts' ACL access were not verified. No discovered servers, malformed files, or failed access checks return 2. Use `--config` to isolate discovery.

Invalid policy diagnostics include the filename, line, and failed validation without copying policy values.

## Servers and tools

| Field | Meaning |
| --- | --- |
| `version` | Required, exactly `1`. |
| `servers` | Required nonempty map of exact server names. Use the same names as your client config and lockfile. |
| `servers.NAME.default` | Required `allow`, `deny`, or `ask` when no tool rule matches. |
| `servers.NAME.tools` | Optional ordered list; the first matching name determines the action and constraints. |
| `tools[].name` | Required case-sensitive Go path glob: `*`, `?`, `[abc]`, `[a-z]`. `*` does not cross `/`. Put specific rules before broad ones. |
| `tools[].action` | Required `allow`, `deny`, or `ask`. Argument constraints apply before asking. |
| `tools[].rate_limit` | Nonnegative calls per rolling minute for that actual tool name; `0` or omitted means unlimited. |
| `tools[].arguments` | Optional list of argument constraints. Every rule must pass. |
| `session_budget` | Nonnegative total allowed calls across all tools in one proxied MCP session; `0` or omitted means unlimited. Denied calls do not consume it. Upstream failures after authorization do. |

A stdio process is one session. A legacy HTTP session starts on successful initialization and ends with DELETE or proxy shutdown. Unknown session IDs are rejected. Modern stateless HTTP requests without session IDs share one budget for the listener's lifetime. Each wrapped server has its own MCP session; Fencepost cannot identify a common agent conversation across independent server processes. Approval grants and counters are in memory and reset with a new session. There is no automatic upstream restart.

## Arguments

`path` is required and starts at the `arguments` object: `$.path`, `$.request.url`, `$.files[0].path`, or `$.files[*].path`. Wildcards select every array element. Missing properties, wrong types, out-of-range indexes, and empty wildcard arrays fail closed. JSONPath filters, recursive descent, quoted property names, and object wildcards are not supported.

Each rule needs at least one constraint; multiple constraints are ANDed. Each allowlist must contain at least one entry.

| Constraint | Example and behavior |
| --- | --- |
| `path_prefix` | `[./workspace, /opt/shared]`. Arguments must be absolute local filesystem paths. Both roots and candidates are resolved with symlinks; containment uses path components, not string prefixes. Nonexistent destinations are checked through their existing ancestors. `..` components, percent-encoded paths (including double encoding), NULs, UNC/device paths, Windows alternate data streams, and ambiguous Windows trailing dots/spaces are denied. Existing policy roots are resolved at load time; later redirection of a resolved root is denied. |
| `host` | `[api.example.com, bücher.example, '::1']`. Requires an HTTP(S) URL, parses its hostname, applies UTS #46/IDNA validation, and compares exact normalized hosts. It rejects userinfo, malformed ports, zone IDs, mapped IPv6, decimal/hex/octal/short IPv4, and noncanonical IP representations. IP literals must be explicitly listed. DNS subdomains are separate hosts; ports are not an allowlist dimension. |
| `regex` | `'^[a-f0-9]{40}$'`. Go/RE2 regex on a string. Matching is unanchored unless you supply `^` and `$`. |
| `max_length` | `4096`. Maximum Unicode code points in a string, including zero. |
| `enum` | `[staging, production]`. Exact JSON values, including objects, arrays, booleans, numbers, and null. |

The proxy validates arguments, not system calls. Filesystem changes between checking and the server opening a file, hard links, DNS changes, HTTP redirects performed by a tool, or a server ignoring the approved arguments require OS containment. See the [threat model](threat-model.md).

## Output

Output rules apply to tool results, including nested structured content and tool errors. They preserve unrelated envelope fields.

| Field | Default and behavior |
| --- | --- |
| `output.redact_secrets` | `true`. Uses the FP005 credential patterns, sensitive-key heuristic, and entropy detector. Replacements identify the detector, for example `[redacted:github-token]`, `[redacted:slack-token]`, `[redacted:api-key]`, or `[redacted:secret]`. Set `false` to disable result redaction; audit entries still omit argument/result bodies and sanitize identifiers. |
| `output.max_bytes` | `1048576`. Allowed range 512–16777216 bytes of encoded result JSON. Oversized results are replaced with a short `isError: true` text result; JSON and binary blocks are never cut in the middle. |
| `output.injection` | `warn`. FP001's detector adds a visible warning text block before the existing content. `block` returns a JSON-RPC error instead. Suspicious JSON-RPC errors are blocked because they have no content-block surface. |

The detectors are heuristics. A warning does not make malicious content safe, and a redaction detector cannot recognize every secret or encoded payload. Each MCP frame/SSE event is bounded at 16 MiB. Streams are processed event by event; the complete stream is never accumulated.

## Pins

If a lock exists, a tool must first appear in `tools/list` with the same definition hash as the lock entry. Changed, added, and unseen tools are hidden or denied. `notifications/tools/list_changed` invalidates cached trust, and a fresh list recomputes hashes. The hash fields and canonical encoding are the same as `pin` and `verify`.

Review a change and update the original server's baseline, then ask the client to refresh tools:

```sh
fencepost pin --config ./mcp.json.fencepost.bak --update filesystem/read_file
```

Use the backup config here so pinning connects directly to the original server. A live proxy rereads the lock on tool-list responses. A missing/corrupt baseline after enforcement began fails closed. The proxy enforces tool hashes; launch-spec comparisons remain the responsibility of `fencepost verify`.

## Approval channel

In standalone proxy mode, run `fencepost approve --policy fencepost.yaml`. It binds a literal loopback address, chooses a random port, writes the local descriptor, and prints a URL containing a random 256-bit token. Open that private URL in a browser. `--listen 127.0.0.1:8790` selects a fixed loopback port. Non-loopback and hostname listen addresses are rejected.

The page shows server, tool, and sanitized arguments with **Approve once**, **Always for this session**, and **Deny**. An always grant applies to that tool in that session; it does not bypass argument rules, pins, rate limits, or budget. The proxy denies on timeout, cancellation, a missing channel, malformed answers, or connection errors. Argument constraints are checked again after approval. The page escapes untrusted text, checks the Host and Origin headers, authenticates every route, and disables caching and framing. The descriptor is removed on orderly shutdown. After an abrupt termination, remove a stale descriptor before restarting the approval service.

| Field | Meaning |
| --- | --- |
| `approval.mode` | `local` (default) or `webhook`. |
| `approval.timeout` | Go duration, default `30s`, positive and at most `10m`. |
| `approval.local_file` | Default `fencepost-approval.json`; contains the loopback endpoint and bearer token. Protect it like a credential. |
| `approval.webhook_url` | Required for webhook mode; HTTPS, or HTTP on a literal loopback IP for local tests. Redirects are refused. |
| `approval.hmac_secret_env` | Required for webhook mode; names an environment variable containing at least 32 bytes of shared secret. Its value is never written into the policy. |

Webhook POST JSON contains `id` (random nonce), `time` (Unix seconds), `session`, `server`, `tool`, and sanitized `arguments`. The request header is `X-Fencepost-Signature: sha256=HEX`, where HEX is HMAC-SHA256 over the exact request body using the shared secret. The receiver should check the signature in constant time, reject stale timestamps, and remember nonces to prevent replay.

Respond with HTTP 200 and `{"decision":"allow"}` or `{"decision":"deny"}`. Sign the exact response body with HMAC-SHA256 over `request.id + "\n" + response_body`, using the same header format. Unsigned, mismatched, late, redirected, oversized, or unrecognized replies deny. The response signature binds the decision to one request. Webhooks do not grant session-wide approval.

## Audit and OpenTelemetry

| Field | Meaning |
| --- | --- |
| `audit.path` | Default `fencepost-audit.jsonl`. Required writes fail closed. Multiple proxy processes can share the file; native file locks serialize appends. |
| `audit.otlp_endpoint` | Optional full OTLP/HTTP JSON traces endpoint, for example `https://collector.example.com/v1/traces`. Off when omitted. Uses HTTPS, or literal loopback HTTP. |

Each JSONL record holds a sequence number, previous hash, sanitized event, and SHA-256 hash of the exact encoded entry. The checkpoint at `<log>.head` records final hash, count, and file size, making tail deletion detectable as well as edits, internal deletions, and reordering. Keep the log and checkpoint together. `<log>.writing` is the persistent OS lock file; locks release automatically when a process exits. Do not delete or replace these files while proxies are running.

Audit entries contain time, session, server, method, tool, decision, matched rule identifiers, and redaction counts. They omit arguments by default and never contain result bodies or upstream error bodies. Opt-in `audit.record_arguments` records sanitized arguments for policy replay; see the gateway guide for retention and replay limits. Writes reach the operating system before forwarding an allowed call; orderly shutdown also syncs the files. Sudden power loss can leave a torn final entry/checkpoint, which verification rejects. A hash chain is not an authenticated signature: someone who can replace both log and checkpoint can forge history. Anchor the final hash outside that trust boundary for stronger evidence.

```sh
fencepost log tail --file fencepost-audit.jsonl --n 20
fencepost log verify --file fencepost-audit.jsonl
fencepost log stats --file fencepost-audit.jsonl
```

`tail` prints a verified snapshot, not a follow stream. `stats` counts attempted calls by server/tool, denied decisions, and redactions. All three commands verify the checkpoint and chain before reporting success.

OTLP exports decision events as instantaneous spans with server/tool/decision/rule/session attributes. Its bounded background queue never sends arguments or results. Collector failures or queue overflow do not replace the local audit; shutdown reports incomplete exports. The endpoint must accept OTLP/HTTP JSON without additional auth headers. No external collector is required to run Fencepost.

## Transports and wrapping

```sh
fencepost proxy --server filesystem --policy fencepost.yaml -- /path/to/server --server-option
fencepost proxy --server remote --listen 127.0.0.1:8787 --upstream https://mcp.example.com/mcp
fencepost wrap --config ./mcp.json
fencepost wrap --config ./mcp.json --write
fencepost unwrap --config ./mcp.json --write
```

HTTP defaults to server name `upstream` when `--server` is omitted. It forwards JSON and SSE, sessions, Last-Event-ID, progress, cancellations, sampling, elicitation, and roots. GET streams and DELETE are forwarded. The client handles SSE reconnection. Redirects are refused; TLS uses the system trust store. The HTTP listener is loopback only and rejects browser Origin headers. It is intended for local MCP clients.

`wrap` and `unwrap` show a full-file diff by default. `--write` applies it. All supported config formats, including JSONC, nested/dotted VS Code settings, and matching Claude Code project entries, are supported. Unrelated settings are retained; rewritten JSON is indented and comments/trailing commas are removed. Disabled entries are left alone. Config backups at `<config>.fencepost.bak` preserve the original bytes and permissions are restricted when created. Existing backups are never overwritten. Restore removes the backup after restoring its exact contents. Review the diff if the config has changed since wrapping.

Wrapped commands select the original entry from the backup using `proxy --server NAME --config BACKUP`, with absolute policy and lock paths. HTTP entries use a stdio-to-HTTP gateway, including a legacy GET stream. Environment references used by remote headers are carried into the wrapper's declared environment. Keep the backup available; it is the proxy's launch source, not just an archive. Duplicate server names within one source are refused. Inputs/helpers/envFile remain unsupported as described in the protocol reference.

Direct stdio launches inherit the proxy's environment and working directory. Config-backed launches use the original declared environment plus the scanner's clean base environment and original cwd. A proxy process is not an OS sandbox.

## AgentWorkflows agents

Point each AgentWorkflows agent's MCP server command at the stdio invocation above, or point its Streamable HTTP connection at the local HTTP proxy. Preserve server names across the agent configuration, policy, and lock. Use absolute binary/policy/lock paths in unattended launches. For a runner using one of the supported JSON client formats, preview and apply `fencepost wrap --config PATH`; otherwise use the explicit proxy command in its MCP configuration.

For CI agents, start from [the no-network policy](../examples/ci-no-network.yaml), adapt the filesystem root, pin the direct servers before wrapping, and enforce network isolation in the CI runner itself. Interactive `ask` denies when nobody answers; unattended teams can use [signed webhook approvals](../examples/team-webhook.yaml). Each MCP connection has its own session budget. This integration uses standard MCP configuration; no AgentWorkflows-specific SDK or live AgentWorkflows deployment was tested.

References: [IDNA implementation](https://pkg.go.dev/golang.org/x/net/idna), [OTLP JSON protocol](https://opentelemetry.io/docs/specs/otlp/).
