# Protocol implementation

Fencepost targets MCP **2026-07-28**, the latest published specification checked on 2026-10-08, with **2025-11-25** compatibility. The implementation is in `internal/mcp`; it does not use an MCP SDK. Go 1.27.2 is the selected stable toolchain.

Sources:

- [Current specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [Current changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [Version negotiation](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)
- [stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [Previous lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [Previous transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [Previous changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)

## Messages and negotiation

JSON-RPC envelopes retain their raw JSON and all unknown fields. Unknown methods are accepted by the framing layer. Request IDs distinguish strings from integers. Notifications have no ID and receive no reply. Requests are correlated by ID even if responses arrive out of order. Both supported revisions send individual messages; JSON-RPC batch arrays are rejected. No method allowlist is built into the message parser.

The current revision removed `initialize`, protocol sessions, and unsolicited server requests. Fencepost first sends `server/discover` with protocol version, client identity, and empty capabilities in `params._meta`. Each subsequent request carries this metadata. Discovery must advertise the current revision. Results must have `resultType: complete`; requests for client input fail the scan because the scanner advertises no sampling, roots, or elicitation capabilities. Unknown fields in results and definitions are retained.

On stdio, a non-modern discovery error or a two-second probe timeout triggers `initialize` with `2025-11-25`, followed by `notifications/initialized`. On HTTP, a legacy JSON-RPC error or HTTP 400/404/405 triggers the same fallback. Recognized modern errors do not trigger a downgrade. Authentication failures, redirects, malformed responses, and transport failures fail the HTTP scan. An unsupported negotiated revision fails explicitly.

The scanner enumerates each advertised `tools`, `prompts`, and `resources` capability, following `nextCursor` until absent. Unadvertised capabilities are skipped. Repeated cursors, more than 1000 pages, duplicate tool names, and malformed definitions fail enumeration. A failed server makes the scan incomplete (exit 2); pin/verify never accept a partial inventory.

## Transports and limits

stdio uses newline-delimited UTF-8 JSON, with partial-read support. A frame must end with a newline. Messages and SSE events are limited to 16 MiB. stderr is discarded rather than copied into reports. The reader handles notifications without confusing them with responses. Legacy server requests receive method-not-found because no client features were advertised. Closing stdin initiates shutdown; a process that remains alive after 300 ms is terminated. POSIX termination covers the process group. Windows termination covers the immediate process; descendant process containment is not implemented.

HTTP sends one POST per message, accepts `application/json` and `text/event-stream`, and processes SSE comments, multiline data, event IDs, and retry fields. Every modern request supplies `MCP-Protocol-Version` and `Mcp-Method`. SSE notifications are consumed until the matching response. Redirects are refused to avoid forwarding configured credentials. TLS uses the system trust store.

Legacy HTTP initialization captures `Mcp-Session-Id`; subsequent requests carry it and `MCP-Protocol-Version`. Shutdown issues DELETE; 404/405 are tolerated. A dropped legacy SSE stream with an event ID resumes using GET and `Last-Event-ID`, respecting `retry`, up to two times within the scan deadline. Modern streams do not resume. The scanner does not open an optional unsolicited GET stream or subscribe to changes.

Each server has a 15-second total deadline. The stdio process receives a small environment allowlist (`PATH`, home/profile directories, Windows system/application directories, command interpreter, executable suffixes, and temporary directories), plus its declared environment. Other parent variables, including tokens, are not inherited. Explicit environment references can resolve parent variables. A clean environment is not an operating-system sandbox: a launched server still runs with the caller's filesystem and network permissions. Online scans execute configured launch commands, which can install packages. Offline scans do not start processes or make network requests.

The scanner and pinning client do not call tools, retrieve prompt bodies or resource contents, handle OAuth/browser login, run interactive config inputs, execute env/header helpers, load `envFile`, or support the deprecated separate HTTP+SSE transport. Tool invocation features such as `x-mcp-header` parameter mirroring and MRTR continuations are outside the scanner's implemented subset. It preserves these fields when reading definitions. Schema references are not fetched.

## Policy proxy

The 0.1.0 proxy relays client-negotiated protocol traffic; it does not negotiate a separate MCP revision or advertise capabilities on the client's behalf. Stdio is bidirectional and preserves request IDs, notifications, progress, cancellation, and server-initiated sampling/elicitation/roots requests. Tool calls awaiting approval do not stop the input reader. Upstream disconnects produce explicit errors for outstanding client requests, and automatic restart is disabled.

The loopback HTTP proxy accepts POST, GET, and DELETE, forwarding session IDs, protocol headers, Last-Event-ID, and JSON/SSE responses. SSE comments, retry values, IDs, and multiline events survive transformation. It buffers at most one bounded event at a time; the client remains responsible for reconnecting/resuming streams. An HTTP entry rewritten by `wrap` uses a stdio-to-HTTP gateway; the gateway opens the optional GET channel for a legacy session. Unknown session IDs, redirects, and browser Origin headers are rejected.

Policies operate on `tools/call` arguments and tool results. Pinned `tools/list` entries are checked with the existing hash format, including paginated lists. A tool-list change notification revokes cached trust. Other methods and unknown extension fields pass through; this is not a protocol-method allowlist. The proxy does not synthesize header-mirrored arguments, OAuth flows, or modern MRTR orchestration; callers must supply protocol features they require. See [policy behavior](policy.md) and [trust boundaries](threat-model.md).

## Lock format

Version 1 of `fencepost.lock` stores sorted server and tool maps. Launch hashes include the configured transport, command, args, env, URL, headers, working directory, and env-file declaration. Environment references are hashed as written: rotating an external variable does not change the launch hash. Source paths and line numbers are excluded. Duplicate server names across config sources must be disambiguated using `--config` before pinning.

Tool hashes cover exactly `name`, `description`, `inputSchema`, `outputSchema`, and `annotations`, including presence versus absence. Canonical JSON sorts object keys lexicographically, retains array order, decodes JSON string escapes, emits UTF-8 without HTML escaping, and normalizes decimal numbers to a coefficient and exponent without float64 rounding. This deterministic encoding is specific to lock format 1; it is not RFC 8785. SHA-256 hashes are lowercase hex. Descriptions are retained for unified diffs, with known credentials redacted. Credentials are never written as launch values. Hashes are fingerprints, not encryption; protect lockfiles containing sensitive descriptions.

Initial `pin` refuses to overwrite an existing lock. `pin --update server/tool` accepts only that tool's addition, removal, or change, leaving other entries untouched. It rejects launch drift. To accept a changed launch spec or add/remove a server, review the complete config, deliberately remove the old lock, and create a fresh baseline. `verify` reports changes to any of the five hashed fields, even when a description diff is empty.

## Client configuration coverage

Config support is based on documentation and fixture tests, not live inspection of installed client applications. Auto-discovery audits all discovered sources; it does not emulate each client's precedence, trust decisions, plugins, disabled-tool lists, remote profiles, or enterprise policy. Entries marked `disabled: true` are skipped. An explicit `--config file` isolates discovery to that file. JSON and JSONC comments/trailing commas are accepted; source lines point to each server's key.

| Client | Discovered paths / format | Evidence |
| --- | --- | --- |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%/Claude/claude_desktop_config.json`; Linux `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json` or `~/.config/Claude/claude_desktop_config.json`; `mcpServers` | [Official macOS/Windows instructions](https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers); Linux path inferred from XDG/community packaging, not officially observed |
| Claude Code | Project `.mcp.json`; user `~/.claude.json` including matching `projects[projectPath].mcpServers`; `~/.claude/settings.json` compatibility entries | [Official MCP docs](https://code.claude.com/docs/en/mcp); `mcpServers` in settings is a compatibility assumption, current normal storage is `.claude.json` |
| Cursor | Project and user `.cursor/mcp.json`; `mcpServers` | [Official MCP docs](https://cursor.com/docs/context/mcp) |
| VS Code | Project `.vscode/mcp.json` and `.vscode/settings.json`; user `Code/User/mcp.json` and `Code/User/settings.json`; `servers`, `mcp.servers` as nested or dotted settings | [Official MCP docs](https://code.visualstudio.com/docs/agent-customization/mcp-servers); historical settings form retained for the requested compatibility |
| Windsurf | `~/.codeium/windsurf/mcp_config.json`; `mcpServers`, `url` or `serverUrl` | Historical Windsurf format; [current documentation](https://docs.windsurf.com/windsurf/cascade/mcp) redirects to Devin and uses different paths. The requested Windsurf path is fixture-tested, not observed in a live installation. |

VS Code's user base is `%APPDATA%` on Windows, `~/Library/Application Support` on macOS, and `$XDG_CONFIG_HOME` (default `~/.config`) on Linux. Windows defaults `%APPDATA%` to `~/AppData/Roaming` when unset. The default VS Code profile is covered. Custom profiles and the newer Copilot portable config are outside these requested formats.

`${NAME}`, `${env:NAME}`, `${env.NAME}`, and `${NAME:-default}` resolve at connection time; unresolved variables fail explicitly. No shell evaluation is performed. `<redacted:ENV_NAME>` replaces known env/header credentials in output. Error bodies, process stderr, launch arguments, URLs, and config values are not echoed. Rule findings carry source locations and review hints without copying hostile descriptions into reports; verify displays sanitized description diffs.
