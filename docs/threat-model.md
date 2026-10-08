# Threat model

Fencepost sits between a local MCP client and a configured server. It assumes the client actually routes its MCP traffic through the proxy and that the policy, binary, lockfile, original config/backup, and approval channel are controlled by the operator. Tool arguments, server definitions, server results, and upstream error messages are untrusted.

## What it enforces

- Tool calls can be denied by server/tool name, argument constraints, rate, session budget, approval, or a mismatched tool definition. Rejections are JSON-RPC errors with the original request ID and a short reason. The agent does not see policy paths, host allowlists, credentials, or rule bodies.
- Filesystem argument rules check resolved path containment and reject traversal, links outside the allowed root, encoded paths, and ambiguous Windows paths. URL argument rules parse the URL, validate IDNs, require exact host membership, and reject misleading userinfo and numeric IP representations.
- A locked tool remains unavailable until the client lists a definition matching the baseline. List-change notifications revoke previous trust. This catches an advertised rug pull; the tool hash is not a code signature.
- Output rules redact recognized secret patterns, replace oversized tool results, and visibly warn about detected prompt injection or block it. The original suspicious content stays visible after a warning unless a size cap also applies.
- Every accepted protocol message and tool decision is audited without argument/result bodies. A checkpoint plus hash chain detects edited, missing, reordered, and truncated entries as long as the checkpoint is trusted.
- Local approval uses a random URL token, loopback binding, Host/Origin checks, escaped text, and timeouts. Webhook decisions require request/response HMAC signatures. Missing approvals deny.

## What it does not enforce

Fencepost does not isolate a process. A server still has its OS account's filesystem, network, process-execution, and credential access. A malicious server can ignore an approved argument, change behavior while keeping the same tool description, read a secret itself, send data directly over the network, or attack the client using a vulnerability in the client. Use an OS sandbox, container/VM boundaries, filesystem permissions, and network controls to contain it. The CI no-network example denies exposed network tools; it does not disable network system calls.

Path validation and a separate process opening the path cannot be atomic. An attacker with write access to a checked directory can race symlink/directory replacement after approval. Hard links, mount changes, Windows filesystem aliases, and differences in the server's path interpretation can also defeat a purely argument-level check. Fencepost rejects ambiguous syntax and rechecks after approval, but does not give the server a pre-opened restricted file descriptor. Keep allowed roots under trusted control and enforce OS permissions.

Host checks do not resolve or pin DNS addresses. They do not inspect redirects, nested URLs inside arbitrary content, or the network request a tool ultimately sends. An allowed host can itself be malicious or resolve to a private address. Use egress filtering and a fetch implementation that checks redirect destinations and resolved IPs when SSRF containment is required.

FP001 and FP005 are heuristics. Obfuscated, encoded, fragmented, novel, or very short secrets/instructions may be missed. Binary image/audio content is size-limited but not semantically decoded. A legitimate high-entropy string can be redacted. A warning is information for the model/user, not a guarantee that the model will ignore an attack. Prompts, resources, progress messages, sampling, elicitation, roots, and other protocol methods pass through; tool permissions are not a method-wide firewall. Review client capability grants separately.

The baseline covers advertised tool definitions. A server can change implementation without changing the hash, or conceal drift until its next list response. The proxy does not poll tools on every call or attest the executable; scanner `verify` remains responsible for launch-spec drift. Protect and review lock updates.

The HTTP proxy and approval service are for local use. Other processes running as the same user can usually read config, approval descriptors, and audit files or invoke servers directly. Windows uses the containing directory's ACLs; Unix uses restrictive file modes for newly created sensitive files. Local administrators are outside the boundary. This is not a multi-tenant authentication or authorization service.

Budgets and approvals last for one proxied MCP session. Starting another process or a new legacy HTTP session starts new counters. Modern stateless HTTP shares the listener's lifetime budget. Independent wrapped servers do not share an agent-conversation identity. No billing-grade or organization-wide accounting is claimed.

Audit hashing detects accidental edits and tampering by actors who cannot also replace the checkpoint. An attacker controlling both files can recompute the chain. Removing all evidence, rolling both files back together, or disk loss requires an external anchor/collector to detect. Writes use the OS cache and sync on orderly shutdown; power loss may leave an incomplete tail that fails verification. OTLP export is optional and best effort, with a bounded queue; it is not the authoritative audit record.

Protocol frames/SSE events, pending requests, HTTP sessions, and local approvals have bounds, but a malicious process can still consume CPU, hold an allowed stream open, flood requests, or stop reading. Fencepost is not a general denial-of-service defense. Crashed upstreams are not restarted automatically. POSIX shutdown kills the process group; Windows kills the immediate process and does not contain descendants.

## Operational assumptions

Pin direct servers before wrapping. Keep policy and audit paths outside directories writable by an untrusted server where possible. Use least-privilege approval operators and a webhook receiver that validates freshness/nonces as well as signatures. Keep original backups private, because they may contain credentials. Review policy denies, injection warnings, and drift rather than automatically approving them. A passing scanner or proxy test is not a claim that an arbitrary MCP server is trustworthy.
