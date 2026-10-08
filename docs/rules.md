# Scanner rules

Generated from `internal/scan.Rules` by `go generate ./internal/scan`.

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

## FP001: Hidden instructions

Severity: high.

Descriptions contain instructions directed at the model, sensitive-file access, or data transfer instructions.

Fix: Remove behavioral instructions and describe only the tool's inputs and effects; review the server source.

## FP002: Deceptive Unicode

Severity: high.

Invisible, bidirectional, or tag characters can conceal instructions; confusable names can impersonate tools.

Fix: Remove invisible controls and use unambiguous ASCII tool names.

## FP003: Tool-name shadowing

Severity: medium.

Tools on different servers have matching or similar names, or a description refers to another server's tool.

Fix: Rename overlapping tools, remove cross-server instructions, and review which server is trusted.

## FP004: Unpinned package launch

Severity: medium.

A package launcher can resolve a different package version on the next run.

Fix: Pin an exact package version or immutable container digest and review upgrades.

## FP005: Plaintext secret

Severity: high.

A config environment variable or header appears to contain a credential.

Fix: Replace the literal with an environment reference and rotate any exposed credential.

## FP006: Unconstrained risky capability

Severity: medium.

A tool advertises shell execution, file writes, or HTTP fetching without a relevant schema constraint.

Fix: Restrict command, path, or host inputs with an allowlist and enforce the restriction on the server.

## FP007: Suspicious description payload

Severity: low.

Descriptions exceed 8192 bytes or contain URLs or base64 payloads of at least 256 characters.

Fix: Keep descriptions concise; review linked or encoded content and remove unnecessary payloads.

## FP008: Remote HTTP without TLS

Severity: high.

The server uses unencrypted HTTP on a non-loopback host.

Fix: Use HTTPS with a valid certificate or a loopback-only endpoint.

These rules are heuristics, not a proof of safety. Constraints in a schema are hints; the scanner does not execute tools or prove that servers enforce them. Unicode confusable detection covers common Latin, Cyrillic, Greek, and fullwidth lookalikes, not the complete Unicode confusables database. Review findings in context.
