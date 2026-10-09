# Changelog

## 0.2.0 - 2026-10-09

- Add an authenticated gateway for supervised stdio and remote Streamable HTTP upstreams, OIDC discovery/JWKS validation, CI keys, and identity-aware policies.
- Load ordered policy directories or signed HTTPS policies with ETag polling; preview edits against recorded audit calls.
- Add stdout JSON, rotating-file, OTLP logs and syslog exports, plus filtered log queries.
- Add a team approval inbox with browser PKCE sign-in, approver/reason audit records and signed chat notifications.
- Add local distroless image builds, Helm and Compose packaging, GoReleaser builds, and AgentWorkflows team examples.

## 0.1.0 - 2026-10-09

- Enforce YAML policies over stdio and Streamable HTTP, with argument allowlists, approvals, rate/session limits, and tool pin checks.
- Redact recognized secrets, cap tool results, and warn about or block detected result injection.
- Wrap and restore every supported client-config format, including an HTTP-to-stdio gateway and exact backups.
- Add loopback approval pages, signed team webhooks, hash-chained JSONL audit commands, and optional OTLP/HTTP decision spans.
- Add adversarial fixture tests, race checks, local fuzz targets, policy schema/examples, and the policy/threat-model/performance references.

- Discover MCP client configs and audit them offline or with live stdio/Streamable HTTP enumeration.
- Detect hidden instructions, deceptive Unicode, shadowing, unpinned launchers, plaintext secrets, risky capabilities, suspicious descriptions, and unencrypted remote HTTP.
- Emit human tables, JSON, and SARIF 2.1.0 reports.
- Pin canonical tool definitions and launch specs, verify drift, and accept individual tool updates.
- Support MCP 2026-07-28 with 2025-11-25 initialization compatibility.

- Add noninteractive starter policies, policy explanations, discovery/permission diagnostics, and policy error locations.
- Bound expired rate-limit state and rejected tool-name retention; add policy/audit property tests and a 10-minute HTTP soak.
- Add local release binaries with build metadata, SHA256SUMS, a minimal container, and release/contribution/security guidance.
