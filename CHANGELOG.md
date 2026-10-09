# Changelog

## 0.4.0 - 2026-10-09

- Add per-tool session call budgets alongside rolling rate limits, with atomic enforcement, bounded counter storage, audit denials, and usage retained across policy reloads once tracking begins.
- Reject fractional YAML call limits instead of silently truncating them, including fractions below one that previously disabled rate/session caps.
- Redact short and mixed sensitive-key values, HTTP authorization/cookie headers, URL userinfo, and private-key fragments alongside recognized tokens, including approval and recorded-argument surfaces.
- Cover policy parsing and redaction with fuzz targets and budget enforcement with concurrent and end-to-end regression tests.
- Extend local console checks to 360/393 CSS pixels and English/German browser locales; keep bulk screenshots in ignored fixture output. The console remains English-only.

## 0.3.0 - 2026-10-09

- Vet npm, PyPI, OCI and MCP registry packages or remote endpoints before installation, with explicit isolation limits, scan findings, package risk signals and pinned maintainer comparisons.
- Compose tested, deny-by-default filesystem, git, fetch, browser, database, shell and cloud starter packs with `init --pack`.
- Add an embedded authenticated loopback console for server/pin state, verified audit events, policy validation, replay and conflict-checked saves.
- Add opt-in Ed25519-signed poisoning-rule bundles with bounded validation and rollback rejection.
- Build a static documentation site locally, and capture console views in both themes at desktop and phone sizes with Playwright.

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
