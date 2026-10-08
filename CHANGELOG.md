# Changelog

## 0.2.0-dev - unreleased

- Enforce YAML policies over stdio and Streamable HTTP, with argument allowlists, approvals, rate/session limits, and tool pin checks.
- Redact recognized secrets, cap tool results, and warn about or block detected result injection.
- Wrap and restore every supported client-config format, including an HTTP-to-stdio gateway and exact backups.
- Add loopback approval pages, signed team webhooks, hash-chained JSONL audit commands, and optional OTLP/HTTP decision spans.
- Add adversarial fixture tests, race checks, local fuzz targets, policy schema/examples, and the policy/threat-model/performance references.

## 0.1.0 - unreleased

- Discover MCP client configs and audit them offline or with live stdio/Streamable HTTP enumeration.
- Detect hidden instructions, deceptive Unicode, shadowing, unpinned launchers, plaintext secrets, risky capabilities, suspicious descriptions, and unencrypted remote HTTP.
- Emit human tables, JSON, and SARIF 2.1.0 reports.
- Pin canonical tool definitions and launch specs, verify drift, and accept individual tool updates.
- Support MCP 2026-07-28 with 2025-11-25 initialization compatibility.
