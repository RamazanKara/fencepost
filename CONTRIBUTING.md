# Contributing

Use Go 1.27.2 and the tools in [README.md](README.md#development). Keep changes scoped to one behavior and match the surrounding Go style. Avoid new dependencies unless necessary.

Run `gofmt` on changed Go files, then `make lint test e2e build`. The test and e2e targets use the race detector. Add a regression test for a fixed bug; preserve the generated scanner-rule reference (`go generate ./internal/scan`) when changing rules. Policy examples must pass runtime and JSON Schema validation.

For matcher, framing, audit, or long-lived proxy changes, run the fuzz/property/soak checks in [RELEASING.md](docs/RELEASING.md). Report actual results, skipped checks, platform limits, and benchmark scope. Use synthetic credentials and temporary directories in fixtures; do not add real client configs, audit logs, secrets, or machine paths.

Use a specific conventional commit message such as `fix(policy): report the invalid rule location`. Explain the user-visible change and validation in the pull request. Contributions use the existing [Apache-2.0 license](LICENSE); retain third-party notices.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
