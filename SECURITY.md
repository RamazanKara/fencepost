# Security

Security fixes target the latest 0.1.x release. Read the [threat model](docs/threat-model.md) before deployment: Fencepost is an MCP policy proxy, and a passing scan does not establish that a server is safe.

Use this repository's **Security → Report a vulnerability** private advisory channel when available. If it is unavailable, open an issue requesting a private contact without including vulnerability details or secrets. Do not disclose a live credential, private audit log, or working exploit in a public issue.

Include the Fencepost version, operating system, affected command/transport, a minimal synthetic policy and reproduction, expected versus observed behavior, and impact. Remove identifying paths and credentials. Coordinate disclosure with the maintainer; no response-time guarantee is made.

If a real secret was exposed, revoke or rotate it before considering history cleanup. Protect policies, lockfiles, original configs/backups, approval descriptors, audit logs, and checkpoints using OS permissions. Audit hash chains require a trusted checkpoint and do not authenticate an attacker-controlled pair of files.
