# Server vetting

`fencepost vet` examines a server before you add it to a client. It never approves a pin or installs into your project. Metadata and dependency downloads use the network; `--net` controls network access for the **server process**, not the trusted package manager's download phase.

```sh
fencepost vet npm:@modelcontextprotocol/server-filesystem
fencepost vet pypi:mcp-server-git
fencepost vet oci:ghcr.io/owner/server:1.0.0
fencepost vet mcp:io.github.owner/server
fencepost vet https://server.example/mcp --net
fencepost vet ./testdata/packages/clean --net
```

These are syntax examples, not claims about registry availability. Bare names mean npm; exact npm/PyPI versions use `@VERSION`/`==VERSION`. Official MCP registry entry URLs also work. Registry entries select their first supported package, or a Streamable HTTP remote. Required runtime arguments, credentials, multiple entry points and non-stdio package transports need manual review; failed enumeration is incomplete, never clean.

The report lists package/version, official registry match when found, sandbox mode, tool names, scan findings, and reasons for **looks fine**, **review**, or **avoid**. Exit 0 means completed with no risk signals, 1 means completed review/avoid, and 2 means invalid input or incomplete enumeration. Metadata/connection failures never count as clean scans.

All scanner rules run over advertised tools, prompts, resources and server instructions. High/critical findings or a likely typosquat produce avoid. Install hooks, versions less than seven days old, unknown ownership/date, ownership changes and incomplete isolation produce review. Name checks compare a small curated list with one-edit/transposition variants and missing npm scopes, not a comprehensive reputation database. A clean result cannot establish executable safety.

## Execution boundary

Every run uses a temporary cwd, home, config and cache and removes them on completion. Parent credentials are not inherited. npm installation uses `--ignore-scripts` without bin links. Reports detect root-package preinstall/install/postinstall/prepare/prepublish hooks; transitive scripts are suppressed but not individually reported. Local npm directories are copied without `.git` or `node_modules`; symlinks and escaping entry paths are rejected. A package needs one JavaScript `bin` entry. Only MCP enumeration runs; advertised tools are never invoked.

PyPI requires Python/pip, accepts wheels only, refuses source builds, and needs one simple console entry point. It runs the temporary target in isolated Python mode. Maintainer/author fields are publisher claims, not verified PyPI account ownership; the report marks that limitation.

Linux first probes bubblewrap user/mount/PID/network namespaces. It hides `/home`, `/root` and `/run`, makes the host root read-only, and exposes the temporary directory as writable. Other host files remain readable: this is not a VM. If unavailable, it probes `unshare` user/mount/PID namespaces; this fallback does **not** constrain filesystem access. Both use a fresh network namespace unless `--net` is supplied. Kernel restrictions can prevent either backend from working.

Without a working backend, including Windows/macOS, default vetting refuses to start executable code. Explicit `--net` permits a documented best effort run with temporary cwd/home and clean environment, reported as review. It does not isolate files, descendants or system calls. Windows terminates the immediate process only. Use an external VM/container for hostile packages. The whole run has a three-minute deadline; enumeration has 20 seconds. CPU/memory limits apply only to OCI containers.

OCI requires Docker. It pulls for metadata, then runs the immutable image ID with read-only root, non-root UID, no capabilities, no-new-privileges, bounded CPU/memory/PIDs and temporary `/tmp`. Networking is disabled unless `--net` is explicit. Container removal is attempted after enumeration/cancellation; the downloaded image remains cached. No host directories/credentials are mounted. Author/creation labels are publisher-controlled and do not reveal install history. Root-only images and missing runtime configuration fail enumeration.

A remote URL requires `--net`: Fencepost scans advertised definitions but cannot sandbox the remote execution or attest its code. Metadata and MCP redirects are refused. Existing HTTP/TLS scanner findings still apply.

## Maintainer baseline

New `pin` baselines record available package versions and maintainer identifiers in optional `packages` entries in `fencepost.lock`. Direct npx, uvx and Docker run launches are recognized, including common package selectors. Shell wrappers, custom package indexes and arbitrary executables have no inferred public-package identity. Failed metadata lookups print warnings without preventing tool pinning. `pin --update server/tool` preserves the original ownership baseline.

`vet --lock PATH` compares those identifiers with current metadata, even when the version is unchanged. Missing/old baselines are explicit. npm uses current registry maintainers; PyPI/OCI compare declared metadata only. This does not reconstruct ownership changes before pinning. Protect lockfiles and review full baseline replacements.

Formats follow the [official MCP registry API](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md), [PyPI JSON API](https://docs.pypi.org/api/json/), and [npm lifecycle documentation](https://docs.npmjs.com/cli/v11/using-npm/scripts/). Tests use local packages and stub metadata; Linux namespaces, Docker and live registries require separate host verification.
