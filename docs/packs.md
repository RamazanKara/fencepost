# Policy packs

```sh
fencepost init --pack filesystem,git --policy fencepost.yaml
fencepost policy check --policy fencepost.yaml
```

Composition merges distinct server maps with deny defaults, secret redaction, a 1 MiB output limit and injection blocking. Packs are embedded and work offline. `init` refuses to overwrite files. Unknown/duplicate names and combining `--server` with `--pack` fail.

| Pack / server | Normal calls allowed | Examples denied |
| --- | --- | --- |
| filesystem | `read_file`, `list_directory`: absolute `path` under `./workspace` | Writes/deletes and outside-root reads |
| git | `git_status`, `git_log`: absolute `repo_path` under `./workspace` | Reset, commit, push, outside repositories |
| fetch | `fetch`: `url` at exactly `example.com` | Other hosts, loopback/private IPs, upload tools |
| browser | `browser_navigate` at `example.com`, `browser_snapshot` | Evaluation, clicks, form filling, other hosts |
| database | `list_tables`; `read_query` with exactly `SELECT 1` or `SELECT current_timestamp` | Other SQL, stacked statements, writes |
| shell | `run_command`: exactly `pwd` or `whoami` | Chaining, substitutions, other executables |
| cloud | `run_command`: exactly `aws sts get-caller-identity`, `az account show`, `gcloud config list` | Mutations, credential exports, other commands |

Create `workspace` beside the policy. Replace example hosts and exact queries/commands with reviewed values; match server, tool and argument names to the actual server. These narrow policies do not infer aliases or schemas. Arbitrary SELECT prefixes are unsafe because queries can still mutate/exfiltrate data, so database examples use exact queries.

Policies constrain tool arguments, not system calls. Use OS isolation and backend read-only credentials. See the [policy reference](policy.md) for first-match ordering, path/host restrictions and replay limits. `go test ./packs` proves each normal call passes and dangerous calls/arguments and missing required arguments deny. E2e also validates every pack against the policy schema.
