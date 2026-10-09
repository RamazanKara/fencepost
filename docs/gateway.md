# Team gateway

`fencepost gateway --config gateway.yaml` serves `/mcp/NAME` for each upstream. It supervises a separate stdio process per authenticated user/client/group set and server, or relays Streamable HTTP. Crashed processes fail their calls and are not automatically restarted. Idle connections expire after 30 minutes when new traffic arrives; at most 256 identity/server connections are retained. Restart resets in-memory sessions, approvals and budgets.

Use an HTTPS reverse proxy in production. Bind the backend to a private interface and preserve the configured Host. Fencepost checks Host and Origin against `public_url`; forwarded identity headers are not trusted. Health is available at `/healthz` with that Host. The listener itself is HTTP. Restrict direct access to the backend and upstreams.

```yaml
listen: 127.0.0.1:8787
public_url: https://tools.example.com
policy:
  source: ./policies
  poll_interval: 1m
lock: ./fencepost.lock
auth:
  issuer: https://identity.example.com
  client_names:
    workflow-client-id: agentworkflows
  browser_client_id: fencepost-inbox
  browser_secret_env: FENCEPOST_INBOX_SECRET
  api_keys:
    - env: FENCEPOST_CI_KEY
      user: ci
      groups: [engineering]
      client: build
approval:
  groups: [tool-approvers]
servers:
  filesystem:
    command: /opt/mcp/filesystem
    args: [/workspace]
    env: {}
  remote:
    url: https://remote.example.com/mcp
    headers:
      Authorization: Bearer ${REMOTE_MCP_TOKEN}
```

Stdio receives the existing clean environment plus explicit `env`. Relative policy, lock and cwd paths resolve beside the gateway config. Pin direct upstreams before deployment. Remote credentials are separate configured credentials; user access tokens and cookies are stripped. Upstream environment references use the existing client-config resolver.

## Sign-in and identity

Fencepost is the OAuth protected resource; the issuer handles sign-in, consent and token issuance. MCP clients discover `/.well-known/oauth-protected-resource/mcp/NAME` through the 401 `WWW-Authenticate` challenge. Configure JWT **access tokens** with the full server URL in `aud`. Every request sends `Authorization: Bearer TOKEN`; query-string tokens are rejected.

OIDC discovery must name exactly the configured issuer and provide JWKS. RS256 (RSA ≥2048 bits), ES256 and EdDSA/Ed25519 are accepted. Signature, issuer, audience, required expiry, not-before and issued-at are checked. JWKS is cached for five minutes; unknown keys can trigger a rate-limited refresh. Invalid tokens receive 401. Opaque tokens/introspection are not supported.

`sub` is the user, `groups` a string array, and `client_id` (or `azp`) the client. `client_names` maps trusted IDs to policy names. Initialization's client name is descriptive only. The issuer must control group claims and issue tokens for these resources.

CI keys require at least 32 bytes from the named environment variable and explicit user/client. They use the Bearer header with constant-time hash comparison. Configure separate keys per team and restart after rotation. They are service identities.

See the [MCP authorization specification](https://modelcontextprotocol.io/specification/latest/basic/authorization). The client's OAuth flow and issuer registration/consent settings remain their responsibilities.

## Central policy

`policy.source` accepts a YAML file, directory, or HTTPS URL. Directories merge immediate `.yaml`/`.yml` files in lexical filename order. Maps merge recursively; later scalars and lists replace earlier values, including complete tool lists. Paths are relative to the directory. The final policy is strictly validated. `policy check --policy DIR` and `policy test --policy DIR --file audit.jsonl` use the same merge.

For remote policy, configure `public_key` as base64 of the 32-byte Ed25519 public key. The publisher returns `X-Fencepost-Signature` as base64 of the Ed25519 signature over **exact response bytes**, plus optional ETag. Polls send `If-None-Match`; 304 retains policy. Redirects, invalid signatures, oversized responses and invalid policies reject. Startup requires valid policy; refresh errors retain the last verified policy and report on stderr. Relative remote-policy paths resolve beside gateway config. HTTPS uses the system trust store.

Files/directories are polled too. Rules change on existing connections at the next check; pending approvals deny if policy changes. Unchanged content preserves approval state. Audit destinations open at startup: restart to change export settings. Signatures authenticate content but do not prevent replay of an older signed policy.

Tool rules support exact `users`, `groups`, `clients` lists. Each present list must be nonempty. Values within a list are ORed; lists are ANDed with the tool name. A nonmatching identity continues to the next rule. Use `default: deny`.

```yaml
version: 1
servers:
  remote:
    default: deny
    tools:
      - {name: read_*, action: allow, groups: [engineering], clients: [agentworkflows]}
```

## Approval inbox

Open `/approvals`. Register `PUBLIC_URL/callback` as the browser client's exact redirect URI. Enable authorization code with PKCE S256 and `openid`; issue its access tokens for `PUBLIC_URL/approvals`. Confidential clients use `browser_secret_env`; omit for registered public clients.

Sign-in uses browser-bound state, single-use callbacks, PKCE, issuer-response checks and HttpOnly SameSite cookies (Secure over HTTPS). Access tokens stay server-side and are revalidated on inbox requests. Only configured approver groups may view/decide. Approval POSTs require CSRF and a reason. The audit records approver and reason; competing decisions cannot approve twice. Timeouts deny. The page retains the last 256 completed requests; attribution remains in the audit.

Optional `approval.webhook_url` and `hmac_secret_env` send pending requests and an inbox URL to a chat bridge. Validate the HMAC-SHA256 `X-Fencepost-Signature` over the body, timestamp and nonce. This is notification only: responses cannot approve. Failed delivery is audited; requests still expire. Gateway asks use the inbox; standalone proxy approval behavior is unchanged.

## Audit export and policy dry runs

The authoritative chain and checkpoint remain required. Exports are bounded, best-effort copies; overflow/delivery failures are reported at shutdown.

```yaml
audit:
  path: /data/audit.jsonl
  stdout: true
  export_file: /data/export.jsonl
  max_bytes: 10485760
  backups: 5
  otlp_logs_endpoint: https://collector.example.com/v1/logs
  syslog: tls://logs.example.com:6514
  record_arguments: false
```

Exports carry complete JSON audit records. Rotation retains numbered backups without rotating the authoritative chain. Use one writer per export file. Syslog supports UDP, TCP with octet counting, and TLS with system certificate verification. UDP is unencrypted and large records can exceed its datagram limit. Existing `otlp_endpoint` trace exports remain supported. OTLP has no custom auth headers.

```sh
fencepost log query --file /data/audit.jsonl --user alice --server remote --tool read_file --decision allow --from 2026-10-09T00:00:00Z --until 2026-10-10T00:00:00Z
fencepost policy test --policy ./policies --file /data/audit.jsonl
```

Query filters are exact; time bounds inclusive. Both commands verify chain/checkpoint before output. Policy tests emit JSONL before/after changes and unknown evaluations, never invoke tools or change state. Exit 0 means the dry run completed (including changes); invalid input/logs return 2.

Arguments are omitted by default. Opt-in `record_arguments` stores sanitized arguments up to 16 KiB. This increases retained sensitive data; redaction is heuristic. Missing/redacted/oversized arguments produce unknown results where exact replay is impossible. Static decisions are recorded separately from approval outcomes. Rates, budgets, live pins and approvals are not simulated.

## Local packaging

`make image` builds `fencepost:0.4.0` locally with Docker/Linux containers and registry access to Go/distroless bases. It never pushes. The image has no shell or stdio executables; supply reviewed binaries or remote upstreams.

Set a random `FENCEPOST_CI_KEY` of at least 32 bytes and run `docker compose -f examples/gateway/docker-compose.yaml up --build`. Two echo servers share the gateway's network namespace and bind loopback. Call `http://127.0.0.1:8787/mcp/documents` with the key. Ticket calls intentionally ask; configure OIDC and an approver group to allow them. Audit persists in a named volume.

For `deploy/helm/fencepost`, load the local image into the cluster or configure your own registry image. Create `fencepost-config` Secret with `gateway.yaml`, policy and optional lock, and `fencepost-credentials` for environment secrets. Set `listen: 0.0.0.0:8787`, HTTPS `public_url`, and audit paths under `/data`.

```sh
helm template fencepost deploy/helm/fencepost
helm template fencepost deploy/helm/fencepost --set networkPolicy.enabled=true
helm template fencepost deploy/helm/fencepost --set persistence.enabled=true --set persistence.existingClaim=fencepost-audit
```

The chart runs non-root, with read-only root filesystem, dropped capabilities and no service-account token. Default storage is ephemeral; use an existing PVC for retention. NetworkPolicy is opt-in with no default egress: explicitly allow DNS, issuer/JWKS, policy, collectors and upstreams. Supply HTTPS Ingress separately. Multiple replicas are rejected because sessions and the inbox are local.

See [AgentWorkflows integration](agentworkflows.md) for per-team registrations.
