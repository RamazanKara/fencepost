# AgentWorkflows through Fencepost

Register Fencepost as the team's MCP server in AgentWorkflows so both products apply their policies:

`agent → context.tool → AgentWorkflows gateway → Fencepost /mcp/NAME → upstream`

The [example agent](../examples/agentworkflows/agent.py) uses the existing `GatewayActivities` and `context.tool` APIs. Register `activities.call` on the Temporal worker and invoke `WorkflowGateway().agent("briefing", {"topic": "release notes"})` from its workflow. Set `AGENTWORKFLOWS_GATEWAY_URL` and `AGENTWORKFLOWS_API_KEY` in the worker.

1. Adapt [gateway.yaml](../examples/agentworkflows/gateway.yaml), [policy.yaml](../examples/agentworkflows/policy.yaml), and the upstream URLs. Start `fencepost gateway --config gateway.yaml` behind HTTPS.
2. Generate separate random secrets of at least 32 bytes for `RESEARCH_MCP_TOKEN` and `SUPPORT_MCP_TOKEN`. Set them in Fencepost and in the **AgentWorkflows gateway** environment. Keep them out of agent arguments and workflow history.
3. Merge [sandbox-policy.yaml](../examples/agentworkflows/sandbox-policy.yaml) into the research team's existing `SandboxPolicySet`. The tool is `documents.echo`, and its registered origin is Fencepost. For support, register `tickets.echo` with `SUPPORT_MCP_TOKEN` and the support team's workflow allowlist.
4. Research calls to documents allow; calls to tickets deny. Support calls to tickets wait in the [approval inbox](gateway.md#approval-inbox). Sign in with a member of `tool-approvers` and record a reason.
5. Inspect `fencepost log query --user research-worker --server documents` and AgentWorkflows' run-linked tool receipts.

Fencepost derives groups and client names from the configured key or signed issuer claims. Payload fields, initialization client names, and forwarded headers cannot grant group membership. A service key identifies a team worker, not the human initiating a run. Per-human identity requires resource-scoped OAuth tokens; this example uses team service keys because AgentWorkflows' registry accepts credentials through `credentialEnv`.

AgentWorkflows' current MCP adapter negotiates **2025-03-26**. Fencepost relays that initialization; use upstreams supporting that revision. The Compose echo servers support it. Fencepost does not translate arbitrary revisions. AgentWorkflows' tool costs, egress policies, retries and receipts still apply. Use upstream idempotency handling for writes; Fencepost does not make retries idempotent.

The examples follow the local AgentWorkflows SDK and registry documentation. A full deployment against Temporal, an external issuer and AgentWorkflows is not covered by Fencepost's tests. References: [MCP registry and agent callbacks](https://github.com/RamazanKara/agentworkflows/blob/main/docs/workflows.md#mcp-tools), [SDK reference](https://github.com/RamazanKara/agentworkflows/blob/main/docs/sdk-reference.md).
