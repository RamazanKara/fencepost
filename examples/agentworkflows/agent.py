import os

from agentworkflows.activities import GatewayActivities


async def briefing(context, arguments):
    return await context.tool("documents.echo", {"text": arguments["topic"]})


activities = GatewayActivities(
    os.environ["AGENTWORKFLOWS_GATEWAY_URL"],
    os.environ["AGENTWORKFLOWS_API_KEY"],
    agents={"briefing": briefing},
)
