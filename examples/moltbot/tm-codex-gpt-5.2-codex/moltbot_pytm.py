from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Process,
    Server,
)


tm = TM("Moltbot")
# High-level system model for the Moltbot CLI + Gateway + channels + nodes.
# TODO - refine asset owners and trust levels per deployment.
tm.description = (
    "Moltbot is a CLI + always-on Gateway that connects messaging channels, "
    "LLM providers, and tool-capable nodes. The Gateway exposes a WS/HTTP control plane, "
    "persists session state, and brokers inbound/outbound messages."
)

tm.isOrdered = True

# --- Trust boundaries ---
internet = Boundary("Internet")
control_clients = Boundary("Control Clients")
control_clients.inBoundary = internet

messaging_platforms = Boundary("Messaging Platforms")
model_providers = Boundary("Model Providers")
node_hosts = Boundary("Node Hosts")

local_host = Boundary("Gateway Host (Local)")
local_storage = Boundary("Gateway Local Storage")
local_storage.inBoundary = local_host

# --- Actors ---
operator = Actor("Operator")
operator.inBoundary = control_clients

end_user = Actor("Channel End User")
end_user.inBoundary = messaging_platforms

# --- External systems ---
channel_api = ExternalEntity("Channel Provider APIs")
channel_api.inBoundary = messaging_platforms

llm_api = ExternalEntity("LLM Provider APIs")
llm_api.inBoundary = model_providers

external_api_client = ExternalEntity("External API Client")
external_api_client.inBoundary = internet

# --- Core processes/servers ---
cli = Process("Moltbot CLI")
cli.inBoundary = control_clients
cli.sourceFiles = ["src/cli/run-main.ts", "src/cli/program/command-registry.ts"]

webchat_ui = Process("WebChat / macOS UI")
webchat_ui.inBoundary = control_clients
webchat_ui.sourceFiles = ["docs/gateway/index.md"]

# Gateway WS/HTTP server
gateway = Server("Gateway WS/HTTP Server")
gateway.inBoundary = local_host
gateway.sourceFiles = [
    "src/gateway/server.ts",
    "src/gateway/server.impl.ts",
    "src/gateway/server-http.ts",
]
# Gateway auth is token/password or identity (Tailscale) by config
# TODO - validate TLS usage per deployment
try:
    gateway.controls.authenticatesSource = True
    gateway.controls.authorizesSource = True
    gateway.controls.validatesInput = True
except Exception:
    pass

channel_adapters = Process("Channel Adapters")
channel_adapters.inBoundary = local_host
channel_adapters.sourceFiles = ["src/channels", "src/web/inbound/monitor.ts"]

agent_runtime = Process("Agent Runtime")
agent_runtime.inBoundary = local_host
agent_runtime.sourceFiles = ["src/auto-reply/reply/agent-runner.ts"]

browser_control = Server("Browser Control Server")
browser_control.inBoundary = local_host
browser_control.sourceFiles = ["src/gateway/server-browser.ts"]

node_host = Server("Node Host Agent")
node_host.inBoundary = node_hosts
node_host.sourceFiles = ["docs/nodes/index.md"]

# --- Datastores (local host) ---
config_store = Datastore("Config Store (moltbot.json)")
config_store.inBoundary = local_storage
config_store.sourceFiles = ["src/config", "docs/gateway/configuration.md"]

credentials_store = Datastore("Credentials Store (~/.clawdbot/credentials)")
credentials_store.inBoundary = local_storage
credentials_store.sourceFiles = ["docs/testing.md", "docs/gateway/authentication.md"]

session_store = Datastore("Session Store (sessions.json)")
session_store.inBoundary = local_storage
session_store.sourceFiles = ["src/config/sessions.ts", "docs/reference/session-management-compaction.md"]

transcript_store = Datastore("Transcript Store (*.jsonl)")
transcript_store.inBoundary = local_storage
transcript_store.sourceFiles = ["src/config/sessions.ts", "docs/reference/session-management-compaction.md"]

logs_store = Datastore("Log Store (~/.clawdbot/logs)")
logs_store.inBoundary = local_storage
logs_store.sourceFiles = ["docs/gateway/logging.md", "src/hooks/bundled/command-logger/handler.ts"]

plugin_store = Datastore("Plugin Store (~/.clawdbot/extensions)")
plugin_store.inBoundary = local_storage
plugin_store.sourceFiles = ["docs/plugin.md", "src/plugins"]

# --- Data ---
gateway_auth = Data(
    "Gateway Auth Token/Password",
    classification=Classification.SECRET,
    storedAt=[credentials_store],
)

channel_credentials = Data(
    "Channel Credentials (tokens/cookies)",
    classification=Classification.SECRET,
    storedAt=[credentials_store],
)

provider_credentials = Data(
    "Model Provider Credentials",
    classification=Classification.SECRET,
    storedAt=[credentials_store],
)

session_content = Data(
    "Session Messages + Tool Output",
    classification=Classification.RESTRICTED,
    storedAt=[session_store, transcript_store],
)

media_content = Data(
    "Inbound/Outbound Media Attachments",
    classification=Classification.RESTRICTED,
)

config_data = Data(
    "Runtime Configuration",
    classification=Classification.SENSITIVE,
    storedAt=[config_store],
)

logs_data = Data(
    "Operational Logs",
    classification=Classification.SENSITIVE,
    storedAt=[logs_store],
)

tool_invocation = Data(
    "Tool Invocation Requests/Results",
    classification=Classification.RESTRICTED,
)

# --- Dataflows ---
# Operator control plane
operator_to_cli = Dataflow(
    operator,
    cli,
    "Operator runs CLI commands",
    protocol="local",
    data=config_data,
)

cli_to_gateway = Dataflow(
    cli,
    gateway,
    "CLI connects to Gateway WS/HTTP",
    protocol="WebSocket/HTTP",
    dstPort=18789,
    data=gateway_auth,
)

# UI clients to gateway
webchat_to_gateway = Dataflow(
    webchat_ui,
    gateway,
    "UI connects to Gateway WS",
    protocol="WebSocket",
    dstPort=18789,
    data=gateway_auth,
)

# External API clients (OpenAI-compatible + tools invoke)
external_api_to_gateway = Dataflow(
    external_api_client,
    gateway,
    "External client uses Gateway HTTP APIs",
    protocol="HTTP",
    dstPort=18789,
    data=session_content,
)

# Messaging channels inbound/outbound
end_user_to_channel = Dataflow(
    end_user,
    channel_api,
    "End user sends channel message",
    protocol="provider-specific",
    data=session_content,
)

channel_to_gateway = Dataflow(
    channel_api,
    channel_adapters,
    "Inbound channel events to Gateway",
    protocol="provider-specific",
    data=session_content,
)

channel_adapters_to_gateway = Dataflow(
    channel_adapters,
    gateway,
    "Normalized inbound messages",
    protocol="local",
    data=session_content,
)

gateway_to_channel = Dataflow(
    channel_adapters,
    channel_api,
    "Outbound messages to channels",
    protocol="provider-specific",
    data=session_content,
)

# LLM provider calls
agent_to_llm = Dataflow(
    agent_runtime,
    llm_api,
    "Model inference request",
    protocol="HTTPS",
    data=provider_credentials,
)

llm_to_agent = Dataflow(
    llm_api,
    agent_runtime,
    "Model inference response",
    protocol="HTTPS",
    data=session_content,
)

# Gateway <-> agent runtime
gateway_to_agent = Dataflow(
    gateway,
    agent_runtime,
    "Dispatch session to agent runtime",
    protocol="local",
    data=session_content,
)

agent_to_gateway = Dataflow(
    agent_runtime,
    gateway,
    "Agent output + tool results",
    protocol="local",
    data=session_content,
)

# Local persistence
gateway_to_config = Dataflow(
    gateway,
    config_store,
    "Read/write configuration",
    protocol="file",
    data=config_data,
)

gateway_to_credentials = Dataflow(
    gateway,
    credentials_store,
    "Read/write credentials",
    protocol="file",
    data=provider_credentials,
)

gateway_to_sessions = Dataflow(
    gateway,
    session_store,
    "Update session metadata",
    protocol="file",
    data=session_content,
)

gateway_to_transcripts = Dataflow(
    gateway,
    transcript_store,
    "Append transcripts",
    protocol="file",
    data=session_content,
)

gateway_to_logs = Dataflow(
    gateway,
    logs_store,
    "Write operational logs",
    protocol="file",
    data=logs_data,
)

# Node tools and browser control
agent_to_node = Dataflow(
    agent_runtime,
    node_host,
    "Invoke node tools",
    protocol="WebSocket",
    data=tool_invocation,
)

node_to_agent = Dataflow(
    node_host,
    agent_runtime,
    "Node tool responses",
    protocol="WebSocket",
    data=tool_invocation,
)

agent_to_browser = Dataflow(
    agent_runtime,
    browser_control,
    "Browser control requests",
    protocol="HTTP/WebSocket",
    data=tool_invocation,
)

browser_to_agent = Dataflow(
    browser_control,
    agent_runtime,
    "Browser control responses",
    protocol="HTTP/WebSocket",
    data=tool_invocation,
)

# Media pipeline (simplified)
channel_media_to_gateway = Dataflow(
    channel_api,
    channel_adapters,
    "Inbound media to Gateway",
    protocol="provider-specific",
    data=media_content,
)

agent_media_to_channel = Dataflow(
    channel_adapters,
    channel_api,
    "Outbound media to channels",
    protocol="provider-specific",
    data=media_content,
)

# Track data traversals
Data(
    name="Conversation Context",
    classification=Classification.RESTRICTED,
    traverses=[
        channel_to_gateway,
        channel_adapters_to_gateway,
        gateway_to_agent,
        agent_to_gateway,
        gateway_to_channel,
    ],
    storedAt=[session_store, transcript_store],
)

if __name__ == "__main__":
    tm.process()
