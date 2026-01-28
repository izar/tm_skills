#!/usr/bin/env python3
"""
PyTM Threat Model for Moltbot
A multi-channel AI assistant gateway that connects various messaging platforms
to LLM providers (primarily Claude) with local tool execution capabilities.
"""

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Lambda,
    Process,
    Server,
    DatastoreType,
)

# Initialize the threat model
tm = TM("Moltbot Threat Model")
tm.description = """Moltbot is a multi-channel AI assistant gateway that bridges messaging platforms
(Discord, Telegram, Slack, WhatsApp, Signal, iMessage, etc.) to LLM providers (Anthropic Claude, OpenAI, etc.).
It runs as a local daemon/gateway on user devices (macOS, Linux, Windows) and enables AI-assisted
conversations with tool execution capabilities including bash commands, browser automation, and file operations.
The system handles sensitive credentials, user conversations, and executes code on the local machine."""

tm.isOrdered = True
tm.mergeResponses = True
tm.assumptions = [
    "Gateway runs on a trusted local device owned by the user",
    "Local file system permissions are properly configured (user-only access to ~/.moltbot/)",
    "Network access is restricted to loopback by default unless explicitly configured",
    "Users understand the security implications of enabling tool execution",
    "Channel API tokens are obtained legitimately by the user",
    "LLM provider API keys are kept confidential",
]

# =============================================================================
# TRUST BOUNDARIES
# =============================================================================

internet = Boundary("Internet/External")
internet.description = "Untrusted external network and third-party services"

local_network = Boundary("Local Network")
local_network.description = "LAN or Tailscale network (semi-trusted)"

local_host = Boundary("Local Host")
local_host.description = "Localhost/loopback (trusted)"

user_space = Boundary("User Space")
user_space.description = "User's local applications and data"
user_space.levels = [1]

gateway_boundary = Boundary("Gateway Process")
gateway_boundary.description = "Moltbot gateway server process boundary"
gateway_boundary.levels = [2]

agent_sandbox = Boundary("Agent Sandbox")
agent_sandbox.description = "Isolated execution environment for tool calls"
agent_sandbox.levels = [3]

# =============================================================================
# ACTORS
# =============================================================================

end_user = Actor("End User")
end_user.description = "Human user interacting via messaging channels or CLI"
end_user.inBoundary = internet
end_user.levels = [1, 2]

device_owner = Actor("Device Owner")
device_owner.description = "Owner/administrator of the device running Moltbot"
device_owner.inBoundary = user_space

channel_user = Actor("Channel User")
channel_user.description = "External user sending messages via channels (may be untrusted)"
channel_user.inBoundary = internet
channel_user.levels = [1]

# =============================================================================
# EXTERNAL ENTITIES (Third-Party Services)
# =============================================================================

anthropic_api = ExternalEntity("Anthropic Claude API")
anthropic_api.description = "Anthropic's Claude LLM API service"
anthropic_api.inBoundary = internet
anthropic_api.protocol = "HTTPS"
anthropic_api.port = 443
# TODO - find the real value for this attribute
anthropic_api.controls.authenticatesDestination = True

openai_api = ExternalEntity("OpenAI API")
openai_api.description = "OpenAI's GPT API service"
openai_api.inBoundary = internet
openai_api.protocol = "HTTPS"
openai_api.port = 443

discord_api = ExternalEntity("Discord API")
discord_api.description = "Discord bot API and gateway"
discord_api.inBoundary = internet
discord_api.protocol = "HTTPS/WSS"
discord_api.port = 443
discord_api.sourceFiles = ["src/discord/"]

telegram_api = ExternalEntity("Telegram Bot API")
telegram_api.description = "Telegram bot HTTP API"
telegram_api.inBoundary = internet
telegram_api.protocol = "HTTPS"
telegram_api.port = 443
telegram_api.sourceFiles = ["src/telegram/"]

slack_api = ExternalEntity("Slack API")
slack_api.description = "Slack Bolt framework API"
slack_api.inBoundary = internet
slack_api.protocol = "HTTPS"
slack_api.port = 443
slack_api.sourceFiles = ["src/slack/"]

whatsapp_web = ExternalEntity("WhatsApp Web")
whatsapp_web.description = "WhatsApp Web protocol via Baileys library"
whatsapp_web.inBoundary = internet
whatsapp_web.protocol = "WSS"
whatsapp_web.port = 443
whatsapp_web.sourceFiles = ["src/web/"]

signal_daemon = ExternalEntity("Signal CLI Daemon")
signal_daemon.description = "Signal-cli daemon for Signal protocol"
signal_daemon.inBoundary = local_host
signal_daemon.protocol = "JSON-RPC"
signal_daemon.sourceFiles = ["src/signal/"]

imessage_service = ExternalEntity("iMessage Service")
imessage_service.description = "Apple iMessage via local protocol"
imessage_service.inBoundary = local_host
imessage_service.sourceFiles = ["src/imessage/"]

tailscale_service = ExternalEntity("Tailscale")
tailscale_service.description = "Tailscale VPN for remote gateway access"
tailscale_service.inBoundary = local_network
tailscale_service.protocol = "WireGuard"
tailscale_service.sourceFiles = ["src/infra/tailscale.ts"]

# =============================================================================
# SERVERS
# =============================================================================

gateway_server = Server("Moltbot Gateway")
gateway_server.description = "Main gateway server handling WebSocket/HTTP connections"
gateway_server.OS = "Cross-platform (macOS/Linux/Windows)"
gateway_server.inBoundary = gateway_boundary
gateway_server.protocol = "WebSocket/HTTP"
gateway_server.port = 18789
gateway_server.controls.isHardened = True
gateway_server.controls.sanitizesInput = True
gateway_server.controls.encodesOutput = True
gateway_server.controls.authorizesSource = True
gateway_server.controls.hasAccessControl = True
gateway_server.sourceFiles = [
    "src/gateway/server.impl.ts",
    "src/gateway/auth.ts",
    "src/gateway/server-methods/",
]
# Gateway binds to loopback by default, network binding requires explicit configuration

cli_client = Server("CLI Client")
cli_client.description = "Command-line interface for interacting with Moltbot"
cli_client.inBoundary = user_space
cli_client.sourceFiles = ["src/cli/", "src/entry.ts"]
cli_client.controls.sanitizesInput = True

macos_app = Server("macOS Menu Bar App")
macos_app.description = "Native macOS companion app with Voice Wake and Talk Mode"
macos_app.OS = "macOS"
macos_app.inBoundary = user_space
macos_app.sourceFiles = ["apps/macos/"]
macos_app.controls.hasAccessControl = True

mobile_app = Server("Mobile Apps (iOS/Android)")
mobile_app.description = "Native mobile companion apps"
mobile_app.inBoundary = local_network
mobile_app.sourceFiles = ["apps/ios/", "apps/android/"]
mobile_app.controls.authenticatesDestination = True

# =============================================================================
# PROCESSES
# =============================================================================

agent_runtime = Process("Agent Runtime")
agent_runtime.description = "Pi embedded agent runner executing LLM inference and tool calls"
agent_runtime.inBoundary = gateway_boundary
agent_runtime.sourceFiles = ["src/agents/pi-embedded-runner/", "src/agents/"]
agent_runtime.controls.sanitizesInput = True
agent_runtime.controls.hasAccessControl = True

bash_executor = Process("Bash Tool Executor")
bash_executor.description = "Executes bash commands from agent tool calls"
bash_executor.inBoundary = agent_sandbox
bash_executor.sourceFiles = ["src/agents/bash-tools.exec.ts", "src/agents/bash-tools.process.ts"]
bash_executor.controls.hasAccessControl = True
# TODO - find the real value for this attribute
bash_executor.controls.isHardened = False  # Depends on sandbox configuration

exec_approval_manager = Process("Execution Approval Manager")
exec_approval_manager.description = "Manages approval workflow for sensitive tool executions"
exec_approval_manager.inBoundary = gateway_boundary
exec_approval_manager.sourceFiles = [
    "src/infra/exec-approvals.ts",
    "src/gateway/exec-approval-manager.ts",
]
exec_approval_manager.controls.hasAccessControl = True

channel_router = Process("Channel Router")
channel_router.description = "Routes inbound messages to appropriate agents/sessions"
channel_router.inBoundary = gateway_boundary
channel_router.sourceFiles = ["src/routing/resolve-route.ts", "src/routing/"]
channel_router.controls.sanitizesInput = True

plugin_loader = Process("Plugin Loader")
plugin_loader.description = "Discovers, loads, and manages extension plugins"
plugin_loader.inBoundary = gateway_boundary
plugin_loader.sourceFiles = ["src/plugins/loader.ts", "src/plugins/discovery.ts"]
# TODO - find the real value for this attribute
plugin_loader.controls.hasAccessControl = False

media_processor = Process("Media Processor")
media_processor.description = "Downloads, converts, and stores media attachments"
media_processor.inBoundary = gateway_boundary
media_processor.sourceFiles = ["src/media/fetch.ts", "src/media/store.ts", "src/media/image-ops.ts"]
media_processor.controls.sanitizesInput = True

# =============================================================================
# LAMBDA/SCHEDULED PROCESSES
# =============================================================================

cron_service = Lambda("Cron Service")
cron_service.description = "Scheduled task execution service"
cron_service.inBoundary = gateway_boundary
cron_service.sourceFiles = ["src/cron/", "src/gateway/server-cron.ts"]
cron_service.controls.hasAccessControl = True

update_checker = Lambda("Update Checker")
update_checker.description = "Periodically checks for CLI updates"
update_checker.inBoundary = gateway_boundary
update_checker.sourceFiles = ["src/infra/update-check.ts"]

health_monitor = Lambda("Health Monitor")
health_monitor.description = "Periodic health checks and maintenance"
health_monitor.inBoundary = gateway_boundary
health_monitor.sourceFiles = ["src/gateway/server-maintenance.ts"]

# =============================================================================
# DATASTORES
# =============================================================================

config_store = Datastore("Config Store")
config_store.description = "Main configuration file (~/.moltbot/config.json)"
config_store.type = DatastoreType.FILE_SYSTEM
config_store.inBoundary = user_space
config_store.inScope = True
config_store.maxClassification = Classification.RESTRICTED
config_store.sourceFiles = ["src/config/io.ts", "src/config/schema.ts"]
config_store.controls.isEncrypted = False
config_store.controls.hasAccessControl = True

credential_store = Datastore("Credential Store")
credential_store.description = "Channel tokens and API keys (~/.moltbot/credentials/)"
credential_store.type = DatastoreType.FILE_SYSTEM
credential_store.inBoundary = user_space
credential_store.inScope = True
credential_store.storesCredentials = True
credential_store.maxClassification = Classification.SECRET
credential_store.sourceFiles = ["src/infra/device-auth-store.ts"]
credential_store.controls.hasAccessControl = True
# TODO - find the real value for this attribute
credential_store.controls.isEncrypted = False  # File permissions only

session_store = Datastore("Session Store")
session_store.description = "Conversation history (~/.moltbot/sessions/)"
session_store.type = DatastoreType.FILE_SYSTEM
session_store.inBoundary = user_space
session_store.inScope = True
session_store.storesPII = True
session_store.maxClassification = Classification.RESTRICTED
session_store.sourceFiles = ["src/sessions/", "src/gateway/session-utils.fs.ts"]
session_store.controls.hasAccessControl = True

whatsapp_auth_store = Datastore("WhatsApp Auth Store")
whatsapp_auth_store.description = "WhatsApp Web authentication state (Baileys)"
whatsapp_auth_store.type = DatastoreType.FILE_SYSTEM
whatsapp_auth_store.inBoundary = user_space
whatsapp_auth_store.storesCredentials = True
whatsapp_auth_store.maxClassification = Classification.SECRET
whatsapp_auth_store.sourceFiles = ["src/web/session.ts"]

runtime_state = Datastore("Runtime State")
runtime_state.description = "In-memory gateway state"
runtime_state.type = DatastoreType.UNKNOWN  # In-memory state
runtime_state.inBoundary = gateway_boundary
runtime_state.sourceFiles = ["src/gateway/server-runtime-state.ts"]

# =============================================================================
# DATA ASSETS
# =============================================================================

api_credentials = Data(
    "API Credentials",
    description="LLM provider API keys (Anthropic, OpenAI, etc.)",
    classification=Classification.SECRET,
    storedAt=[credential_store],
    isPII=False,
    isCredentials=True,
)

channel_tokens = Data(
    "Channel Auth Tokens",
    description="Bot tokens for Discord, Telegram, Slack, etc.",
    classification=Classification.SECRET,
    storedAt=[credential_store],
    isCredentials=True,
)

user_messages = Data(
    "User Messages",
    description="Inbound messages from users via channels",
    classification=Classification.RESTRICTED,
    createdAt=[channel_user],
    storedAt=[session_store],
    isPII=True,
)

agent_responses = Data(
    "Agent Responses",
    description="LLM-generated responses to user queries",
    classification=Classification.RESTRICTED,
    storedAt=[session_store],
)

tool_commands = Data(
    "Tool Commands",
    description="Bash commands and other tool invocations from agent",
    classification=Classification.RESTRICTED,
    transformedAt=[agent_runtime],
)

tool_output = Data(
    "Tool Execution Output",
    description="Output from bash commands and tool executions",
    classification=Classification.RESTRICTED,
)

config_data = Data(
    "Configuration Data",
    description="Gateway and agent configuration settings",
    classification=Classification.RESTRICTED,
    storedAt=[config_store],
)

media_content = Data(
    "Media Content",
    description="Images, audio, video attachments from messages",
    classification=Classification.RESTRICTED,
    transformedAt=[media_processor],
)

whatsapp_session = Data(
    "WhatsApp Session Data",
    description="WhatsApp Web authentication keys and session state",
    classification=Classification.SECRET,
    storedAt=[whatsapp_auth_store],
    isCredentials=True,
)

# =============================================================================
# DATAFLOWS
# =============================================================================

# --- User to Gateway flows ---

cli_to_gateway = Dataflow(
    cli_client,
    gateway_server,
    "CLI commands to gateway",
    protocol="WebSocket",
    dstPort=18789,
    data=user_messages,
    note="Local CLI client sends commands and messages to gateway",
)

macos_to_gateway = Dataflow(
    macos_app,
    gateway_server,
    "macOS app to gateway",
    protocol="WebSocket",
    dstPort=18789,
    data=user_messages,
    note="macOS menu bar app controls gateway via WebSocket",
)

mobile_to_gateway = Dataflow(
    mobile_app,
    gateway_server,
    "Mobile app to gateway",
    protocol="WebSocket",
    dstPort=18789,
    data=user_messages,
    note="iOS/Android apps connect to gateway over network",
)

# --- Channel inbound flows ---

discord_inbound = Dataflow(
    discord_api,
    gateway_server,
    "Discord messages inbound",
    protocol="WSS",
    srcPort=443,
    data=user_messages,
    note="Bot receives messages from Discord via WebSocket gateway",
)

telegram_inbound = Dataflow(
    telegram_api,
    gateway_server,
    "Telegram messages inbound",
    protocol="HTTPS",
    srcPort=443,
    data=user_messages,
    note="Bot receives messages from Telegram via long polling or webhook",
)

slack_inbound = Dataflow(
    slack_api,
    gateway_server,
    "Slack messages inbound",
    protocol="HTTPS/WSS",
    srcPort=443,
    data=user_messages,
    note="Bot receives messages from Slack via Bolt framework",
)

whatsapp_inbound = Dataflow(
    whatsapp_web,
    gateway_server,
    "WhatsApp messages inbound",
    protocol="WSS",
    srcPort=443,
    data=user_messages,
    note="Messages received via WhatsApp Web protocol (Baileys)",
)

signal_inbound = Dataflow(
    signal_daemon,
    gateway_server,
    "Signal messages inbound",
    protocol="JSON-RPC",
    data=user_messages,
    note="Messages from Signal via signal-cli daemon",
)

# --- Gateway to LLM Provider flows ---

gateway_to_anthropic = Dataflow(
    gateway_server,
    anthropic_api,
    "LLM inference requests to Claude",
    protocol="HTTPS",
    dstPort=443,
    data=user_messages,
    note="Gateway sends conversation context to Claude API",
)

anthropic_to_gateway = Dataflow(
    anthropic_api,
    gateway_server,
    "LLM responses from Claude",
    protocol="HTTPS",
    srcPort=443,
    data=agent_responses,
    responseTo=gateway_to_anthropic,
    note="Claude API streams responses back to gateway",
)

gateway_to_openai = Dataflow(
    gateway_server,
    openai_api,
    "LLM inference requests to OpenAI",
    protocol="HTTPS",
    dstPort=443,
    data=user_messages,
    note="Gateway sends requests to OpenAI-compatible endpoints",
)

# --- Internal gateway flows ---

gateway_to_agent = Dataflow(
    gateway_server,
    agent_runtime,
    "Message to agent runtime",
    data=user_messages,
    note="Gateway dispatches messages to agent runtime for processing",
)

agent_to_bash = Dataflow(
    agent_runtime,
    bash_executor,
    "Tool execution request",
    data=tool_commands,
    note="Agent requests bash command execution",
)

bash_to_agent = Dataflow(
    bash_executor,
    agent_runtime,
    "Tool execution result",
    data=tool_output,
    responseTo=agent_to_bash,
    note="Bash executor returns command output to agent",
)

agent_to_approval = Dataflow(
    agent_runtime,
    exec_approval_manager,
    "Approval request for sensitive command",
    data=tool_commands,
    note="Agent requests user approval for sensitive operations",
)

approval_to_user = Dataflow(
    exec_approval_manager,
    device_owner,
    "Approval prompt to user",
    data=tool_commands,
    note="User prompted to approve/reject sensitive command",
)

# --- Channel outbound flows ---

gateway_to_discord = Dataflow(
    gateway_server,
    discord_api,
    "Discord messages outbound",
    protocol="HTTPS",
    dstPort=443,
    data=agent_responses,
    note="Gateway sends responses to Discord via API",
)

gateway_to_telegram = Dataflow(
    gateway_server,
    telegram_api,
    "Telegram messages outbound",
    protocol="HTTPS",
    dstPort=443,
    data=agent_responses,
    note="Gateway sends responses to Telegram via Bot API",
)

gateway_to_slack = Dataflow(
    gateway_server,
    slack_api,
    "Slack messages outbound",
    protocol="HTTPS",
    dstPort=443,
    data=agent_responses,
    note="Gateway sends responses to Slack via API",
)

gateway_to_whatsapp = Dataflow(
    gateway_server,
    whatsapp_web,
    "WhatsApp messages outbound",
    protocol="WSS",
    dstPort=443,
    data=agent_responses,
    note="Gateway sends responses via WhatsApp Web protocol",
)

# --- Credential flows ---

cred_to_gateway = Dataflow(
    credential_store,
    gateway_server,
    "Load credentials",
    data=api_credentials,
    note="Gateway loads API keys and tokens from credential store",
)

gateway_to_session = Dataflow(
    gateway_server,
    session_store,
    "Persist conversation",
    data=user_messages,
    note="Gateway persists conversation history to session store",
)

session_to_gateway = Dataflow(
    session_store,
    gateway_server,
    "Load conversation history",
    data=user_messages,
    responseTo=gateway_to_session,
    note="Gateway loads previous conversation context",
)

# --- Configuration flows ---

config_to_gateway = Dataflow(
    config_store,
    gateway_server,
    "Load configuration",
    data=config_data,
    note="Gateway loads configuration on startup and reload",
)

cli_to_config = Dataflow(
    cli_client,
    config_store,
    "Update configuration",
    data=config_data,
    note="CLI writes configuration changes to config store",
)

# --- Media flows ---

channel_media_download = Dataflow(
    whatsapp_web,
    media_processor,
    "Download media attachments",
    data=media_content,
    note="Media processor downloads attachments from channels",
)

media_to_agent = Dataflow(
    media_processor,
    agent_runtime,
    "Processed media to agent",
    data=media_content,
    note="Media processor provides images/files to agent runtime",
)

# --- Plugin flows ---

plugin_to_gateway = Dataflow(
    plugin_loader,
    gateway_server,
    "Plugin registration",
    note="Plugins register hooks and capabilities with gateway",
)

# --- Tailscale flows ---

tailscale_to_gateway = Dataflow(
    tailscale_service,
    gateway_server,
    "Remote access via Tailscale",
    protocol="WireGuard",
    data=user_messages,
    note="Remote clients connect to gateway via Tailscale tunnel",
)


if __name__ == "__main__":
    tm.process()
