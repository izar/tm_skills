# Project: Moltbot

## Structure

Moltbot is a multi-channel AI assistant gateway application built with TypeScript/Node.js. The architecture follows a hub-and-spoke pattern with a central gateway server that bridges multiple messaging platforms to LLM providers.

**Core Components:**
- **Gateway Server** (`src/gateway/`): Central WebSocket/HTTP server (port 18789) handling all client connections, authentication, and message routing
- **CLI Client** (`src/cli/`, `src/entry.ts`): Command-line interface for local interaction and configuration
- **Channel Integrations** (`src/discord/`, `src/telegram/`, `src/slack/`, `src/web/`, `src/signal/`, `src/imessage/`): Adapters for each messaging platform
- **Agent Runtime** (`src/agents/`): LLM inference engine with tool execution capabilities
- **Plugin System** (`src/plugins/`, `extensions/`): Extensibility layer for custom integrations
- **Configuration Store** (`src/config/`): File-based configuration management (~/.moltbot/)

**Companion Applications:**
- macOS Menu Bar App (`apps/macos/`)
- iOS/Android Apps (`apps/ios/`, `apps/android/`)

**Data Storage:**
- Configuration: `~/.moltbot/config.json`
- Credentials: `~/.moltbot/credentials/`
- Sessions: `~/.moltbot/sessions/`

## Apparent business case

Moltbot enables users to interact with AI assistants (primarily Claude) through their existing messaging platforms. The system serves several use cases:

1. **Personal AI Assistant**: Users can chat with Claude via WhatsApp, Telegram, Discord, or other messaging apps they already use daily
2. **Tool Execution**: The assistant can execute bash commands, browse the web, manipulate files, and perform other automated tasks on the user's behalf
3. **Multi-Device Access**: Users can access their AI assistant from any device through the messaging platform of their choice, or via companion apps
4. **Extensibility**: Organizations or power users can extend functionality through plugins for custom integrations (MS Teams, Matrix, etc.)
5. **Privacy-Focused**: Runs locally on user devices rather than cloud-hosted, keeping conversation history and credentials under user control

## Findings

The PyTM analysis identified **611 potential threats** across the system:

### Severity Distribution
| Severity | Count |
|----------|-------|
| Very High | 78 |
| High | 246 |
| Medium | 268 |
| Low | 16 |
| Very Low | 3 |

### Critical Threat Categories (Very High Severity)

**1. Data Leak (DS06) - 28 instances**
- Risk: Sensitive data (API keys, credentials, conversation history) transmitted without adequate protection
- Affected: All dataflows, especially credential loading and LLM API calls
- Mitigation: Encrypt all data in transit (TLS), encrypt sensitive data at rest, implement secure credential storage

**2. Session Hijacking (AC17, AC18) - 10 instances**
- Risk: Attackers could capture session tokens via XSS or network interception
- Affected: Gateway server, Agent Runtime
- Mitigation: Cryptographic session tokens, secure token transmission, session timeout policies

**3. Cross-Site Request Forgery (AC21) - 6 instances**
- Risk: Malicious requests could be executed on behalf of authenticated users
- Affected: Gateway server HTTP endpoints
- Mitigation: CSRF tokens, SameSite cookies, origin validation

**4. Buffer/Overflow Vulnerabilities (INP02, INP07) - 12 instances**
- Risk: Memory corruption through malicious input
- Affected: Agent Runtime, input processing
- Mitigation: Input validation, bounds checking, use of memory-safe constructs

**5. Command Injection (INP05, INP31) - 10 instances**
- Risk: Arbitrary command execution through unsanitized input
- Affected: Gateway server, bash tool executor
- Mitigation: Input sanitization, parameterized commands, sandboxed execution

**6. XSS Attacks (SC02, INP28) - 14 instances**
- Risk: Malicious scripts injected through user-controlled content
- Affected: Gateway server, web interfaces
- Mitigation: Output encoding, Content Security Policy, input validation

**7. Path Traversal (HA01) - 2 instances**
- Risk: Unauthorized file access through manipulated paths
- Affected: File operations, media processing
- Mitigation: Path canonicalization, access control, chroot/sandboxing

**8. Malicious File Upload (AC06) - 3 instances**
- Risk: Execution of uploaded malicious content
- Affected: Media processor, attachment handling
- Mitigation: File type validation, sandboxed processing, principle of least privilege

### High-Priority Dataflow Risks

| Dataflow | Primary Risks |
|----------|--------------|
| CLI commands to gateway | Data leak, credential exposure |
| Channel messages inbound | Injection attacks, malicious content |
| Gateway to LLM providers | API key exposure, data leak |
| Credential store access | Credential theft, unauthorized access |
| Tool execution requests | Command injection, privilege escalation |
| Media downloads | Malicious files, content injection |

### Key Security Controls Identified

The threat model recognizes several existing security controls:
- Gateway authentication (token/password/Tailscale identity)
- Loopback-only binding by default
- Input sanitization on gateway and channel router
- Execution approval workflow for sensitive commands
- Access control on datastores (file permissions)

### Recommended Security Improvements

1. **Credential Encryption**: Add at-rest encryption for `~/.moltbot/credentials/`
2. **TLS Everywhere**: Ensure all internal communications use TLS when crossing trust boundaries
3. **Sandbox Hardening**: Strengthen Docker/container isolation for bash tool execution
4. **CSRF Protection**: Implement CSRF tokens on all HTTP endpoints
5. **Session Management**: Add session expiration and rotation policies
6. **Input Validation**: Strengthen validation on all channel inbound paths
7. **Audit Logging**: Expand security audit logging for sensitive operations
8. **Plugin Isolation**: Implement stronger isolation between plugins and core runtime
