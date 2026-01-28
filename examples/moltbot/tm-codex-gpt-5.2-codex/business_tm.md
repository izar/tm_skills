# Project: Moltbot
## Structure
Moltbot consists of a CLI and an always-on Gateway (WS/HTTP) that broker messages between channel providers, model providers, and tool-capable nodes. The Gateway runs on a host with local state (config, credentials, sessions, transcripts, logs) and exposes control APIs to UIs/CLI and external API clients. Channel adapters normalize inbound/outbound messages; an agent runtime calls model providers and tools; optional node hosts and browser control servers handle tool execution.

## Apparent business case
Provide a unified automation assistant that connects chat channels and operator tools to LLMs, while persisting sessions and allowing remote control of the gateway for messaging, workflows, and tool execution.

## Findings
Counts by severity: Very High: 60, High: 166, Medium: 201, Low: 15, Very Low: 3

- [Very High] Buffer Manipulation (INP07) on Agent Runtime
- [Very High] Catching exception throw/signal from privileged block (AC14) on Agent Runtime
- [Very High] Cross Site Request Forgery (AC21) on Agent Runtime
- [Very High] File Content Injection (INP23) on Agent Runtime
- [Very High] Overflow Buffers (INP02) on Agent Runtime
- [High] Argument Injection (INP41) on Agent Runtime
- [High] Client-side Injection-induced Buffer Overflow (INP12) on Agent Runtime
- [High] Code Injection (INP26) on Agent Runtime
- [High] Command Delimiters (INP13) on Agent Runtime
- [High] Command Injection (INP31) on Agent Runtime
- [Medium] Authentication Abuse/ByPass (AA01) on Agent Runtime
- [Medium] Double Encoding (DE02) on Agent Runtime
- [Medium] Excessive Allocation (DO02) on Agent Runtime
- [Medium] Flooding (DO01) on Agent Runtime
- [Medium] Hijacking a privileged process (AC13) on Agent Runtime
