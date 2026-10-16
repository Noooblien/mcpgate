# Changelog

All notable changes to **MCPGate** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Sliding-window loop detector preventing infinite recursive tool-calls (OWASP-LLM08).
- Transparent HTTP and Server-Sent Events (SSE) MCP reverse proxy.
- Prometheus metrics collector for tool call latency, rate limit breaches, and error rates.

---

## [v0.1.0] - 2026-10-16

### Added
- Stdio MCP sub-process reverse proxy with JSON-RPC 2.0 streaming parser.
- Token bucket rate-limiter per agent/session.
- Role-Based Access Control (RBAC) tool firewall.
