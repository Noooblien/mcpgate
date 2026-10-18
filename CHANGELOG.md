# Changelog

All notable changes to **MCPGate** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Declarative Zero-Trust Policy Engine (`pkg/policy`)**: Specification-driven policy evaluation engine with priority resolution, glob tool/agent matching, field-level argument constraints, and temporal execution windows.
- **Enterprise Policy Actions**: Support for `ALLOW`, `DENY`, `REQUIRE_APPROVAL` (Human-in-the-Loop / 2FA gate), and `FORCE_REDACTION` with dynamic per-rule rate limiting overrides.
- **Dynamic Hot-Reloading & Manifest Linter**: Thread-safe policy manifest swapping and syntax/logic linter (`mcpgate policy lint`).
- **CLI Subcommand & Scorecard Visualizations (`mcpgate policy`)**: Rich ANSI policy evaluation scorecards, demo suite (`--demo`), default policy dumping (`dump`), and Mermaid policy hierarchy flowcharts (`--mermaid`).
- **Adversarial Security Fuzzer & Exploit Neutralization Harness (`pkg/fuzz`)**: Automated attack generator evaluating 8 vulnerability classes (Prompt Injection, Command Injection, SSRF/Cloud Metadata, Path Traversal, Secret Exfiltration, Unicode Evasion, Recursive Loops, Buffer Overflow) and benign control baselines.
- **Resilience Scorecard & Mermaid Attack Surface Topology (`mcpgate fuzz`)**: Terminal ANSI scorecard formatting (`RenderFuzzScorecard`) and Mermaid pipeline diagrams (`RenderFuzzMermaid`).
- Sliding-window loop detector preventing infinite recursive tool-calls (OWASP-LLM08).
- Transparent HTTP and Server-Sent Events (SSE) MCP reverse proxy.
- Prometheus metrics collector for tool call latency, rate limit breaches, and error rates.

---

## [v0.1.0] - 2026-10-16

### Added
- Stdio MCP sub-process reverse proxy with JSON-RPC 2.0 streaming parser.
- Token bucket rate-limiter per agent/session.
- Role-Based Access Control (RBAC) tool firewall.
