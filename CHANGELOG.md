# Changelog

All notable changes to **MCPGate** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Cryptographic Tool Provenance, Mutual Request Signing & Non-Repudiation Engine (`pkg/provenance`)**: End-to-end zero-trust request signing with Ed25519 digital signatures, canonical JSON argument hashing, and tamper-proof verification (`mcpgate provenance`).
- **Gateway Execution Attestation Receipts**: Mints cryptographically signed, verifiable Execution Attestation Receipts linking request signatures, arguments digests, response hashes, and verdicts for non-repudiation audit trails.
- **Replay Attack & Clock Skew Guardrails**: Sliding-window cryptographic nonce verification with automatic TTL eviction and strict clock skew tolerance ($\pm 30\text{s}$).
- **Upstream Tool Manifest Verification**: Verifies upstream MCP server schema manifests and descriptions to prevent tool poisoning and man-in-the-middle schema alterations.
- **CLI Subcommand & Scorecard Visualizations**: Terminal ANSI provenance scorecards (`RenderProvenanceScorecard`), Mermaid sequence flowcharts (`--mermaid`), JSON audit proofs, and Markdown compliance reporting (`--demo`, `--format`, `-verify`).
- **Ephemeral Secret Vault & Bi-Directional DLP Engine (`pkg/redact`)**: In-memory thread-safe vault with agent tenant isolation, configurable lease TTLs, deterministic surrogate token generation (`[[VAULT:<CAT>:<HEX>]]`), and zero-leak detokenization.
- **Shannon Entropy Scanner (`entropy.go`)**: Information-theoretic entropy detector ($H(X) \ge 4.3$) identifying unstructured high-entropy credentials, private keys, and connection strings while excluding structured tokens.
- **Role-Based Data Loss Prevention Policies**: Enforces `VAULT`, `MASK`, `BLOCK`, and `ALLOW` modes with privilege escalation prevention for restricted agent roles.
- **CLI Subcommand & DLP Scorecards (`mcpgate redact`)**: Terminal ANSI DLP scorecards, Mermaid tokenization sequence diagrams (`--mermaid`), interactive string redaction/detokenization, and multi-provider demo (`--demo`).
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
