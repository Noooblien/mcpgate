# AGENT.md: MCPGate Autonomous Engineering Guide

Welcome, AI Agent. This specification governs how autonomous AI teammates and developers build, maintain, and contribute to **MCPGate**.

MCPGate is the high-performance security gateway, reverse-proxy, and tool-call firewall for the Model Context Protocol (MCP), supporting stdio, HTTP, and Server-Sent Events (SSE).

---

## 1. Core Operating Principles

1. **Protocol Adherence**:
   - Strictly implement the Model Context Protocol (MCP) JSON-RPC 2.0 specifications (`tools/list`, `tools/call`, `resources/list`, `prompts/list`).
   - Frame parsing, streaming serialization, and error responses must comply with standard JSON-RPC error codes.

2. **Defense in Depth**:
   - Every tool call and argument must be validated against registered schemas and RBAC authorization policies before passing downstream.
   - Detect and prevent infinite tool execution loops (`pkg/firewall/loop_detector.go` for OWASP-LLM08).

3. **Strict Branch Protection & Git Hygiene**:
   - **`main` is protected.** Never attempt direct pushes to `main`.
   - Always branch: `feat/<name>`, `fix/<name>`, or `docs/<name>`.
   - Write semantic commits following Conventional Commits (`feat(scope): ...`, `fix(scope): ...`, `test(scope): ...`).
   - Create a Pull Request via GitHub CLI (`gh pr create`), verify test matrix, and squash-merge (`gh pr merge <num> --squash --delete-branch`).

4. **Zero-Flake Testing**:
   - Verify all tests pass with `go test -v ./...`.

---

## 2. Directory Layout & Subsystem Architecture

```
mcpgate/
├── pkg/
│   ├── firewall/      # Tool-call validation, loop detection (OWASP-LLM08), schema guards
│   ├── httpproxy/     # Transparent HTTP and Server-Sent Events (SSE) MCP reverse proxy
│   ├── metrics/       # Tool execution latency, error rates, and Prometheus metrics
│   ├── proxy/         # Stdio sub-process reverse proxy and JSON-RPC 2.0 interceptor
│   ├── ratelimit/     # Token bucket rate limiting, RPM/TPM caps per tenant/agent
│   ├── rbac/          # Role-Based Access Control and tool permissions
│   └── spec/          # MCP JSON-RPC 2.0 types and protocol envelope definitions
├── tests/             # Comprehensive unit and integration test suite
├── .github/           # CI matrix workflows and PR templates
├── AGENT.md           # This autonomous engineer specification
├── CONTRIBUTING.md    # Contribution guidelines
├── SECURITY.md        # Vulnerability disclosure policy
├── CHANGELOG.md       # Semantic versioning release log
└── README.md          # Project overview and documentation
```

---

## 3. Essential Commands

| Task | Command |
|---|---|
| **Run all tests** | `go test -v ./...` |
| **Run specific test** | `go test -v ./tests -run Test<Name>` |
| **Run benchmarks** | `go test -bench=. ./tests` |
| **Create PR** | `gh pr create --base main --head <branch> --title "..." --body "..."` |
| **Squash & Merge** | `gh pr merge <pr_number> --squash --delete-branch` |
