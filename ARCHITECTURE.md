# Architecture Blueprint: MCPGate

**MCPGate** acts as an enterprise-grade API gateway and security boundary between autonomous AI agents and Model Context Protocol (MCP) tool servers.

---

## 1. Gateway Topology

```
                  ┌─────────────────────────────────────────┐
                  │              Agent Runtime              │
                  │        (OpenBot / Claude / Cursor)      │
                  └────────────────────┬────────────────────┘
                                       │ JSON-RPC 2.0 (stdio / HTTP / SSE)
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │                 MCPGate                 │
                  ├─────────────────────────────────────────┤
                  │  1. Authenticate & Token Bucket Rate-Lim│
                  │  2. RBAC Policy Enforcement             │
                  │  3. Loop Detector (OWASP-LLM08)         │
                  │  4. Argument Schema Validation          │
                  │  5. Prometheus Metrics & Audit Log      │
                  └────────────────────┬────────────────────┘
                                       │ Sanitized JSON-RPC Dispatch
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │            Target MCP Server            │
                  │      (GitHub / PostgreSQL / Filesystem) │
                  └─────────────────────────────────────────┘
```

---

## 2. Core Modules

1. **Proxy Layer (`pkg/proxy`, `pkg/httpproxy`)**:
   - Manages duplex communication channels over standard I/O pipes (stdio) or HTTP/SSE streams.
   - Parses frames asynchronously and routes requests.

2. **Firewall & Loop Detector (`pkg/firewall`)**:
   - Maintains a sliding-window hash ring of recent tool calls.
   - Detects when an agent repeatedly invokes identical tools with matching parameters, tripping the circuit breaker to prevent infinite agent runaway cost.

3. **Rate Limiting (`pkg/ratelimit`)**:
   - Implements multi-tier token bucket rate limiting (RPM/TPM).
