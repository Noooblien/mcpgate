# MCPGate 🛡️

**Zero-Trust Security Gateway, Prompt Injection Firewall, Dynamic RBAC & Secret Redaction Engine for the Model Context Protocol (MCP)**.

Built in Go for low-latency interceptor proxying of AI agent tool execution.

---

## Architecture & Defense-in-Depth

```
  +------------------+
  |  Agent / Client  |
  +--------+---------+
           | (JSON-RPC 2.0 / tools/call)
           v
  +-------------------------------------------------------------+
  |                       MCPGate Engine                        |
  |                                                             |
  |  [Layer 1] Token Bucket Rate Limiting (per-agent RPM)       |
  |  [Layer 2] Dynamic Role-Based Access Control (RBAC)         |
  |            - Global guardrails: SSRF (169.254.169.254),      |
  |              path traversal, destructive filesystem ops     |
  |  [Layer 3] Prompt Injection & Jailbreak Firewall            |
  |            - Direct override & jailbreak pattern detectors   |
  |            - Zero-width space & invisible Unicode stripping |
  |            - Base64 obfuscation payload decoders            |
  |            - Honeytoken canary leak traps                   |
  |  [Layer 4] Secret & Sensitive PII Redactor                  |
  |            - Scans OpenAI, Anthropic, AWS, GitHub tokens    |
  |            - PEM private key blocks & JWT signatures        |
  |            - Luhn-verified credit card numbers & SSNs       |
  |            - HMAC-derived deterministic pseudonymization    |
  |  [Layer 5] Cryptographic Audit Ledger                       |
  |            - Append-only SHA-256 rolling digest hash chain  |
  +-----------------------------+-------------------------------+
                                | (Sanitized / Allowed)
                                v
                     +--------------------+
                     |  Target MCP Server |
                     +--------------------+
```

---

## CLI Usage

### Inspect a Tool Call
```bash
mcpgate inspect -agent agent_1 -role standard -tool read_file -args '{"path": "config.json"}'
```

### Redaction Preview
```bash
mcpgate inspect -agent agent_1 -role standard -tool read_file \
  -args '{"token": "sk-12345678901234567890123456789012"}'
```

### Start HTTP & Server-Sent Events (SSE) Proxy
```bash
# Transparent HTTP/SSE reverse-proxy on port 8089 forwarding to upstream MCP server
mcpgate serve --port 8089 --upstream http://localhost:8080

# Check real-time security metrics and gateway health
curl http://localhost:8089/health
curl http://localhost:8089/metrics
```

### Verify Audit Ledger Tamper-Proof Integrity
```bash
mcpgate audit -strict
```

### Evaluate Declarative Zero-Trust Policies
```bash
# Run comprehensive policy demo suite across 5 scenarios
mcpgate policy --demo

# Lint a custom policy manifest file
mcpgate policy lint -policy policy.json

# Render Mermaid policy hierarchy flowchart
mcpgate policy --mermaid
```

### Run Adversarial Security Fuzzer
```bash
# Execute 8-vector attack suite and generate ANSI scorecard
mcpgate fuzz -role standard

# Output Mermaid attack surface topology diagram
mcpgate fuzz -mermaid
```

### View Active Security Rules
```bash
mcpgate rules
```

---

## Weekend Development Roadmap 🚀

- [x] Zero-Trust Prompt Injection Firewall & Direct Jailbreak Detectors
- [x] Secret & Sensitive Token Redactor (Luhn Credit Cards, API Keys, Private Keys, HMAC Pseudonymization)
- [x] Dynamic Role-Based Access Control (RBAC) & Global SSRF/Traverse Guardrails
- [x] Declarative Zero-Trust Policy Engine & Manifest Linter (`mcpgate policy`)
- [x] High-Throughput Token Bucket Rate Limiter
- [x] Cryptographic Hash Chain Audit Ledger
- [x] Transparent Stdio Reverse-Proxy (`mcpgate proxy`)
- [x] High-Performance HTTP & Server-Sent Events (SSE) Reverse-Proxy (`mcpgate serve`)
- [x] Autonomous MCP Red-Team Fuzzing & Security Scanner (`mcpgate fuzz`)
- [ ] Interactive Real-Time Terminal TUI Dashboard (`mcpgate tui`)
- [ ] Ephemeral WASM Policy Plugin Sandbox (`mcpgate wasm`)
- [ ] Fleet-Wide Distributed Cluster Synchronization & Redis Quorum Adapter (`mcpgate cluster`)

---

## License

[MIT](LICENSE) © 2026 [Rahul Singh Maraskole](https://github.com/Noooblien)

