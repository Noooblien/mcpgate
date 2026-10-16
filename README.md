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

### Verify Audit Ledger Tamper-Proof Integrity
```bash
mcpgate audit -strict
```

### View Active Security Rules
```bash
mcpgate rules
```

---

## License

[MIT](LICENSE) © 2026 [Rahul Singh Maraskole](https://github.com/Noooblien)
