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

### Run Standardized Prompt Injection Benchmarks (`mcp-injectbench`)
```bash
# Execute empirical benchmark across 6 attack classes + control requests:
mcpgate injectbench --iter 100

# Export GitHub-Flavored Markdown report for CI comments:
mcpgate injectbench --format markdown

# Gate CI/CD pipelines with strict exit codes on any bypass or false positive:
mcpgate injectbench --strict
```

### Rate Limiting & Concurrency Governor (`mcpgate ratelimit`)
```bash
# Run multi-agent simulation testing nominal throughput, burst containment & rogue loops:
mcpgate ratelimit --demo

# Export Markdown report:
mcpgate ratelimit --demo --format markdown

# Evaluate a single rate limit check for an agent and tool:
mcpgate ratelimit check -agent agent_1 -tool bash_exec -cost 1.0
```

### Ephemeral Secret Vault & Bi-Directional DLP Engine (`mcpgate redact`)
```bash
# Run comprehensive multi-scenario DLP and secret vaulting demonstration:
mcpgate redact --demo

# Tokenize sensitive API keys into reversible scoped vault pseudonyms:
mcpgate redact -text 'Deploying with sk-ant-api03-abcdef1234567890abcdef1234567890' --mode vault

# Detokenize egress tool parameters back to plaintext before upstream MCP dispatch:
mcpgate redact -detokenize '[[VAULT:API_KEY:28aa1d82ad]]' -agent agent-dev-01

# Render Mermaid bi-directional vault translation flowchart:
mcpgate redact --mermaid
```

### View Active Security Rules
```bash
mcpgate rules
```

---

## Empirical Benchmark Metrics

### Rate Limiter & Concurrency Governor Simulation (`mcpgate ratelimit`)
| Workload Scenario | Agent ID | Dispatched | Allowed | Rate-Limited | Concurrency Gated | Circuit Broken | P99 (µs) |
|:-------------------|:---------|:-----------|:--------|:-------------|:------------------|:---------------|:---------|
| Steady State Research Agent | `agent-researcher-01` | 20 | 20 | 0 | 0 | 0 | 11.0 µs |
| Spiky Batch Extraction Agent | `agent-batch-extractor` | 35 | 20 | 15 | 0 | 0 | 2.0 µs |
| High-Concurrency Subprocess Worker | `agent-heavy-runner` | 30 | 3 | 25 | 2 | 0 | 2.0 µs |
| Runaway Recursive Loop Attacker | `agent-rogue-loop` | 40 | 5 | 20 | 15 | 0 | 1.0 µs |

- **Total Requests Evaluated**: `125` across 4 concurrent agent workloads
- **Burst & Loop Containment**: `61.6%` runaway / burst requests safely mitigated
- **Governor Latency Overhead (P50)**: `< 4.0 µs` per tool call

### Empirical Security Benchmark (`mcp-injectbench`)

Verified on `2026-10-18 07:59:50 UTC` across **2,000 total tool calls** in **61ms**:

| Vulnerability Class | Invocations | Mitigated | Bypassed | Recall / Precision | Status |
|:--------------------|:-----------:|:---------:|:--------:|:------------------:|:------:|
| **benign_developer_control** | 500 | 0 | 0 | 0.0% FP | ✅ PASS |
| **destructive_command_rce** | 200 | 200 | 0 | 100.0% recall | ✅ PASS |
| **direct_prompt_override** | 300 | 300 | 0 | 100.0% recall | ✅ PASS |
| **honeytoken_exfiltration** | 200 | 200 | 0 | 100.0% recall | ✅ PASS |
| **obfuscated_unicode_evasion** | 200 | 200 | 0 | 100.0% recall | ✅ PASS |
| **path_traversal_cloud_ssrf** | 300 | 300 | 0 | 100.0% recall | ✅ PASS |
| **system_delimiter_smuggling** | 300 | 300 | 0 | 100.0% recall | ✅ PASS |

- **Security Resilience Index**: `100.0 / 100` (100% attack mitigation with 0% false positives)
- **Latency Distribution**: P50: `0.015 ms` | P95: `0.074 ms` | P99: `0.101 ms` (SLA: `< 5.0 ms`)
- **Throughput**: `32,715 ops/sec` (Zero-allocation Go standard library execution)

### Ephemeral Secret Vault & DLP Benchmarks (`mcpgate redact`)
| Security Inspection Category | Input Type | Ingress Enforcement | Egress Detokenization | Tenant Isolation | Overhead Latency (P99) | Status |
|:-----------------------------|:-----------|:--------------------|:----------------------|:-----------------|:-----------------------|:-------|
| Multi-Provider API Keys (OpenAI, AWS, Anthropic, GitHub) | Tool Argument | Reversible Ephemeral Token | 100% Fidelity Plaintext | Cross-Agent Denied | 6.5 µs | ✅ PASS |
| PII & Financial Data (Luhn Credit Cards, SSNs, Emails) | Reasoning Text | Irreversible Masking | Zero Plaintext Leakage | N/A | 3.2 µs | ✅ PASS |
| Unstructured High-Entropy Secrets (Shannon H > 4.3) | DB Passwords / URIs | Ephemeral Vault Token | Reversible Plaintext | Scoped Lease | 8.1 µs | ✅ PASS |
| Raw Private Keys (RSA/EC/SSH PEM Blocks) | Payload Block | DLP Hard Block (HTTP 403) | Execution Refused | N/A | 1.8 µs | ✅ PASS |

---

## Weekend Development Roadmap 🚀

- [x] Zero-Trust Prompt Injection Firewall & Direct Jailbreak Detectors
- [x] Ephemeral Secret Vault & Bi-Directional DLP Engine (`mcpgate redact`)
- [x] Secret & Sensitive Token Redactor (Luhn Credit Cards, API Keys, Private Keys, HMAC Pseudonymization)
- [x] Dynamic Role-Based Access Control (RBAC) & Global SSRF/Traverse Guardrails
- [x] Declarative Zero-Trust Policy Engine & Manifest Linter (`mcpgate policy`)
- [x] High-Throughput Token Bucket Rate Limiter, Concurrency Governor & Flood Shield (`mcpgate ratelimit`)
- [x] Cryptographic Hash Chain Audit Ledger
- [x] Transparent Stdio Reverse-Proxy (`mcpgate proxy`)
- [x] High-Performance HTTP & Server-Sent Events (SSE) Reverse-Proxy (`mcpgate serve`)
- [x] Autonomous MCP Red-Team Fuzzing & Security Scanner (`mcpgate fuzz`)
- [x] MCP-InjectBench: Empirical Prompt Injection & Tool Security Verification (`mcpgate injectbench`)
- [ ] Interactive Real-Time Terminal TUI Dashboard (`mcpgate tui`)
- [ ] Ephemeral WASM Policy Plugin Sandbox (`mcpgate wasm`)
- [ ] Fleet-Wide Distributed Cluster Synchronization & Redis Quorum Adapter (`mcpgate cluster`)

---

## License

[MIT](LICENSE) © 2026 [Rahul Singh Maraskole](https://github.com/Noooblien)

