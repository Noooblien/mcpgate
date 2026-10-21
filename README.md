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

### Cryptographic Tool Provenance & Non-Repudiation Attestation
```bash
# Run multi-scenario provenance verification demo with ANSI scorecard:
mcpgate provenance --demo

# Output Mermaid sequence diagram of the verified cryptographic signing lifecycle:
mcpgate provenance --demo --mermaid

# Verify an exported AttestationReceipt JSON token:
mcpgate provenance -verify receipt.json

# Export Markdown compliance report:
mcpgate provenance --demo --format markdown
```

### Adaptive Blast Radius Governor & Cumulative Risk Engine (`mcpgate risk`)
```bash
# Run comprehensive multi-scenario blast radius governance demonstration:
mcpgate risk --demo

# Evaluate a specific tool call with multi-dimensional risk scoring:
mcpgate risk -check -agent agent-dev-01 -role standard -tool bash_exec -args '{"cmd": "rm -rf /var/log"}'

# Export Markdown risk compliance report:
mcpgate risk --demo --format markdown

# Render Mermaid blast radius governance flowchart:
mcpgate risk --demo --mermaid
```

### Canary Honeytools, Deception Defense & Forensic Quarantine (`mcpgate honeypot`)
```bash
# Run comprehensive canary probe and deception defense demonstration:
mcpgate honeypot --demo

# Intercept a specific tool call through the deception engine:
mcpgate honeypot -check -session sess_1 -agent agent_1 -tool admin_export_vault_credentials

# Render Mermaid attack trapping & forensic alerting sequence diagram:
mcpgate honeypot --demo --mermaid

# Export Markdown incident report for SIEM / SOC compliance:
mcpgate honeypot --demo --format markdown
```

### Behavioral Tool Call Anomaly & Markov Deviation Engine (`mcpgate anomaly`)
```bash
# Run 4 enterprise behavioral anomaly scenarios (Markov sequence jumps, payload blasts, prototype pollution):
mcpgate anomaly --demo

# Intercept a specific tool call with prior transition context and custom thresholds:
mcpgate anomaly -check -agent agent_1 -tool run_cmd -prior read_file -args '{"cmd": "id"}'

# Render Mermaid Markov transition graph with anomaly annotations:
mcpgate anomaly --demo --mermaid

# Export Markdown security audit report for SIEM / SOC ingestion:
mcpgate anomaly --demo --format markdown
```

### Just-In-Time (JIT) Capability Delegation & Ephemeral Lease Engine (`mcpgate jit`)
```bash
# Run 4 enterprise zero-trust JIT delegation scenarios (auto-grant, step-up dual custody, parameter substitution attack, forbidden command denial):
mcpgate jit --demo

# Request an ephemeral capability lease for a diagnostic tool:
mcpgate jit -tool diagnostics.query_metrics -agent agent_1 -args '{"service": "api"}'

# Render Mermaid diagram of the JIT state machine and step-up authorization flow:
mcpgate jit --demo --mermaid

# Export Markdown audit ledger report:
mcpgate jit --demo --format markdown
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

### Cryptographic Tool Provenance & Attestation Benchmarks (`mcpgate provenance`)
| Provenance Security Layer | Cryptographic Primitive | Integrity Guarantee | Replay Attack Mitigation | Verification Latency (P99) | Status |
|:--------------------------|:------------------------|:--------------------|:-------------------------|:---------------------------|:-------|
| **Agent Request Mutual Signing** | Ed25519 + SHA-256 | Non-Repudiation | Sliding-window nonces + TTL | 1.8 µs | ✅ PASS |
| **MITM Argument Tamper Detection** | Canonical JSON Digest | 100% Bit-flip detection | Instant Block | 2.1 µs | ✅ PASS |
| **Replay & Skew Defense** | Rolling Nonce Set | Zero replay tolerance | 30s max clock drift | 0.9 µs | ✅ PASS |
| **Upstream Manifest Attestation** | Upstream Server Ed25519 | Zero schema poisoning | Schema digest verification | 2.4 µs | ✅ PASS |
| **Execution Attestation Receipt** | Gateway Ed25519 Audit Token | Verifiable Non-Repudiation | Dual-hash receipt chaining | 3.1 µs | ✅ PASS |

### Canary Honeytools & Adversarial Deception Benchmarks (`mcpgate honeypot`)
| Deception Defense Layer | Deception Mode | Attack Vector | Quarantine Mechanism | Response Latency (P99) | Status |
|:------------------------|:---------------|:--------------|:---------------------|:-----------------------|:-------|
| **Admin Vault Decoy Tool** | `HONEYED_PAYLOAD` | Credential Enumeration | Auto-Quarantine Session | 1.4 µs | ✅ PASS |
| **Host Shell Decoy Tool** | `SYNTHETIC_ERROR` | RCE & Jailbreak Breakout | Auto-Quarantine Session | 1.2 µs | ✅ PASS |
| **Canary Secret Exfiltration** | `HARD_QUARANTINE` | Parameter Leakage | Immediate Session Lock | 0.8 µs | ✅ PASS |
| **Post-Breach Containment** | `HARD_QUARANTINE` | Lateral Movement Probing | Global Agent/Session Block | 0.4 µs | ✅ PASS |

### Behavioral Tool Call Anomaly & Markov Engine Benchmarks (`mcpgate anomaly`)
| Anomaly Detection Layer | Analysis Engine | Attack / Anomaly Vector | Mitigation Verdict | Evaluation Latency (P99) | Status |
|:------------------------|:----------------|:------------------------|:-------------------|:-------------------------|:-------|
| **Markov Sequence Jumps** | Transition Matrix ($P < \tau$) | Unprecedented Data Exfiltration | Instant BLOCK / Quarantine | 1.8 µs | ✅ PASS |
| **Payload Blast Radius** | Welford Dispersion ($Z > 3.0$) | Massive Obfuscated Buffer Bomb | Instant BLOCK | 2.2 µs | ✅ PASS |
| **High-Entropy Injection** | Shannon Entropy ($H \ge 5.5$) | Encrypted Shellcode & Base64 Blobs | Instant BLOCK | 1.9 µs | ✅ PASS |
| **Schema Parameter Drift** | Parameter Cardinality Scorer | Prototype Pollution / Raw SQL Keys | Operational QUARANTINE | 1.1 µs | ✅ PASS |

### Just-In-Time (JIT) Ephemeral Delegation Benchmarks (`mcpgate jit`)
| JIT Zero-Trust Defense Layer | Mechanism | Threat Model | Mitigation Verdict | Evaluation Latency (P99) | Status |
|:-----------------------------|:----------|:-------------|:-------------------|:-------------------------|:-------|
| **Zero Standing Privilege** | Ephemeral HMAC-SHA256 Lease | Unauthorized Tool Invocation | Block Without Signed Lease | 1.2 µs | ✅ PASS |
| **Step-Up Dual Custody Gate** | Supervisor Verification | High-Risk Mutation / Deletion | Gated in PENDING_APPROVAL | 1.5 µs | ✅ PASS |
| **Parameter Substitution Tamper** | SHA-256 Canonical Digest | In-Flight Argument Mutation | Instant BLOCK & Alert | 2.1 µs | ✅ PASS |
| **One-Time Use Enforcement** | Single-Use Nonce Invalidation | Lease Replay Attack | Instant BLOCK (`ERR_LEASE_REPLAY`) | 0.9 µs | ✅ PASS |
| **Ephemeral TTL Self-Destruction** | Time-Bounded Lease Expiration | Stale Lease Backdoor Execution | Instant Expired Invalidation | 0.8 µs | ✅ PASS |

---

## Weekend Development Roadmap 🚀

- [x] Just-In-Time (JIT) Ephemeral Capability Delegation & Step-Up Authorization Engine (`mcpgate jit`)
- [x] Zero-Trust Prompt Injection Firewall & Direct Jailbreak Detectors
- [x] Behavioral Tool Call Anomaly Detection & Markov Sequence Deviation Engine (`mcpgate anomaly`)
- [x] Canary Honeytools, Deception Defense & Forensic Quarantine (`mcpgate honeypot`)
- [x] Adaptive Blast Radius Governor & Cumulative Risk Engine (`mcpgate risk`)
- [x] Cryptographic Tool Provenance, Request Mutual Signing & Non-Repudiation Attestation (`mcpgate provenance`)
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

