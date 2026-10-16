# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | :white_check_mark: |

---

## Reporting a Vulnerability

As an MCP firewall and proxy, MCPGate is central to securing tool environments against unauthorized command execution and recursive prompt injection.

To report a vulnerability:
1. **Do not create a public issue.**
2. Send report details to **`security@noooblien.com`**.
3. Include:
   - Reproduction steps or proof of concept.
   - MCP client and server configurations.
   - Impact assessment (e.g. firewall bypass, unauthenticated tool execution).

---

## Security Model

- **Least Privilege RBAC**: Tools must be explicitly granted per agent/tenant token.
- **Loop & Denial-of-Service Defense (`pkg/firewall`)**: Automatic sliding-window loop detection prevents infinite repeating tool invocations from consuming agent credits.
- **SSRF & Stdio Isolation**: Subprocess stdio streams are spawned in isolated process groups.
