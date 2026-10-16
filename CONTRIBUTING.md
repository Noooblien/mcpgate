# Contributing to MCPGate

Thank you for contributing to **MCPGate**, the enterprise security gateway and reverse-proxy for the Model Context Protocol (MCP).

---

## Getting Started

```bash
git clone https://github.com/Noooblien/mcpgate.git
cd mcpgate
go build -o bin/mcpgate ./cmd/mcpgate
go test -v -race ./...
```

---

## Pull Request Guidelines

1. Create a descriptive feature branch: `git checkout -b feat/your-feature`.
2. Ensure tests pass before pushing.
3. Open a Pull Request for review.
