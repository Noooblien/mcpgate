package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/Noooblien/mcpgate/pkg/audit"
	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/httpproxy"
	"github.com/Noooblien/mcpgate/pkg/proxy"
	"github.com/Noooblien/mcpgate/pkg/rbac"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "inspect":
		inspectCmd := flag.NewFlagSet("inspect", flag.ExitOnError)
		agentID := inspectCmd.String("agent", "agent-production-01", "Agent identifier")
		roleStr := inspectCmd.String("role", "standard", "Agent role: admin, standard, restricted, readonly")
		toolName := inspectCmd.String("tool", "read_file", "Target MCP tool name")
		argsJSON := inspectCmd.String("args", "{}", "JSON string of tool call arguments")
		strict := inspectCmd.Bool("strict", false, "Exit with code 1 if blocked")
		_ = inspectCmd.Parse(os.Args[2:])

		var args map[string]interface{}
		if err := json.Unmarshal([]byte(*argsJSON), &args); err != nil {
			log.Fatalf("Invalid JSON in -args: %v", err)
		}

		gate, err := gateway.NewMCPGate(gateway.GatewayConfig{
			HMACSeed:     "mcpgate-secure-seed-98213",
			MaxRPM:       120,
			BurstSize:    20,
			AuditLogPath: "./.audit/mcpgate_audit.jsonl",
			CanaryTokens: []string{"CANARY_SECRET_LEAK_TOKEN"},
		})
		if err != nil {
			log.Fatalf("Failed to initialize MCPGate: %v", err)
		}

		role := rbac.AgentRole(*roleStr)
		verdict := gate.InterceptToolCall(*agentID, role, *toolName, args)
		fmt.Print(gateway.RenderGateScorecard(verdict, *agentID, *toolName))

		if *strict && !verdict.Allowed {
			os.Exit(1)
		}

	case "audit":
		auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
		logPath := auditCmd.String("file", "./.audit/mcpgate_audit.jsonl", "Path to audit ledger file")
		strict := auditCmd.Bool("strict", false, "Exit with code 1 if tampering is detected")
		_ = auditCmd.Parse(os.Args[2:])

		ledger, err := audit.NewAuditLedger(*logPath)
		if err != nil {
			log.Fatalf("Failed to open audit ledger: %v", err)
		}

		valid, count, err := ledger.VerifyIntegrity()
		fmt.Printf("\n🔒 [MCPGate] Cryptographic Audit Ledger Integrity Verification\n")
		fmt.Printf("   File Path:        %s\n", *logPath)
		fmt.Printf("   Entries Verified: %d events\n", count)
		if valid {
			fmt.Printf("   Status:           \033[1;32m[PASS] ALL HASHES VERIFIED (ZERO TAMPERING)\033[0m\n\n")
		} else {
			fmt.Printf("   Status:           \033[1;31m[FAIL] INTEGRITY COMPROMISED: %v\033[0m\n\n", err)
			if *strict {
				os.Exit(1)
			}
		}

	case "proxy":
		proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
		agentID := proxyCmd.String("agent", "agent-stdio-client", "Agent client ID")
		roleStr := proxyCmd.String("role", "standard", "Agent role: admin, standard, restricted, readonly")
		_ = proxyCmd.Parse(os.Args[2:])

		gate, err := gateway.NewMCPGate(gateway.GatewayConfig{
			HMACSeed:     "mcpgate-proxy-seed",
			MaxRPM:       120,
			BurstSize:    20,
			AuditLogPath: "./.audit/mcpgate_audit.jsonl",
		})
		if err != nil {
			log.Fatalf("Failed to init MCPGate: %v", err)
		}

		proxyInst := proxy.NewStdioProxy(proxy.StdioProxyConfig{
			AgentID: *agentID,
			Role:    rbac.AgentRole(*roleStr),
		}, gate)

		fmt.Fprintf(os.Stderr, "🛡️  [MCPGate] Stdio Reverse-Proxy active for %s (Role: %s). Streaming JSON-RPC 2.0...\n", *agentID, *roleStr)
		_ = proxyInst.RunPipes(os.Stdin, os.Stdout, io.Discard, os.Stdin)

	case "serve":
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		port := serveCmd.Int("port", 8089, "HTTP proxy listen port")
		upstream := serveCmd.String("upstream", "", "Upstream MCP HTTP/SSE server URL (e.g. http://localhost:8080)")
		defaultAgent := serveCmd.String("agent", "agent-http-client", "Default agent ID when header is omitted")
		defaultRole := serveCmd.String("role", "standard", "Default agent role: admin, standard, restricted, readonly")
		maxRPM := serveCmd.Int("rpm", 120, "Rate limit ceiling in requests-per-minute per agent")
		_ = serveCmd.Parse(os.Args[2:])

		gate, err := gateway.NewMCPGate(gateway.GatewayConfig{
			HMACSeed:     "mcpgate-http-seed",
			MaxRPM:       *maxRPM,
			BurstSize:    25,
			AuditLogPath: "./.audit/mcpgate_audit.jsonl",
		})
		if err != nil {
			log.Fatalf("Failed to initialize MCPGate: %v", err)
		}

		proxyServer, err := httpproxy.NewHTTPProxyServer(httpproxy.HTTPProxyConfig{
			ListenAddr:     fmt.Sprintf(":%d", *port),
			UpstreamURL:    *upstream,
			DefaultAgentID: *defaultAgent,
			DefaultRole:    rbac.AgentRole(*defaultRole),
			Gateway:        gate,
		})
		if err != nil {
			log.Fatalf("Failed to initialize HTTP/SSE proxy: %v", err)
		}

		addr := fmt.Sprintf(":%d", *port)
		fmt.Printf("\n🛡️  [MCPGate] Zero-Trust HTTP/SSE Reverse-Proxy listening on http://0.0.0.0:%d\n", *port)
		if *upstream != "" {
			fmt.Printf("   Upstream MCP Server: %s\n", *upstream)
		} else {
			fmt.Printf("   Upstream MCP Server: None (Standalone Gateway Mode)\n")
		}
		fmt.Printf("   Default Role:        %s (RPM: %d)\n", *defaultRole, *maxRPM)
		fmt.Printf("   Audit Ledger:        ./.audit/mcpgate_audit.jsonl\n")
		fmt.Printf("   Health & Metrics:    http://0.0.0.0:%d/health, /metrics\n\n", *port)

		server := &http.Server{
			Addr:    addr,
			Handler: proxyServer.Handler(),
		}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}

	case "rules":
		fmt.Println("\n🛡️  [MCPGate] Active Security Rulesets & Defense-in-Depth Policies:")
		fmt.Println("  1. Prompt Injection Firewall:")
		fmt.Println("     - Direct override patterns: 'ignore previous instructions', 'DAN mode', system delimiters")
		fmt.Println("     - Indirect evasion heuristics: zero-width spaces, directional Unicode spoofing, Base64 decoders")
		fmt.Println("     - Honeytoken canary leakage traps")
		fmt.Println("  2. Sensitive Secret & PII Redactor:")
		fmt.Println("     - API Keys: OpenAI (sk-*), Anthropic (sk-ant-*), AWS (AKIA*), GitHub (ghp_*, gho_*)")
		fmt.Println("     - Private Keys: PEM RSA/EC/SSH blocks")
		fmt.Println("     - PII: Emails, SSNs, Luhn-validated Credit Cards")
		fmt.Println("  3. Dynamic Role-Based Access Control (RBAC):")
		fmt.Println("     - Roles: admin, standard, restricted, readonly")
		fmt.Println("     - Global Banned: 'rm -rf /', cloud metadata SSRF (169.254.169.254), /etc/shadow, path traversal")
		fmt.Println("  4. High-Throughput Token Bucket Rate Limiter:")
		fmt.Println("     - Default 120 RPM with configurable burst ceilings")
		fmt.Println("  5. Cryptographic Audit Ledger:")
		fmt.Println("     - SHA-256 chained rolling digest ledger stored in ./.audit/mcpgate_audit.jsonl")

	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println("MCPGate — Zero-Trust Model Context Protocol (MCP) Security Gateway & Prompt Injection Firewall")
	fmt.Println("\nCommands:")
	fmt.Println("  inspect     Intercept and evaluate a tool call through RBAC, firewall, and secret redaction")
	fmt.Println("  proxy       Run inline stdio reverse-proxy intercepting live JSON-RPC 2.0 tool execution")
	fmt.Println("  serve       Start high-performance HTTP & SSE reverse-proxy for remote MCP servers")
	fmt.Println("  audit       Verify cryptographic hash chain integrity of the audit ledger")
	fmt.Println("  rules       List active security policies, banned patterns, and redaction schemas")
	fmt.Println("\nExamples:")
	fmt.Println("  mcpgate inspect -agent agent_1 -role standard -tool read_file -args '{\"path\": \"main.go\"}'")
	fmt.Println("  mcpgate inspect -agent agent_1 -role readonly -tool write_file -args '{\"path\": \"foo.txt\"}'")
	fmt.Println("  mcpgate proxy -agent agent_worker -role standard")
	fmt.Println("  mcpgate serve --port 8089 --upstream http://localhost:8080")
	fmt.Println("  mcpgate audit -file ./.audit/mcpgate_audit.jsonl -strict")
	fmt.Println("  mcpgate rules")
}
