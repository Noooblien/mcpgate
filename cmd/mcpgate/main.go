package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Noooblien/mcpgate/pkg/audit"
	"github.com/Noooblien/mcpgate/pkg/fuzz"
	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/honeypot"
	"github.com/Noooblien/mcpgate/pkg/httpproxy"
	"github.com/Noooblien/mcpgate/pkg/injectbench"
	"github.com/Noooblien/mcpgate/pkg/policy"
	"github.com/Noooblien/mcpgate/pkg/provenance"
	"github.com/Noooblien/mcpgate/pkg/proxy"
	"github.com/Noooblien/mcpgate/pkg/ratelimit"
	"github.com/Noooblien/mcpgate/pkg/rbac"
	"github.com/Noooblien/mcpgate/pkg/redact"
	"github.com/Noooblien/mcpgate/pkg/risk"
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

	case "fuzz":
		fuzzCmd := flag.NewFlagSet("fuzz", flag.ExitOnError)
		roleStr := fuzzCmd.String("role", "standard", "Agent role under test: admin, standard, restricted, readonly")
		strict := fuzzCmd.Bool("strict", false, "Exit with non-zero code if resilience < 100% or false negatives detected")
		mermaid := fuzzCmd.Bool("mermaid", false, "Output Mermaid attack surface flowchart diagram")
		_ = fuzzCmd.Parse(os.Args[2:])

		gate, err := gateway.NewMCPGate(gateway.GatewayConfig{
			HMACSeed:     "mcpgate-fuzz-cli-seed",
			MaxRPM:       1000,
			BurstSize:    500,
			AuditLogPath: "./.audit/mcpgate_fuzz_audit.jsonl",
		})
		if err != nil {
			log.Fatalf("Failed to initialize gateway for fuzzing: %v", err)
		}

		fuzzer := fuzz.NewSecurityFuzzer(gate)
		payloads := fuzz.GenerateDefaultPayloads()
		report := fuzzer.RunSuite(payloads, rbac.AgentRole(*roleStr))

		if *mermaid {
			fmt.Println(fuzz.RenderFuzzMermaid(report))
			return
		}

		fmt.Print(fuzz.RenderFuzzScorecard(report))

		if *strict && (!report.Passed || report.FalseNegatives > 0) {
			os.Exit(1)
		}
		return

	case "policy":
		policyCmd := flag.NewFlagSet("policy", flag.ExitOnError)
		policyFile := policyCmd.String("policy", "", "Path to declarative policy JSON manifest")
		agentID := policyCmd.String("agent", "agent-production-01", "Agent identifier")
		roleStr := policyCmd.String("role", "standard", "Agent role: admin, standard, restricted, readonly")
		toolName := policyCmd.String("tool", "read_file", "Target MCP tool name")
		argsJSON := policyCmd.String("args", "{}", "JSON string of tool call arguments")
		demo := policyCmd.Bool("demo", false, "Run comprehensive declarative policy test suite")
		lint := policyCmd.Bool("lint", false, "Lint and validate the policy manifest file")
		dump := policyCmd.Bool("dump", false, "Dump default zero-trust policy manifest to stdout")
		mermaid := policyCmd.Bool("mermaid", false, "Render Mermaid policy hierarchy diagram")
		strict := policyCmd.Bool("strict", false, "Exit with code 1 if any policy check is blocked or violated")
		// Check positional action in os.Args[2:] (e.g. `mcpgate policy dump` or `mcpgate policy lint -policy ...`)
		action := ""
		argsToParse := os.Args[2:]
		if len(argsToParse) > 0 && !strings.HasPrefix(argsToParse[0], "-") {
			action = argsToParse[0]
			argsToParse = argsToParse[1:]
		}
		_ = policyCmd.Parse(argsToParse)

		isDump := *dump || action == "dump"
		isLint := *lint || action == "lint"
		isDemo := *demo || action == "demo"
		isMermaid := *mermaid || action == "mermaid"

		var manifest *policy.PolicyManifest
		if *policyFile != "" {
			engine, err := policy.LoadFromFile(*policyFile)
			if err != nil {
				log.Fatalf("Failed to load policy file %s: %v", *policyFile, err)
			}
			manifest = engine.GetManifest()
		} else {
			manifest = policy.DefaultZeroTrustPolicy()
		}

		if isDump {
			bytes, _ := json.MarshalIndent(manifest, "", "  ")
			fmt.Println(string(bytes))
			return
		}

		if isLint {
			errs := policy.Validate(manifest)
			if len(errs) == 0 {
				fmt.Printf("\n\033[1;32m[PASS]\033[0m Policy manifest '%s' (v%s) is valid (zero errors, %d rules)\n\n", manifest.Metadata.Name, manifest.Metadata.Version, len(manifest.Rules))
			} else {
				fmt.Printf("\n\033[1;31m[FAIL]\033[0m Found %d validation errors in policy manifest:\n", len(errs))
				for _, e := range errs {
					fmt.Printf("  • %s\n", e)
				}
				fmt.Println()
				if *strict {
					os.Exit(1)
				}
			}
			return
		}

		if isMermaid {
			fmt.Println(policy.RenderPolicyMermaid(manifest))
			return
		}

		engine, err := policy.NewEngine(manifest)
		if err != nil {
			log.Fatalf("Failed to initialize policy engine: %v", err)
		}

		if isDemo {
			scenarios := policy.GenerateDemoScenarios()
			fmt.Printf("\n\033[1;36m========================================================================================\033[0m\n")
			fmt.Printf("   \033[1;37mMCPGATE DECLARATIVE SECURITY POLICY DEMO SUITE (%d SCENARIOS)\033[0m\n", len(scenarios))
			fmt.Printf("\033[1;36m========================================================================================\033[0m\n")

			blockedCount := 0
			for i, sc := range scenarios {
				fmt.Printf("\n\033[1;33m[Scenario %d/%d]\033[0m \033[1m%s\033[0m: %s\n", i+1, len(scenarios), sc.Name, sc.Description)
				dec := engine.Evaluate(sc.Request)
				fmt.Print(policy.RenderPolicyScorecard(dec, sc.Request))
				if !dec.Allowed {
					blockedCount++
				}
			}
			fmt.Printf("\n\033[1;32m✓ Policy Demo Complete.\033[0m Evaluated %d scenarios (%d threats blocked/gated).\n\n", len(scenarios), blockedCount)
			return
		}

		var args map[string]interface{}
		if err := json.Unmarshal([]byte(*argsJSON), &args); err != nil {
			log.Fatalf("Invalid JSON in -args: %v", err)
		}

		req := policy.PolicyRequest{
			AgentID:  *agentID,
			Role:     rbac.AgentRole(*roleStr),
			ToolName: *toolName,
			Args:     args,
		}
		decision := engine.Evaluate(req)
		fmt.Print(policy.RenderPolicyScorecard(decision, req))

		if *strict && !decision.Allowed {
			os.Exit(1)
		}

	case "injectbench":
		benchCmd := flag.NewFlagSet("injectbench", flag.ExitOnError)
		roleStr := benchCmd.String("role", "standard", "Agent role under test: admin, standard, restricted, readonly")
		iter := benchCmd.Int("iter", 100, "Number of test iterations")
		strict := benchCmd.Bool("strict", false, "Exit with code 1 if resilience < 100% or any attack bypasses")
		format := benchCmd.String("format", "text", "Output format: text | markdown | json")
		_ = benchCmd.Parse(os.Args[2:])

		cfg := injectbench.DefaultBenchmarkConfig()
		cfg.Iterations = *iter
		cfg.TargetRole = *roleStr
		cfg.StrictMode = *strict
		cfg.OutputFormat = *format

		summary, err := injectbench.RunBenchmark(nil, cfg)
		if err != nil {
			log.Fatalf("InjectBench execution failed: %v", err)
		}

		switch *format {
		case "markdown":
			fmt.Println(injectbench.RenderMarkdownReport(summary))
		case "json":
			jsonStr, _ := summary.RenderJSON()
			fmt.Println(jsonStr)
		default:
			fmt.Print(injectbench.RenderTerminalScorecard(summary))
		}

		if *strict && (!summary.OverallPassed || summary.AttacksBypassed > 0 || summary.FalsePositives > 0) {
			os.Exit(1)
		}

	case "ratelimit":
		rlCmd := flag.NewFlagSet("ratelimit", flag.ExitOnError)
		demo := rlCmd.Bool("demo", false, "Run multi-agent concurrency and burst containment simulation")
		check := rlCmd.Bool("check", false, "Evaluate a single rate limit check for an agent and tool")
		agentID := rlCmd.String("agent", "agent-production-01", "Agent identifier")
		toolName := rlCmd.String("tool", "web_search", "MCP tool name")
		cost := rlCmd.Float64("cost", 1.0, "Token / weight cost for request")
		rpm := rlCmd.Int("rpm", 120, "Configured requests per minute")
		burst := rlCmd.Int("burst", 20, "Burst capacity")
		maxConc := rlCmd.Int("concurrency", 5, "Max in-flight concurrent operations")
		format := rlCmd.String("format", "text", "Output format: text | markdown | json")
		strict := rlCmd.Bool("strict", false, "Exit with code 1 if throttled")

		// Support positional action (e.g. `mcpgate ratelimit demo`)
		action := ""
		argsToParse := os.Args[2:]
		if len(argsToParse) > 0 && !strings.HasPrefix(argsToParse[0], "-") {
			action = argsToParse[0]
			argsToParse = argsToParse[1:]
		}
		_ = rlCmd.Parse(argsToParse)

		isDemo := *demo || action == "demo" || (!*check && action != "check")
		isCheck := *check || action == "check"

		governor := ratelimit.NewTokenBucketLimiter(ratelimit.RateLimiterConfig{
			MaxRPM:             *rpm,
			Burst:              *burst,
			MaxConcurrency:     *maxConc,
			MaxToolConcurrency: map[string]int{"bash_exec": 3},
			ToolLimits: map[string]ratelimit.ToolLimit{
				"bash_exec": {MaxRPM: 60, Burst: 5},
			},
		})

		if isCheck && !*demo && action != "demo" {
			dec, err := governor.AllowTool(*agentID, *toolName, *cost)
			if *format == "json" {
				bytes, _ := json.MarshalIndent(dec, "", "  ")
				fmt.Println(string(bytes))
			} else {
				fmt.Printf("\n🛡️  [MCPGate] Rate Limit & Concurrency Check for Agent '%s'\n", *agentID)
				fmt.Printf("   Tool:             %s (Cost: %.1f)\n", *toolName, *cost)
				if dec.Allowed {
					fmt.Printf("   Status:           \033[1;32m[ALLOWED]\033[0m\n")
					fmt.Printf("   Remaining Tokens: %.1f / %.1f\n", dec.TokensRemaining, dec.Capacity)
					fmt.Printf("   Refill Rate:      %.2f tokens/sec\n\n", dec.RefillRatePerSec)
				} else {
					fmt.Printf("   Status:           \033[1;31m[THROTTLED: %s]\033[0m\n", dec.Status)
					fmt.Printf("   Reason:           %s\n", err)
					fmt.Printf("   Retry-After:      %v\n\n", dec.RetryAfter)
					if *strict {
						os.Exit(1)
					}
				}
			}
			return
		}

		if isDemo {
			scenarios := ratelimit.DefaultSimulationScenarios()
			summary, err := ratelimit.RunSimulation(governor, scenarios)
			if err != nil {
				log.Fatalf("Rate limiter simulation failed: %v", err)
			}

			switch *format {
			case "markdown":
				fmt.Println(ratelimit.RenderMarkdownReport(summary))
			case "json":
				jsonStr, _ := summary.RenderJSON()
				fmt.Println(jsonStr)
			default:
				fmt.Print(ratelimit.RenderTerminalScorecard(summary))
			}

			if *strict && summary.BurstContainmentPct < 20.0 {
				os.Exit(1)
			}
			return
		}

	case "redact":
		redactCmd := flag.NewFlagSet("redact", flag.ExitOnError)
		demo := redactCmd.Bool("demo", false, "Run comprehensive DLP and secret vaulting demo scenarios")
		text := redactCmd.String("text", "", "Text string to scan and redact")
		agentID := redactCmd.String("agent", "agent-production-01", "Agent identifier")
		roleStr := redactCmd.String("role", "standard", "Agent role: admin, standard, restricted, readonly")
		mode := redactCmd.String("mode", "vault", "Enforcement mode: vault | mask | block")
		detok := redactCmd.String("detokenize", "", "Tokenized text string to detokenize back to plaintext")
		mermaid := redactCmd.Bool("mermaid", false, "Render Mermaid vault flow diagram")
		format := redactCmd.String("format", "text", "Output format: text | markdown | json")
		strict := redactCmd.Bool("strict", false, "Exit with code 1 if secrets blocked by DLP")
		_ = redactCmd.Parse(os.Args[2:])

		cfg := redact.DefaultDLPConfig()
		switch *mode {
		case "mask":
			cfg.DefaultAction = redact.DLPActionMask
		case "block":
			cfg.DefaultAction = redact.DLPActionBlock
		case "vault":
			cfg.DefaultAction = redact.DLPActionVault
		}

		dlp := redact.NewDLPController(cfg)

		if *mermaid {
			fmt.Println(redact.RenderDLPMermaid())
			return
		}

		if *detok != "" {
			restored, count := dlp.DetokenizeEgress(*detok, *agentID)
			fmt.Printf("\n🔒 [MCPGate Vault] Detokenized %d secrets for Agent '%s':\n", count, *agentID)
			fmt.Printf("   Output: %s\n\n", restored)
			return
		}

		if *demo || len(os.Args) == 2 {
			scenarios := redact.DefaultDemoScenarios()
			var allResults []*redact.DLPResult
			for _, sc := range scenarios {
				res := dlp.InspectAndSanitize(sc.Payload, sc.AgentID, sc.Role)
				allResults = append(allResults, res)
				if *format == "text" {
					fmt.Print(redact.RenderDLPScorecard(res, sc.AgentID, cfg.DefaultAction))
				}
			}

			switch *format {
			case "markdown":
				fmt.Println(redact.RenderMarkdownReport(allResults))
			case "json":
				bytes, _ := json.MarshalIndent(allResults, "", "  ")
				fmt.Println(string(bytes))
			}

			if *strict {
				for _, r := range allResults {
					if !r.Allowed {
						os.Exit(1)
					}
				}
			}
			return
		}

		if *text != "" {
			role := rbac.AgentRole(*roleStr)
			res := dlp.InspectAndSanitize(*text, *agentID, role)
			if *format == "json" {
				js, _ := res.RenderJSON()
				fmt.Println(js)
			} else {
				fmt.Print(redact.RenderDLPScorecard(res, *agentID, cfg.DefaultAction))
			}
			if *strict && !res.Allowed {
				os.Exit(1)
			}
			return
		}

		fmt.Println("Usage: mcpgate redact [--demo] [-text <string>] [-detokenize <token>] [--mode vault|mask|block] [--mermaid]")

	case "provenance", "attest":
		provCmd := flag.NewFlagSet("provenance", flag.ExitOnError)
		demo := provCmd.Bool("demo", false, "Run cryptographic provenance and non-repudiation audit demonstration")
		mermaid := provCmd.Bool("mermaid", false, "Output Mermaid sequence diagram markup of the verified signing lifecycle")
		format := provCmd.String("format", "text", "Output format: text | markdown | json")
		strict := provCmd.Bool("strict", false, "Exit with code 1 if any legitimate scenario fails verification")
		verifyFile := provCmd.String("verify", "", "Path to a JSON AttestationReceipt file to verify")
		_ = provCmd.Parse(os.Args[2:])

		pe, agentPrivs, err := provenance.SetupDemoEnvironment()
		if err != nil {
			log.Fatalf("Failed to initialize provenance engine: %v", err)
		}

		if *verifyFile != "" {
			data, err := os.ReadFile(*verifyFile)
			if err != nil {
				log.Fatalf("Failed to read receipt file: %v", err)
			}
			receipt, err := provenance.ParseReceiptFromJSON(data)
			if err != nil {
				log.Fatalf("Invalid receipt JSON: %v", err)
			}
			valid, err := pe.VerifyReceipt(receipt)
			if valid && err == nil {
				fmt.Printf("\n\033[1;32m[VERIFIED]\033[0m Attestation Receipt '%s' is authentic and tamper-evident.\n", receipt.ReceiptID)
				fmt.Printf("   Agent:      %s\n", receipt.AgentID)
				fmt.Printf("   Tool:       %s\n", receipt.ToolName)
				fmt.Printf("   Verdict:    %s\n", receipt.Verdict)
				fmt.Printf("   Timestamp:  %s\n\n", receipt.Timestamp.Format(time.RFC3339))
			} else {
				fmt.Printf("\n\033[1;31m[TAMPERED]\033[0m Attestation Receipt verification failed: %v\n\n", err)
				os.Exit(1)
			}
			return
		}

		scenarios := provenance.GetDemoScenarios()
		if *demo || len(os.Args) == 2 {
			var allProofs []*provenance.AuditProof
			for _, sc := range scenarios {
				priv := agentPrivs[sc.AgentID]
				req, err := pe.SignRequest(sc.AgentID, priv, sc.ToolName, sc.ArgumentsJSON)
				if err != nil {
					log.Fatalf("Request signing failed: %v", err)
				}

				if sc.TamperPayload {
					req.ArgumentsJSON = `{"cluster": "attacker-controlled-node", "image": "malicious/trojan:latest"}`
				}

				if sc.ReplayNonce {
					_ = pe.VerifyRequest(req)
				}

				verRes := pe.VerifyRequest(req)

				var receipt *provenance.AttestationReceipt
				if verRes.Valid {
					receipt, _ = pe.IssueReceipt(req, sc.ResponseJSON, sc.Verdict, sc.Duration)
				}

				proof := &provenance.AuditProof{
					Receipt:      receipt,
					Request:      req,
					Verification: verRes,
				}
				allProofs = append(allProofs, proof)

				if *format == "text" {
					fmt.Print(provenance.RenderProvenanceScorecard(verRes, receipt))
					if *mermaid && receipt != nil {
						fmt.Println(provenance.RenderProvenanceMermaid(receipt))
					}
				}
			}

			switch *format {
			case "markdown":
				fmt.Println(provenance.RenderMarkdownReport(allProofs))
			case "json":
				bytes, _ := json.MarshalIndent(allProofs, "", "  ")
				fmt.Println(string(bytes))
			}

			if *strict {
				for _, p := range allProofs {
					if !p.Verification.Valid && p.Request.AgentID == "agent-analyst-alpha" && !strings.Contains(p.Verification.Detail, "nonce") {
						os.Exit(1)
					}
				}
			}
			return
		}

	case "risk":
		riskCmd := flag.NewFlagSet("risk", flag.ExitOnError)
		demo := riskCmd.Bool("demo", false, "Run comprehensive adaptive blast radius & cumulative risk scenarios")
		check := riskCmd.Bool("check", false, "Assess risk for a proposed tool execution")
		sessionID := riskCmd.String("session", "session-default-01", "Session identifier")
		agentID := riskCmd.String("agent", "agent-production-01", "Agent identifier")
		roleStr := riskCmd.String("role", "standard", "Agent role: admin, standard, restricted, readonly")
		toolName := riskCmd.String("tool", "read_file", "Target MCP tool name")
		argsJSON := riskCmd.String("args", "{}", "JSON string of tool call arguments")
		budget := riskCmd.Float64("budget", 100.0, "Session blast radius budget in points")
		mermaid := riskCmd.Bool("mermaid", false, "Render Mermaid blast radius flowchart diagram")
		format := riskCmd.String("format", "text", "Output format: text | markdown | json")
		strict := riskCmd.Bool("strict", false, "Exit with code 1 if quarantined or step-up approval required")
		_ = riskCmd.Parse(os.Args[2:])

		cfg := risk.DefaultRiskGovernorConfig()
		if *budget > 0 {
			cfg.SessionRiskBudget = *budget
		}
		governor := risk.NewRiskGovernor(cfg, risk.NewToolScorer())

		if *demo || (!*check && *argsJSON == "{}" && *toolName == "read_file" && len(os.Args) <= 2) {
			assessments, err := risk.RunDemoSuite()
			if err != nil {
				log.Fatalf("Risk demo execution failed: %v", err)
			}

			switch *format {
			case "markdown":
				fmt.Println(risk.RenderMarkdownReport(assessments))
			case "json":
				bytes, _ := json.MarshalIndent(assessments, "", "  ")
				fmt.Println(string(bytes))
			default:
				for _, a := range assessments {
					fmt.Print(risk.RenderRiskScorecard(a))
					if *mermaid {
						fmt.Println(risk.RenderRiskMermaid(a))
					}
				}
			}

			if *strict {
				for _, a := range assessments {
					if a.Verdict == risk.VerdictQuarantinedBlock {
						os.Exit(1)
					}
				}
			}
			return
		}

		var args map[string]interface{}
		if err := json.Unmarshal([]byte(*argsJSON), &args); err != nil {
			log.Fatalf("Invalid JSON in -args: %v", err)
		}

		role := rbac.AgentRole(*roleStr)
		assessment := governor.AssessToolCall(*sessionID, *agentID, role, *toolName, args)

		switch *format {
		case "markdown":
			fmt.Println(risk.RenderMarkdownReport([]*risk.RiskAssessment{assessment}))
		case "json":
			bytes, _ := json.MarshalIndent(assessment, "", "  ")
			fmt.Println(string(bytes))
		default:
			fmt.Print(risk.RenderRiskScorecard(assessment))
			if *mermaid {
				fmt.Println(risk.RenderRiskMermaid(assessment))
			}
		}

		if *strict && (assessment.Verdict == risk.VerdictQuarantinedBlock || assessment.Verdict == risk.VerdictStepUpApproval) {
			os.Exit(1)
		}
		return

	case "honeypot":
		hpCmd := flag.NewFlagSet("honeypot", flag.ExitOnError)
		demo := hpCmd.Bool("demo", false, "Run comprehensive canary tool probe and deception defense scenarios")
		check := hpCmd.Bool("check", false, "Intercept a tool call through the honeypot deception engine")
		sessionID := hpCmd.String("session", "sess-prod-01", "Session identifier")
		agentID := hpCmd.String("agent", "agent-production-01", "Agent identifier")
		roleStr := hpCmd.String("role", "standard", "Agent role: admin, standard, restricted, readonly")
		toolName := hpCmd.String("tool", "admin_export_vault_credentials", "Target MCP tool name")
		argsJSON := hpCmd.String("args", "{}", "JSON string of tool call arguments")
		mode := hpCmd.String("mode", "honeyed", "Deception mode: honeyed | error | quarantine | tarpit")
		mermaid := hpCmd.Bool("mermaid", false, "Render Mermaid sequence diagram of forensic trap")
		format := hpCmd.String("format", "text", "Output format: text | markdown | json")
		strict := hpCmd.Bool("strict", false, "Exit with code 1 if honeypot tripped or session quarantined")
		_ = hpCmd.Parse(os.Args[2:])

		var decMode honeypot.DeceptionMode
		switch *mode {
		case "error":
			decMode = honeypot.ModeSyntheticError
		case "quarantine":
			decMode = honeypot.ModeHardQuarantine
		case "tarpit":
			decMode = honeypot.ModeTarpit
		default:
			decMode = honeypot.ModeHoneyedPayload
		}

		cfg := honeypot.HoneypotConfig{
			Enabled:               true,
			DefaultDeceptionMode:  decMode,
			AutoQuarantineSession: true,
			TarpitDelay:           0,
		}
		engine := honeypot.NewEngine(cfg)

		if *demo || (!*check && *argsJSON == "{}" && *toolName == "admin_export_vault_credentials" && len(os.Args) <= 2) {
			summary, verdicts, err := honeypot.RunDemoSuite()
			if err != nil {
				log.Fatalf("Honeypot demo execution failed: %v", err)
			}

			switch *format {
			case "markdown":
				fmt.Println(honeypot.RenderMarkdownReport(summary))
			case "json":
				jsonStr, _ := summary.RenderJSON()
				fmt.Println(jsonStr)
			default:
				scenarios := honeypot.GetDemoScenarios()
				for i, v := range verdicts {
					sc := scenarios[i]
					fmt.Print(honeypot.RenderHoneypotScorecard(v, sc.SessionID, sc.AgentID, sc.ToolName))
					if *mermaid {
						fmt.Println(honeypot.RenderHoneypotMermaid(v.TrapEvent))
					}
				}
				fmt.Printf("\n\033[1;32m✓ Honeypot Demo Complete.\033[0m Evaluated %d scenarios (%d traps triggered, %d sessions quarantined).\n\n",
					summary.TotalEvaluated, summary.TrapsTriggered, summary.SessionsLocked)
			}

			if *strict && summary.TrapsTriggered > 0 {
				os.Exit(1)
			}
			return
		}

		var args map[string]interface{}
		if err := json.Unmarshal([]byte(*argsJSON), &args); err != nil {
			log.Fatalf("Invalid JSON in -args: %v", err)
		}

		role := rbac.AgentRole(*roleStr)
		verdict := engine.InterceptToolCall(*sessionID, *agentID, role, *toolName, args)

		switch *format {
		case "json":
			bytes, _ := json.MarshalIndent(verdict, "", "  ")
			fmt.Println(string(bytes))
		default:
			fmt.Print(honeypot.RenderHoneypotScorecard(verdict, *sessionID, *agentID, *toolName))
			if *mermaid {
				fmt.Println(honeypot.RenderHoneypotMermaid(verdict.TrapEvent))
			}
		}

		if *strict && (verdict.IsHoneypotHit || verdict.SessionLocked) {
			os.Exit(1)
		}
		return

	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println("MCPGate — Zero-Trust Model Context Protocol (MCP) Security Gateway & Prompt Injection Firewall")
	fmt.Println("\nCommands:")
	fmt.Println("  inspect     Intercept and evaluate a tool call through RBAC, firewall, and secret redaction")
	fmt.Println("  honeypot    Deploy canary honeytools, detect token exfiltration & synthesize deceptive responses")
	fmt.Println("  risk        Evaluate multi-dimensional blast radius, velocity burst containment & cumulative session risk")
	fmt.Println("  provenance  Verify Ed25519 request signing, prevent replay attacks, and issue attestation receipts")
	fmt.Println("  redact      Run ephemeral secret vault, high-entropy detector & bi-directional DLP engine")
	fmt.Println("  ratelimit   Run dynamic token bucket rate limiter, concurrency governor & burst containment engine")
	fmt.Println("  injectbench Run standardized MCP prompt injection & tool poisoning security benchmarks")
	fmt.Println("  policy      Evaluate declarative zero-trust policies, lint manifests, or run demo suite")
	fmt.Println("  fuzz        Run adversarial attack fuzzing suite across 8 vulnerability classes")
	fmt.Println("  proxy       Run inline stdio reverse-proxy intercepting live JSON-RPC 2.0 tool execution")
	fmt.Println("  serve       Start high-performance HTTP & SSE reverse-proxy for remote MCP servers")
	fmt.Println("  audit       Verify cryptographic hash chain integrity of the audit ledger")
	fmt.Println("  rules       List active security policies, banned patterns, and redaction schemas")
	fmt.Println("\nExamples:")
	fmt.Println("  mcpgate honeypot [--demo] [--mermaid] [--format text|markdown|json]")
	fmt.Println("  mcpgate honeypot -check -session sess_1 -agent agent_1 -tool admin_export_vault_credentials")
	fmt.Println("  mcpgate risk [--demo] [--mermaid] [--format text|markdown|json]")
	fmt.Println("  mcpgate risk -check -agent agent_1 -role standard -tool bash_exec -args '{\"cmd\": \"rm -rf /\"}'")
	fmt.Println("  mcpgate provenance [--demo] [--mermaid] [--format text|markdown|json]")
	fmt.Println("  mcpgate provenance -verify receipt.json")
	fmt.Println("  mcpgate redact [--demo] [--mode vault|mask|block] [--format text|markdown|json]")
	fmt.Println("  mcpgate redact -text 'sk-ant-123...' --mode vault")
	fmt.Println("  mcpgate ratelimit [--demo] [--format text|markdown|json]")
	fmt.Println("  mcpgate ratelimit check -agent agent_1 -tool bash_exec -cost 1.0")
	fmt.Println("  mcpgate injectbench [--iter 100] [--strict] [--format text|markdown|json]")
	fmt.Println("  mcpgate inspect -agent agent_1 -role standard -tool read_file -args '{\"path\": \"main.go\"}'")
	fmt.Println("  mcpgate policy --demo [-strict] [--mermaid]")
	fmt.Println("  mcpgate policy lint -policy rules.json")
	fmt.Println("  mcpgate policy eval -agent agent_1 -role standard -tool fetch_url -args '{\"url\": \"http://example.com\"}'")
	fmt.Println("  mcpgate fuzz [-role standard] [-strict] [-mermaid]")
	fmt.Println("  mcpgate proxy -agent agent_worker -role standard")
	fmt.Println("  mcpgate serve --port 8089 --upstream http://localhost:8080")
	fmt.Println("  mcpgate audit -file ./.audit/mcpgate_audit.jsonl -strict")
	fmt.Println("  mcpgate rules")
}
