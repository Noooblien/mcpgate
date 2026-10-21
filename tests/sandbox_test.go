package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/sandbox"
)

func TestIntegration_Sandbox_DemoSuite(t *testing.T) {
	summary := sandbox.RunSandboxDemo()

	if summary.TotalEvaluated != 4 {
		t.Fatalf("expected 4 evaluated scenarios, got %d", summary.TotalEvaluated)
	}

	if summary.AllowedCount != 1 {
		t.Errorf("expected 1 authorized clean invocation, got %d", summary.AllowedCount)
	}
	if summary.BlockedCount != 3 {
		t.Errorf("expected 3 quarantined dangerous invocations, got %d", summary.BlockedCount)
	}

	scorecard := sandbox.RenderSandboxScorecard(summary)
	if !strings.Contains(scorecard, "VIRTUAL TOOL SANDBOX") {
		t.Errorf("scorecard missing header in integration test")
	}

	mermaid := sandbox.RenderSandboxMermaid(summary)
	if !strings.Contains(mermaid, "flowchart TD") {
		t.Errorf("mermaid missing flowchart TD in integration test")
	}

	md := sandbox.RenderSandboxMarkdown(summary)
	if !strings.Contains(md, "MCPGate Virtual Tool Sandbox & Path Jail Isolation Report") {
		t.Errorf("markdown report missing expected heading")
	}
}

func TestIntegration_Sandbox_LiveInspection(t *testing.T) {
	cfg := sandbox.DefaultSandboxConfig()
	engine := sandbox.NewEngine(cfg)

	// Clean workspace file read
	cleanReq := sandbox.SandboxRequest{
		RequestID: "req_live_01",
		AgentID:   "agent_audit",
		ToolName:  "read_file",
		Path:      "/workspace/src/index.ts",
		Timestamp: time.Now(),
	}
	evalClean := engine.Evaluate(cleanReq)
	if !evalClean.IsAllowed {
		t.Fatalf("expected clean workspace read to be allowed: %s", evalClean.ContainmentNote)
	}

	// Hostile chroot escape attempt
	escapeReq := sandbox.SandboxRequest{
		RequestID: "req_live_02",
		AgentID:   "agent_audit",
		ToolName:  "run_command",
		Command:   "cat /proc/self/environ",
		Timestamp: time.Now(),
	}
	evalEscape := engine.Evaluate(escapeReq)
	if evalEscape.IsAllowed {
		t.Fatalf("expected access to /proc to be quarantined")
	}
}
