package tests

import (
	"strings"
	"testing"

	"github.com/Noooblien/mcpgate/pkg/honeypot"
	"github.com/Noooblien/mcpgate/pkg/rbac"
)

func TestIntegration_Honeypot_DemoSuite(t *testing.T) {
	summary, verdicts, err := honeypot.RunDemoSuite()
	if err != nil {
		t.Fatalf("failed to run honeypot demo suite: %v", err)
	}

	if summary.TotalEvaluated != len(honeypot.GetDemoScenarios()) {
		t.Fatalf("expected %d evaluated scenarios, got %d", len(honeypot.GetDemoScenarios()), summary.TotalEvaluated)
	}

	if summary.TrapsTriggered != 3 {
		t.Errorf("expected 3 traps triggered, got %d", summary.TrapsTriggered)
	}

	if summary.DecoyToolHits != 2 {
		t.Errorf("expected 2 decoy tool hits, got %d", summary.DecoyToolHits)
	}

	if summary.CanaryTokenHits != 1 {
		t.Errorf("expected 1 canary token hit, got %d", summary.CanaryTokenHits)
	}

	if summary.SessionsLocked < 1 {
		t.Errorf("expected at least 1 session locked, got %d", summary.SessionsLocked)
	}

	if summary.CleanPassed != 1 {
		t.Errorf("expected 1 clean passed scenario, got %d", summary.CleanPassed)
	}

	for _, v := range verdicts {
		scorecard := honeypot.RenderHoneypotScorecard(v, "sess-test", "agent-test", "tool-test")
		if len(scorecard) == 0 || !strings.Contains(scorecard, "MCPGATE HONEYPOT") {
			t.Errorf("invalid scorecard generated")
		}

		mermaid := honeypot.RenderHoneypotMermaid(v.TrapEvent)
		if len(mermaid) == 0 || (!strings.Contains(mermaid, "sequenceDiagram") && !strings.Contains(mermaid, "graph TD")) {
			t.Errorf("invalid mermaid diagram generated")
		}
	}

	mdReport := honeypot.RenderMarkdownReport(summary)
	if !strings.Contains(mdReport, "MCPGate Honeypot & Adversarial Deception Report") {
		t.Errorf("markdown report missing expected header")
	}
}

func TestIntegration_Honeypot_LiveInterceptionFlow(t *testing.T) {
	engine := honeypot.NewEngine(honeypot.HoneypotConfig{
		Enabled:               true,
		AutoQuarantineSession: true,
	})

	// 1. Injected tools list includes canary tools
	realTools := []map[string]interface{}{
		{"name": "fetch_web", "description": "Fetches a URL"},
	}
	decorated := engine.InjectToolsList(realTools)
	if len(decorated) <= 1 {
		t.Fatalf("expected decorated tool list to contain canary tools")
	}

	// 2. Normal call succeeds
	cleanVerdict := engine.InterceptToolCall("sess-live-01", "agent-worker", rbac.RoleStandard, "fetch_web", map[string]interface{}{
		"url": "https://docs.anthropic.com",
	})
	if !cleanVerdict.Allowed {
		t.Fatalf("expected clean call to be allowed, got blocked: %s", cleanVerdict.Reason)
	}

	// 3. Attack call trips canary honeypot
	honeypotVerdict := engine.InterceptToolCall("sess-live-01", "agent-worker", rbac.RoleStandard, "admin_export_vault_credentials", map[string]interface{}{
		"vault_path": "secret/prod/keys",
	})
	if honeypotVerdict.Allowed {
		t.Fatalf("expected honeypot call to be blocked")
	}
	if !honeypotVerdict.IsHoneypotHit {
		t.Fatalf("expected IsHoneypotHit to be true")
	}
	if !honeypotVerdict.SessionLocked {
		t.Fatalf("expected SessionLocked to be true")
	}

	// 4. Subsequent innocent call is locked out by quarantine
	lockedVerdict := engine.InterceptToolCall("sess-live-01", "agent-worker", rbac.RoleStandard, "fetch_web", map[string]interface{}{
		"url": "https://golang.org",
	})
	if lockedVerdict.Allowed {
		t.Fatalf("expected quarantined session to block subsequent calls")
	}
	if !lockedVerdict.SessionLocked {
		t.Fatalf("expected session to remain locked")
	}
}
