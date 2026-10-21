package tests

import (
	"strings"
	"testing"

	"github.com/Noooblien/mcpgate/pkg/rbac"
	"github.com/Noooblien/mcpgate/pkg/risk"
)

func TestIntegration_RiskGovernor_DemoSuite(t *testing.T) {
	assessments, err := risk.RunDemoSuite()
	if err != nil {
		t.Fatalf("failed to run demo suite: %v", err)
	}

	if len(assessments) == 0 {
		t.Fatalf("expected assessments from demo suite, got 0")
	}

	foundAllowed := false
	foundStepUp := false
	foundQuarantined := false

	for _, a := range assessments {
		if a.AssessmentID == "" {
			t.Errorf("assessment ID is empty")
		}
		if a.ToolName == "" {
			t.Errorf("tool name is empty")
		}
		if a.RiskLevel == "" {
			t.Errorf("risk level is empty")
		}

		switch a.Verdict {
		case risk.VerdictAllowed:
			foundAllowed = true
		case risk.VerdictStepUpApproval:
			foundStepUp = true
		case risk.VerdictQuarantinedBlock:
			foundQuarantined = true
		}

		scorecard := risk.RenderRiskScorecard(a)
		if len(scorecard) == 0 || !strings.Contains(scorecard, "SCORECARD") {
			t.Errorf("invalid scorecard generated for %s", a.ToolName)
		}

		mermaid := risk.RenderRiskMermaid(a)
		if len(mermaid) == 0 || !strings.Contains(mermaid, "flowchart TD") {
			t.Errorf("invalid mermaid diagram generated for %s", a.ToolName)
		}
	}

	if !foundAllowed {
		t.Errorf("expected at least one allowed assessment in demo suite")
	}
	if !foundStepUp {
		t.Errorf("expected at least one step-up approval assessment in demo suite")
	}
	if !foundQuarantined {
		t.Errorf("expected at least one quarantined assessment in demo suite")
	}

	report := risk.RenderMarkdownReport(assessments)
	if !strings.Contains(report, "MCPGate Adaptive Blast Radius & Risk Governor Report") {
		t.Errorf("markdown report missing expected header")
	}
}

func TestIntegration_RiskGovernor_EndToEndLifecyle(t *testing.T) {
	cfg := risk.DefaultRiskGovernorConfig()
	governor := risk.NewRiskGovernor(cfg, risk.NewToolScorer())

	sessionID := "integ_session_e2e"
	agentID := "agent_integ"

	// 1. Initial tool call within budget
	a1 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "read_file", map[string]interface{}{"path": "test.txt"})
	if a1.Verdict != risk.VerdictAllowed {
		t.Fatalf("expected allowed for read_file, got %s", a1.Verdict)
	}
	governor.CommitToolExecution(sessionID, a1.ToolName, a1.InstantaneousScore)

	// 2. Destructive execution requires HITL step up
	a2 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "bash_exec", map[string]interface{}{"cmd": "rm -rf /var/log"})
	if a2.Verdict != risk.VerdictStepUpApproval {
		t.Fatalf("expected step up for destructive bash, got %s", a2.Verdict)
	}

	// 3. Reset session returns cumulative score to zero
	governor.ResetSession(sessionID)
	state, exists := governor.GetSessionState(sessionID)
	if exists && state.CumulativeScore > 0 {
		t.Fatalf("expected reset session to have zero score, got %f", state.CumulativeScore)
	}
}
