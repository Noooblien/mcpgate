package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/anomaly"
)

func TestIntegration_Anomaly_DemoSuite(t *testing.T) {
	policy := anomaly.DefaultAnomalyPolicy()
	summary := anomaly.RunDemoSuite(policy)

	if summary.TotalEvaluated != 4 {
		t.Fatalf("expected 4 scenarios evaluated, got %d", summary.TotalEvaluated)
	}

	if summary.Allowed != 1 {
		t.Errorf("expected exactly 1 allowed clean scenario, got %d", summary.Allowed)
	}

	if summary.Blocked+summary.Quarantined < 2 {
		t.Errorf("expected at least 2 blocked or quarantined scenarios, got %d", summary.Blocked+summary.Quarantined)
	}

	// Verify scorecard rendering
	scorecard := anomaly.RenderAnomalyScorecard(summary)
	if !strings.Contains(scorecard, "MCPGATE BEHAVIORAL TOOL ANOMALY") {
		t.Errorf("scorecard output missing title")
	}

	// Verify Mermaid state transition graph rendering
	mermaid := anomaly.RenderAnomalyMermaid(summary.Assessments)
	if !strings.Contains(mermaid, "stateDiagram-v2") {
		t.Errorf("mermaid output missing stateDiagram-v2")
	}

	// Verify Markdown audit report rendering
	md := anomaly.RenderAnomalyMarkdownReport(summary)
	if !strings.Contains(md, "Detailed Assessment Breakdown") {
		t.Errorf("markdown report missing Detailed Assessment Breakdown")
	}
}

func TestIntegration_Anomaly_PipelineInterception(t *testing.T) {
	policy := anomaly.DefaultAnomalyPolicy()
	detector := anomaly.NewDetector(policy)
	agentID := "agent-pipeline-interceptor"
	sessionID := "sess-live-9900"

	// 1. Train normal baseline
	for i := 0; i < 15; i++ {
		detector.RecordObservation(anomaly.ToolCallObservation{
			SessionID: sessionID,
			AgentID:   agentID,
			ToolName:  "list_files",
			Arguments: map[string]interface{}{"path": "/workspace"},
			Timestamp: time.Now(),
		})
		detector.RecordObservation(anomaly.ToolCallObservation{
			SessionID: sessionID,
			AgentID:   agentID,
			ToolName:  "read_file",
			PriorTool: "list_files",
			Arguments: map[string]interface{}{"path": "/workspace/main.go"},
			Timestamp: time.Now(),
		})
	}

	// 2. Normal sequential call: list_files -> read_file
	obsNormal := anomaly.ToolCallObservation{
		ObservationID: "live-step-1",
		SessionID:     sessionID,
		AgentID:       agentID,
		ToolName:      "read_file",
		PriorTool:     "list_files",
		Arguments:     map[string]interface{}{"path": "/workspace/main.go"},
		Timestamp:     time.Now(),
	}
	resNormal := detector.Evaluate(obsNormal)
	if resNormal.Verdict != anomaly.VerdictAllow {
		t.Errorf("expected clean sequential call to be allowed, got %s (score: %.3f)", resNormal.Verdict, resNormal.CompositeScore)
	}

	// 3. Rogue abrupt transition jump: read_file -> wipe_disk
	obsRogue := anomaly.ToolCallObservation{
		ObservationID: "live-step-2",
		SessionID:     sessionID,
		AgentID:       agentID,
		ToolName:      "wipe_disk",
		PriorTool:     "read_file",
		Arguments:     map[string]interface{}{"force": true},
		Timestamp:     time.Now(),
	}
	resRogue := detector.Evaluate(obsRogue)
	if resRogue.Verdict != anomaly.VerdictBlock && resRogue.Verdict != anomaly.VerdictQuarantine {
		t.Errorf("expected wipe_disk jump to be blocked or quarantined, got %s (score: %.3f)", resRogue.Verdict, resRogue.CompositeScore)
	}
}
