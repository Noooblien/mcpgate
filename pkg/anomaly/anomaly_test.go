package anomaly

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMarkovTransitionAnomaly(t *testing.T) {
	policy := DefaultAnomalyPolicy()
	detector := NewDetector(policy)
	agentID := "agent-test-seq"

	// Train sequence: toolA -> toolB 20 times
	for i := 0; i < 20; i++ {
		detector.RecordObservation(ToolCallObservation{
			SessionID: "s1",
			AgentID:   agentID,
			ToolName:  "toolA",
			Arguments: map[string]interface{}{"k": "v"},
		})
		detector.RecordObservation(ToolCallObservation{
			SessionID: "s1",
			AgentID:   agentID,
			ToolName:  "toolB",
			PriorTool: "toolA",
			Arguments: map[string]interface{}{"k": "v"},
		})
	}

	// 1. Evaluate normal transition toolA -> toolB
	obsClean := ToolCallObservation{
		SessionID: "s2",
		AgentID:   agentID,
		ToolName:  "toolB",
		PriorTool: "toolA",
		Arguments: map[string]interface{}{"k": "v"},
	}
	resClean := detector.Evaluate(obsClean)
	if resClean.SequenceAnomalyScore > 0.40 {
		t.Fatalf("Expected low sequence anomaly for trained transition, got %.3f", resClean.SequenceAnomalyScore)
	}

	// 2. Evaluate unprecedented transition toolA -> dangerousToolX
	obsJump := ToolCallObservation{
		SessionID: "s2",
		AgentID:   agentID,
		ToolName:  "dangerousToolX",
		PriorTool: "toolA",
		Arguments: map[string]interface{}{"k": "v"},
	}
	resJump := detector.Evaluate(obsJump)
	if resJump.SequenceAnomalyScore < 0.80 {
		t.Fatalf("Expected high sequence anomaly for unprecedented transition jump, got %.3f", resJump.SequenceAnomalyScore)
	}
}

func TestPayloadLengthZScore(t *testing.T) {
	policy := DefaultAnomalyPolicy()
	detector := NewDetector(policy)
	agentID := "agent-test-payload"

	// Train tool with small payload lengths ~50 chars
	for i := 0; i < 20; i++ {
		detector.RecordObservation(ToolCallObservation{
			SessionID: "s1",
			AgentID:   agentID,
			ToolName:  "standard_tool",
			Arguments: map[string]interface{}{"data": "short string payload"},
		})
	}

	// Evaluate massive 100KB payload
	massivePayload := strings.Repeat("A", 100000)
	obsMassive := ToolCallObservation{
		SessionID: "s2",
		AgentID:   agentID,
		ToolName:  "standard_tool",
		Arguments: map[string]interface{}{"data": massivePayload},
	}
	resMassive := detector.Evaluate(obsMassive)
	if resMassive.PayloadAnomalyScore < 0.90 {
		t.Fatalf("Expected near-maximum payload anomaly for 100KB payload, got %.3f", resMassive.PayloadAnomalyScore)
	}
}

func TestShannonEntropy(t *testing.T) {
	lowEntropy := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	highEntropy := []byte("!@#$%^&*()_+1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~`{}|[]\\:\";'<>?,./")

	hLow := CalculateShannonEntropy(lowEntropy)
	hHigh := CalculateShannonEntropy(highEntropy)

	if hLow > 0.5 {
		t.Fatalf("Expected very low entropy for repeated bytes, got %.2f", hLow)
	}
	if hHigh < 5.0 {
		t.Fatalf("Expected high entropy for diverse byte distribution, got %.2f", hHigh)
	}
}

func TestParameterKeyAnomaly(t *testing.T) {
	policy := DefaultAnomalyPolicy()
	detector := NewDetector(policy)
	agentID := "agent-test-params"

	// Train with legitimate keys
	for i := 0; i < 20; i++ {
		detector.RecordObservation(ToolCallObservation{
			SessionID: "s1",
			AgentID:   agentID,
			ToolName:  "fetch_user",
			Arguments: map[string]interface{}{"user_id": "123", "fields": "name,email"},
		})
	}

	// Evaluate injected malicious keys
	obsInjected := ToolCallObservation{
		SessionID: "s2",
		AgentID:   agentID,
		ToolName:  "fetch_user",
		Arguments: map[string]interface{}{
			"user_id":          "123",
			"__proto__":        "polluted",
			"eval_code":        "os.exit(1)",
			"raw_sql_override": "DROP TABLE users",
		},
	}
	resInjected := detector.Evaluate(obsInjected)
	if resInjected.ParameterAnomalyScore < 0.50 {
		t.Fatalf("Expected high parameter anomaly for injected keys, got %.3f", resInjected.ParameterAnomalyScore)
	}
}

func TestQuarantineAndRelease(t *testing.T) {
	policy := DefaultAnomalyPolicy()
	policy.QuarantineThreshold = 0.50
	policy.BlockThreshold = 0.95
	detector := NewDetector(policy)
	agentID := "agent-test-quarantine"

	// Train minimal baseline
	for i := 0; i < 10; i++ {
		detector.RecordObservation(ToolCallObservation{
			SessionID: "s1",
			AgentID:   agentID,
			ToolName:  "safe_tool",
			Arguments: map[string]interface{}{"status": "ok"},
		})
	}

	// Trigger quarantine via unprecedented jump and strange parameters
	obsTrigger := ToolCallObservation{
		SessionID: "s2",
		AgentID:   agentID,
		ToolName:  "unseen_exfil",
		PriorTool: "safe_tool",
		Arguments: map[string]interface{}{
			"alien_key_1": "abc",
			"alien_key_2": "def",
		},
	}
	res := detector.Evaluate(obsTrigger)
	if res.Verdict != VerdictQuarantine {
		t.Fatalf("Expected VerdictQuarantine, got %s (Score: %.3f)", res.Verdict, res.CompositeScore)
	}

	if !detector.IsAgentQuarantined(agentID) {
		t.Fatalf("Agent should be quarantined in detector state")
	}

	// Next call should immediately be locked under quarantine
	obsLocked := ToolCallObservation{
		SessionID: "s3",
		AgentID:   agentID,
		ToolName:  "safe_tool",
		Arguments: map[string]interface{}{"status": "ok"},
	}
	resLocked := detector.Evaluate(obsLocked)
	if resLocked.Verdict != VerdictQuarantine {
		t.Fatalf("Expected call to be locked by quarantine, got %s", resLocked.Verdict)
	}

	// Release quarantine
	detector.ReleaseQuarantine(agentID)
	if detector.IsAgentQuarantined(agentID) {
		t.Fatalf("Agent should no longer be quarantined after release")
	}
}

func TestConcurrentEvaluations(t *testing.T) {
	policy := DefaultAnomalyPolicy()
	detector := NewDetector(policy)
	agentID := "agent-concurrent"

	// Train baseline
	for i := 0; i < 10; i++ {
		detector.RecordObservation(ToolCallObservation{
			SessionID: "train",
			AgentID:   agentID,
			ToolName:  "tool1",
			Arguments: map[string]interface{}{"key": "val"},
		})
	}

	var wg sync.WaitGroup
	workers := 50
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(id int) {
			defer wg.Done()
			obs := ToolCallObservation{
				ObservationID: "conc-obs",
				SessionID:     "conc-sess",
				AgentID:       agentID,
				ToolName:      "tool1",
				Arguments:     map[string]interface{}{"key": "val"},
				Timestamp:     time.Now(),
			}
			res := detector.Evaluate(obs)
			if res == nil {
				t.Errorf("Worker %d got nil assessment", id)
			}
		}(i)
	}
	wg.Wait()
}

func TestDemoSuiteExecution(t *testing.T) {
	policy := DefaultAnomalyPolicy()
	summary := RunDemoSuite(policy)

	if summary.TotalEvaluated != 4 {
		t.Fatalf("Expected 4 scenarios evaluated, got %d", summary.TotalEvaluated)
	}
	if summary.Allowed == 0 {
		t.Fatalf("Expected at least 1 allowed scenario, got %d", summary.Allowed)
	}
	if summary.Blocked+summary.Quarantined == 0 {
		t.Fatalf("Expected high-risk scenarios to be blocked or quarantined, got 0")
	}

	scorecard := RenderAnomalyScorecard(summary)
	if !strings.Contains(scorecard, "MCPGATE BEHAVIORAL TOOL ANOMALY") {
		t.Fatalf("Scorecard missing expected header title")
	}

	mermaid := RenderAnomalyMermaid(summary.Assessments)
	if !strings.Contains(mermaid, "stateDiagram-v2") {
		t.Fatalf("Mermaid diagram missing expected stateDiagram-v2 tag")
	}

	markdown := RenderAnomalyMarkdownReport(summary)
	if !strings.Contains(markdown, "Executive Summary") {
		t.Fatalf("Markdown report missing Executive Summary")
	}
}
