package risk

import (
	"sync"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

func TestToolScorer_DefaultProfiles(t *testing.T) {
	scorer := NewToolScorer()

	// 1. Safe read tool
	score, dims, factors, requiresHITL := scorer.EvaluateToolCall("read_file", map[string]interface{}{"path": "test.txt"})
	if score > 15.0 {
		t.Errorf("expected read_file to have low score <= 15.0, got %f", score)
	}
	if dims.Filesystem <= 0 {
		t.Errorf("expected filesystem dimension > 0")
	}
	if requiresHITL {
		t.Errorf("read_file should not require HITL")
	}
	if len(factors) != 0 {
		t.Errorf("expected zero risk factors for benign read, got %v", factors)
	}

	// 2. Destructive command
	score, _, factors, requiresHITL = scorer.EvaluateToolCall("bash_exec", map[string]interface{}{"cmd": "rm -rf /var/log/*"})
	if score < 70.0 {
		t.Errorf("expected destructive command score >= 70.0, got %f", score)
	}
	if !requiresHITL {
		t.Errorf("destructive command must require HITL")
	}
	foundDestructive := false
	for _, f := range factors {
		if f == "destructive_unrecoverable_command" {
			foundDestructive = true
			break
		}
	}
	if !foundDestructive {
		t.Errorf("expected destructive_unrecoverable_command risk factor, got %v", factors)
	}

	// 3. Cloud metadata SSRF
	score, dims, factors, requiresHITL = scorer.EvaluateToolCall("fetch_url", map[string]interface{}{"url": "http://169.254.169.254/latest/meta-data"})
	if score < 50.0 {
		t.Errorf("expected cloud metadata SSRF score >= 50.0, got %f", score)
	}
	if dims.Network <= 0 {
		t.Errorf("expected network dimension contribution")
	}
	if !requiresHITL {
		t.Errorf("cloud metadata target must require HITL")
	}

	// 4. Financial transfer
	score, dims, factors, requiresHITL = scorer.EvaluateToolCall("transfer_funds", map[string]interface{}{"amount": 2500.0})
	if score < 80.0 {
		t.Errorf("expected large transfer score >= 80.0, got %f", score)
	}
	if dims.Financial <= 0 {
		t.Errorf("expected financial dimension contribution")
	}
	if !requiresHITL {
		t.Errorf("financial transfer must require HITL")
	}
}

func TestRiskGovernor_DecayKinetics(t *testing.T) {
	cfg := DefaultRiskGovernorConfig()
	cfg.HalfLifeDecay = 100 * time.Millisecond // Fast half-life for testing
	governor := NewRiskGovernor(cfg, NewToolScorer())

	sessionID := "test_decay_sess"

	// Commit 60 points
	governor.CommitToolExecution(sessionID, "write_file", 60.0)

	state, ok := governor.GetSessionState(sessionID)
	if !ok {
		t.Fatalf("session not found")
	}
	if state.CumulativeScore < 59.0 || state.CumulativeScore > 60.1 {
		t.Fatalf("expected initial cumulative score ~60.0, got %f", state.CumulativeScore)
	}

	// Sleep for ~1 half-life
	time.Sleep(120 * time.Millisecond)

	state, ok = governor.GetSessionState(sessionID)
	if !ok {
		t.Fatalf("session not found")
	}

	// Score should have decayed to approximately half (~30 pts, +/- 10)
	if state.CumulativeScore >= 55.0 || state.CumulativeScore <= 15.0 {
		t.Errorf("expected decayed score between 15 and 55, got %f", state.CumulativeScore)
	}
}

func TestRiskGovernor_VelocityBurstQuarantine(t *testing.T) {
	cfg := DefaultRiskGovernorConfig()
	cfg.VelocityWindow = 5 * time.Second
	cfg.VelocityThreshold = 40.0 // Burst limit 40 points
	governor := NewRiskGovernor(cfg, NewToolScorer())

	sessionID := "test_burst_sess"
	agentID := "agent_burst"

	// Call 1: write_file (score ~25)
	a1 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "write_file", map[string]interface{}{"path": "test1.txt"})
	if a1.Verdict != VerdictAllowed {
		t.Fatalf("call 1 should be allowed, got %v", a1.Verdict)
	}
	governor.CommitToolExecution(sessionID, "write_file", a1.InstantaneousScore)

	// Call 2: immediately call another write_file (score ~25, cumulative velocity ~50 > 40)
	a2 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "write_file", map[string]interface{}{"path": "test2.txt"})
	if a2.Verdict != VerdictQuarantinedBlock {
		t.Fatalf("call 2 should trigger velocity burst quarantine, got %v", a2.Verdict)
	}

	// Verify session state is marked quarantined
	state, ok := governor.GetSessionState(sessionID)
	if !ok || !state.IsQuarantined {
		t.Fatalf("session should be quarantined")
	}

	// Call 3: subsequent call is blocked due to quarantine
	a3 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "read_file", map[string]interface{}{"path": "test3.txt"})
	if a3.Verdict != VerdictQuarantinedBlock {
		t.Fatalf("call 3 should be blocked by quarantine, got %v", a3.Verdict)
	}

	// Approve step-up to lift quarantine
	unlocked := governor.ApproveStepUp(sessionID)
	if !unlocked {
		t.Fatalf("failed to lift quarantine")
	}

	state, ok = governor.GetSessionState(sessionID)
	if !ok || state.IsQuarantined {
		t.Fatalf("quarantine should be lifted")
	}
}

func TestRiskGovernor_CumulativeBudgetWarningAndBlock(t *testing.T) {
	cfg := DefaultRiskGovernorConfig()
	cfg.SessionRiskBudget = 50.0 // 50 point budget
	cfg.WarningThresholdPct = 60.0 // 30 points warning
	cfg.VelocityThreshold = 1000.0 // disable velocity trigger
	governor := NewRiskGovernor(cfg, NewToolScorer())

	sessionID := "test_budget_sess"
	agentID := "agent_budget"

	// Call 1: 25 points -> projected 25 < 30 warning -> Allowed
	a1 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "write_file", map[string]interface{}{})
	if a1.Verdict != VerdictAllowed {
		t.Errorf("expected VerdictAllowed, got %v", a1.Verdict)
	}
	governor.CommitToolExecution(sessionID, "write_file", 25.0)

	// Call 2: 25 points -> projected 50 >= 30 warning (and <= 50 budget) -> VerdictWarning
	a2 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "write_file", map[string]interface{}{})
	if a2.Verdict != VerdictWarning {
		t.Errorf("expected VerdictWarning, got %v", a2.Verdict)
	}
	governor.CommitToolExecution(sessionID, "write_file", 25.0)

	// Call 3: 25 points -> projected 75 > 50 budget -> VerdictStepUpApproval or VerdictQuarantinedBlock
	a3 := governor.AssessToolCall(sessionID, agentID, rbac.RoleStandard, "write_file", map[string]interface{}{})
	if a3.Verdict != VerdictStepUpApproval && a3.Verdict != VerdictQuarantinedBlock {
		t.Errorf("expected StepUp or Block, got %v", a3.Verdict)
	}
}

func TestRiskGovernor_Concurrency(t *testing.T) {
	cfg := DefaultRiskGovernorConfig()
	cfg.VelocityThreshold = 5000.0
	cfg.SessionRiskBudget = 10000.0
	governor := NewRiskGovernor(cfg, NewToolScorer())

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sessionID := "concurrent_sess"
			for i := 0; i < iterations; i++ {
				a := governor.AssessToolCall(sessionID, "agent_concurrent", rbac.RoleAdmin, "read_file", map[string]interface{}{"idx": i})
				if a == nil {
					t.Errorf("got nil assessment")
					return
				}
				governor.CommitToolExecution(sessionID, "read_file", 1.0)
			}
		}(w)
	}

	wg.Wait()

	state, ok := governor.GetSessionState("concurrent_sess")
	if !ok {
		t.Fatalf("session not found")
	}

	expectedTotal := workers * iterations
	if state.TotalCalls != expectedTotal {
		t.Errorf("expected %d total calls, got %d", expectedTotal, state.TotalCalls)
	}
}
