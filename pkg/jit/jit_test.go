package jit

import (
	"strings"
	"testing"
	"time"
)

func TestAutoApproveLowRisk(t *testing.T) {
	engine := NewEngine(DefaultJITConfig())

	req := JITRequest{
		AgentID:       "agent_reader",
		ToolName:      "diagnostics.query_metrics",
		Args:          map[string]interface{}{"metric": "cpu_utilization"},
		Justification: "Read metrics",
		RequestedTTL:  30 * time.Second,
	}

	lease, err := engine.RequestLease(req)
	if err != nil {
		t.Fatalf("expected lease grant, got error: %v", err)
	}

	if lease.Status != StatusActive {
		t.Errorf("expected StatusActive for low risk, got %s", lease.Status)
	}

	// Validate and consume
	res := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if !res.ExecutionAllowed {
		t.Fatalf("expected execution allowed, got reason: %s", res.Reason)
	}
	if res.Status != StatusConsumed {
		t.Errorf("expected StatusConsumed after execution, got %s", res.Status)
	}
}

func TestStepUpHighRisk(t *testing.T) {
	engine := NewEngine(DefaultJITConfig())

	req := JITRequest{
		AgentID:       "agent_admin",
		ToolName:      "database.drop_table",
		Args:          map[string]interface{}{"table": "users_backup"},
		Justification: "Schema cleanup",
		RequestedTTL:  60 * time.Second,
	}

	lease, err := engine.RequestLease(req)
	if err != nil {
		t.Fatalf("unexpected error requesting lease: %v", err)
	}

	if lease.Status != StatusPendingApproval {
		t.Fatalf("expected StatusPendingApproval for critical tool, got %s", lease.Status)
	}

	// Execution before approval must fail
	resBlocked := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if resBlocked.ExecutionAllowed {
		t.Fatalf("expected execution blocked pending approval")
	}
	if resBlocked.ViolationCode != "ERR_STEP_UP_REQUIRED" {
		t.Errorf("expected ERR_STEP_UP_REQUIRED, got %s", resBlocked.ViolationCode)
	}

	// Supervisor approves
	approvedLease, err := engine.ApproveStepUp(lease.LeaseID, "security_officer")
	if err != nil {
		t.Fatalf("step-up approval failed: %v", err)
	}
	if approvedLease.Status != StatusActive {
		t.Errorf("expected StatusActive after approval, got %s", approvedLease.Status)
	}

	// Now execution succeeds
	resAllowed := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if !resAllowed.ExecutionAllowed {
		t.Fatalf("expected execution allowed after approval, got: %s", resAllowed.Reason)
	}
}

func TestParameterSubstitutionAttack(t *testing.T) {
	engine := NewEngine(DefaultJITConfig())

	req := JITRequest{
		AgentID:       "agent_deploy",
		ToolName:      "github.merge_pr",
		Args:          map[string]interface{}{"pull_number": 42},
		Justification: "Merge verified PR",
	}

	lease, _ := engine.RequestLease(req)
	_, _ = engine.ApproveStepUp(lease.LeaseID, "lead_reviewer")

	// Attacker tampers with PR number using valid lease
	tamperedArgs := map[string]interface{}{"pull_number": 999}
	res := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, tamperedArgs)

	if res.ExecutionAllowed {
		t.Fatalf("parameter substitution attack should have been blocked!")
	}
	if res.ViolationCode != "ERR_PARAMETER_SUBSTITUTION_ATTACK" {
		t.Errorf("expected ERR_PARAMETER_SUBSTITUTION_ATTACK, got %s", res.ViolationCode)
	}
}

func TestReplayAttackDefense(t *testing.T) {
	engine := NewEngine(DefaultJITConfig())

	req := JITRequest{
		AgentID:       "agent_worker",
		ToolName:      "diagnostics.query_metrics",
		Args:          map[string]interface{}{"service": "auth"},
		Justification: "Query logs",
	}

	lease, _ := engine.RequestLease(req)

	// First execution succeeds
	res1 := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if !res1.ExecutionAllowed {
		t.Fatalf("first execution should succeed: %s", res1.Reason)
	}

	// Replay attempt fails
	res2 := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if res2.ExecutionAllowed {
		t.Fatalf("replay of consumed lease should be blocked!")
	}
	if res2.ViolationCode != "ERR_LEASE_REPLAY_ATTEMPT" {
		t.Errorf("expected ERR_LEASE_REPLAY_ATTEMPT, got %s", res2.ViolationCode)
	}
}

func TestLeaseExpiration(t *testing.T) {
	cfg := DefaultJITConfig()
	cfg.DefaultTTL = 10 * time.Millisecond // ultra-short TTL for test
	engine := NewEngine(cfg)

	req := JITRequest{
		AgentID:       "agent_worker",
		ToolName:      "diagnostics.query_metrics",
		Args:          map[string]interface{}{"target": "db"},
		Justification: "Check status",
		RequestedTTL:  10 * time.Millisecond,
	}

	lease, _ := engine.RequestLease(req)

	// Wait for lease to expire
	time.Sleep(20 * time.Millisecond)

	res := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if res.ExecutionAllowed {
		t.Fatalf("expired lease should not be allowed to execute")
	}
	if res.ViolationCode != "ERR_LEASE_EXPIRED" {
		t.Errorf("expected ERR_LEASE_EXPIRED, got %s", res.ViolationCode)
	}
}

func TestForbiddenDestructiveCommand(t *testing.T) {
	engine := NewEngine(DefaultJITConfig())

	req := JITRequest{
		AgentID:       "agent_rogue",
		ToolName:      "system.run_command",
		Args:          map[string]interface{}{"command": "rm -rf / --no-preserve-root"},
		Justification: "Malicious attack test",
	}

	_, err := engine.RequestLease(req)
	if err == nil {
		t.Fatalf("expected error requesting lease with forbidden payload")
	}
	if !strings.Contains(err.Error(), "forbidden system attack signature") {
		t.Errorf("expected forbidden attack message, got: %v", err)
	}
}

func TestSignatureTampering(t *testing.T) {
	engine := NewEngine(DefaultJITConfig())

	req := JITRequest{
		AgentID:       "agent_tamper",
		ToolName:      "diagnostics.query_metrics",
		Args:          map[string]interface{}{"check": "ping"},
		Justification: "Ping test",
	}

	lease, _ := engine.RequestLease(req)

	// Tamper with signature
	lease.Signature = "0000000000000000000000000000000000000000000000000000000000000000"

	res := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if res.ExecutionAllowed {
		t.Fatalf("forged signature should be rejected!")
	}
	if res.ViolationCode != "ERR_SIGNATURE_FORGED" {
		t.Errorf("expected ERR_SIGNATURE_FORGED, got %s", res.ViolationCode)
	}
}

func TestRevokeLease(t *testing.T) {
	engine := NewEngine(DefaultJITConfig())

	req := JITRequest{
		AgentID:       "agent_worker",
		ToolName:      "diagnostics.query_metrics",
		Args:          map[string]interface{}{"target": "gateway"},
		Justification: "Diagnostics",
	}

	lease, _ := engine.RequestLease(req)

	err := engine.RevokeLease(lease.LeaseID, "emergency security halt")
	if err != nil {
		t.Fatalf("failed to revoke lease: %v", err)
	}

	res := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if res.ExecutionAllowed {
		t.Fatalf("revoked lease should not be allowed to execute")
	}
}

func TestScorecardAndMermaid(t *testing.T) {
	summary := RunJITDemo()

	if summary.TotalRequests != 4 {
		t.Errorf("expected 4 total requests, got %d", summary.TotalRequests)
	}

	scorecard := RenderJITScorecard(summary)
	if !strings.Contains(scorecard, "JUST-IN-TIME (JIT)") {
		t.Errorf("scorecard missing header")
	}

	mermaid := RenderJITMermaid(summary)
	if !strings.Contains(mermaid, "flowchart TD") {
		t.Errorf("mermaid missing flowchart directive")
	}

	markdown := RenderJITMarkdown(summary)
	if !strings.Contains(markdown, "| Lease ID |") {
		t.Errorf("markdown missing table headers")
	}
}
