package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/jit"
)

func TestIntegration_JIT_DemoSuite(t *testing.T) {
	summary := jit.RunJITDemo()

	if summary.TotalRequests != 4 {
		t.Fatalf("expected 4 total demo requests, got %d", summary.TotalRequests)
	}

	if summary.ConsumedLeases < 2 {
		t.Errorf("expected at least 2 consumed leases, got %d", summary.ConsumedLeases)
	}
	if summary.DeniedRequests < 2 {
		t.Errorf("expected at least 2 denied/tampered attempts, got %d", summary.DeniedRequests)
	}

	scorecard := jit.RenderJITScorecard(summary)
	if !strings.Contains(scorecard, "JUST-IN-TIME (JIT)") {
		t.Errorf("scorecard missing header in integration test")
	}

	mermaid := jit.RenderJITMermaid(summary)
	if !strings.Contains(mermaid, "flowchart TD") {
		t.Errorf("mermaid missing flowchart TD in integration test")
	}

	md := jit.RenderJITMarkdown(summary)
	if !strings.Contains(md, "Just-In-Time (JIT) Capability Delegation & Ephemeral Lease Audit") {
		t.Errorf("markdown report missing expected heading")
	}
}

func TestIntegration_JIT_CompleteLifecycle(t *testing.T) {
	engine := jit.NewEngine(jit.DefaultJITConfig())

	// 1. Request lease for critical tool
	req := jit.JITRequest{
		AgentID:       "agent_pipeline",
		ToolName:      "aws.terminate_instance",
		Args:          map[string]interface{}{"instance_id": "i-0987654321fedcba0"},
		Justification: "Scale-down idle compute",
		RequestedTTL:  60 * time.Second,
	}

	lease, err := engine.RequestLease(req)
	if err != nil {
		t.Fatalf("unexpected error requesting lease: %v", err)
	}

	// 2. Initial state must be pending approval
	if lease.Status != jit.StatusPendingApproval {
		t.Fatalf("expected pending approval, got %s", lease.Status)
	}

	// 3. Execution without approval fails
	r1 := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if r1.ExecutionAllowed {
		t.Fatalf("expected unapproved execution to be blocked")
	}

	// 4. Human supervisor approves
	_, err = engine.ApproveStepUp(lease.LeaseID, "devops_lead")
	if err != nil {
		t.Fatalf("failed to approve step up: %v", err)
	}

	// 5. Valid execution succeeds
	r2 := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if !r2.ExecutionAllowed {
		t.Fatalf("expected execution allowed after approval: %s", r2.Reason)
	}

	// 6. Immediate second execution fails (one-time use consumed)
	r3 := engine.ValidateAndConsume(lease.LeaseID, req.ToolName, req.Args)
	if r3.ExecutionAllowed {
		t.Fatalf("expected replay attempt to be blocked")
	}
	if r3.ViolationCode != "ERR_LEASE_REPLAY_ATTEMPT" {
		t.Errorf("expected ERR_LEASE_REPLAY_ATTEMPT, got %s", r3.ViolationCode)
	}
}
