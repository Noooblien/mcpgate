package jit

import (
	"time"
)

// RunJITDemo executes a 4-scenario benchmark showcasing zero-trust JIT capability delegation,
// ephemeral scoped leases, step-up dual-custody gates, and parameter substitution tamper defense.
func RunJITDemo() *JITSummary {
	start := time.Now()
	engine := NewEngine(DefaultJITConfig())

	evaluations := make([]*VerificationResult, 0)
	totalRequests := 0
	consumedCount := 0
	stepUpCount := 0
	deniedCount := 0

	// -------------------------------------------------------------------------------------------------
	// Scenario 1: Automated Low-Risk Ephemeral Grant & Execution
	// -------------------------------------------------------------------------------------------------
	totalRequests++
	req1 := JITRequest{
		RequestID:     "req_diag_01",
		AgentID:       "agent_sre_bot",
		ToolName:      "diagnostics.query_metrics",
		Args:          map[string]interface{}{"service": "api-gateway", "window": "5m"},
		Justification: "Routine latency telemetry inspection",
		RequestedTTL:  60 * time.Second,
	}
	lease1, _ := engine.RequestLease(req1)
	res1 := engine.ValidateAndConsume(lease1.LeaseID, req1.ToolName, req1.Args)
	evaluations = append(evaluations, res1)
	if res1.ExecutionAllowed {
		consumedCount++
	}

	// -------------------------------------------------------------------------------------------------
	// Scenario 2: Critical Infrastructure Escalation Requiring Step-Up Approval
	// -------------------------------------------------------------------------------------------------
	totalRequests++
	req2 := JITRequest{
		RequestID:     "req_db_drop_02",
		AgentID:       "agent_migration_bot",
		ToolName:      "database.drop_table",
		Args:          map[string]interface{}{"table": "legacy_staging_cache", "cascade": false},
		Justification: "Post-migration cleanup of deprecated staging table",
		RequestedTTL:  120 * time.Second,
	}
	lease2, _ := engine.RequestLease(req2)

	// Step 2a: Attempt execution without approval -> Blocked
	res2a := engine.ValidateAndConsume(lease2.LeaseID, req2.ToolName, req2.Args)
	evaluations = append(evaluations, res2a)
	stepUpCount++

	// Step 2b: Supervisor grants approval
	_, _ = engine.ApproveStepUp(lease2.LeaseID, "security_lead_approver")

	// Step 2c: Re-execute -> Allowed & Consumed
	res2b := engine.ValidateAndConsume(lease2.LeaseID, req2.ToolName, req2.Args)
	evaluations = append(evaluations, res2b)
	if res2b.ExecutionAllowed {
		consumedCount++
	}

	// -------------------------------------------------------------------------------------------------
	// Scenario 3: Parameter Substitution Tampering Attack Defense
	// -------------------------------------------------------------------------------------------------
	totalRequests++
	req3 := JITRequest{
		RequestID:     "req_pr_merge_03",
		AgentID:       "agent_ci_bot",
		ToolName:      "github.merge_pr",
		Args:          map[string]interface{}{"repo": "enterprise/core", "pull_number": 42},
		Justification: "Auto-merge approved security patch PR #42",
		RequestedTTL:  60 * time.Second,
	}
	lease3, _ := engine.RequestLease(req3)
	_, _ = engine.ApproveStepUp(lease3.LeaseID, "pr_codeowner_approver")

	// Adversary tampers with arguments: keeps lease3 ID but substitutes malicious PR #999!
	tamperedArgs := map[string]interface{}{"repo": "enterprise/core", "pull_number": 999}
	res3Tamper := engine.ValidateAndConsume(lease3.LeaseID, req3.ToolName, tamperedArgs)
	evaluations = append(evaluations, res3Tamper)
	deniedCount++

	// Legitimate execution with original args succeeds
	res3Legit := engine.ValidateAndConsume(lease3.LeaseID, req3.ToolName, req3.Args)
	evaluations = append(evaluations, res3Legit)
	if res3Legit.ExecutionAllowed {
		consumedCount++
	}

	// Replay attack: attempting to use lease3 again after consumption
	res3Replay := engine.ValidateAndConsume(lease3.LeaseID, req3.ToolName, req3.Args)
	evaluations = append(evaluations, res3Replay)
	deniedCount++

	// -------------------------------------------------------------------------------------------------
	// Scenario 4: Forbidden Destructive Attack Signature Rejection
	// -------------------------------------------------------------------------------------------------
	totalRequests++
	req4 := JITRequest{
		RequestID:     "req_exploit_04",
		AgentID:       "agent_rogue_bot",
		ToolName:      "system.run_command",
		Args:          map[string]interface{}{"command": "rm -rf / --no-preserve-root"},
		Justification: "Jailbroken command execution probe",
		RequestedTTL:  60 * time.Second,
	}
	lease4, err := engine.RequestLease(req4)
	if err != nil {
		res4 := &VerificationResult{
			LeaseID:          lease4.LeaseID,
			ToolName:         req4.ToolName,
			AgentID:          req4.AgentID,
			Status:           StatusDenied,
			ExecutionAllowed: false,
			Reason:           err.Error(),
			ViolationCode:    "ERR_ELEVATION_DENIED",
			RiskTier:         RiskCritical,
			Lease:            lease4,
			Duration:         10 * time.Microsecond,
		}
		evaluations = append(evaluations, res4)
		deniedCount++
	}

	return &JITSummary{
		TotalRequests:  totalRequests,
		ActiveLeases:   0,
		ConsumedLeases: consumedCount,
		ExpiredLeases:  0,
		DeniedRequests: deniedCount,
		StepUpRequired: stepUpCount,
		Evaluations:    evaluations,
		Duration:       time.Since(start),
	}
}
