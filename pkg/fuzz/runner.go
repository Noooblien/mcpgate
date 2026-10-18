package fuzz

import (
	"time"

	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// SecurityFuzzer runs automated adversarial fuzzing campaigns against MCPGate.
type SecurityFuzzer struct {
	gate *gateway.MCPGate
}

// NewSecurityFuzzer creates a new adversarial fuzzer backed by an MCPGate instance.
func NewSecurityFuzzer(gate *gateway.MCPGate) *SecurityFuzzer {
	return &SecurityFuzzer{gate: gate}
}

// ExecuteTrial runs a single adversarial test payload through the gateway.
func (f *SecurityFuzzer) ExecuteTrial(payload FuzzPayload, role rbac.AgentRole) TrialResult {
	start := time.Now()

	verdict := f.gate.InterceptToolCall(
		"fuzz-agent-tester",
		role,
		payload.ToolName,
		payload.Arguments,
	)

	latency := float64(time.Since(start).Microseconds()) / 1000.0

	blocked := !verdict.Allowed
	passed := (blocked == payload.ExpectedBlocked)

	threatScore := 0.0
	if blocked {
		threatScore = 1.0
	}

	return TrialResult{
		Payload:     payload,
		Blocked:     blocked,
		BlockReason: verdict.BlockReason,
		ThreatScore: threatScore,
		LatencyMs:   latency,
		Passed:      passed,
	}
}

// RunSuite executes an array of fuzzing payloads and generates a comprehensive report.
func (f *SecurityFuzzer) RunSuite(payloads []FuzzPayload, role rbac.AgentRole) FuzzSecurityReport {
	trials := make([]TrialResult, 0, len(payloads))

	blockedCount := 0
	allowedCount := 0
	falseNegatives := 0
	var totalLatency float64

	for _, p := range payloads {
		res := f.ExecuteTrial(p, role)
		trials = append(trials, res)
		totalLatency += res.LatencyMs

		if res.Blocked {
			blockedCount++
		} else {
			allowedCount++
			if p.ExpectedBlocked {
				falseNegatives++
			}
		}
	}

	avgLatency := 0.0
	if len(payloads) > 0 {
		avgLatency = totalLatency / float64(len(payloads))
	}

	// Calculate resilience: percentage of trials that behaved according to expected security posture
	passedCount := 0
	for _, t := range trials {
		if t.Passed {
			passedCount++
		}
	}

	resilience := 0.0
	if len(payloads) > 0 {
		resilience = (float64(passedCount) / float64(len(payloads))) * 100.0
	}

	allPassed := (falseNegatives == 0)

	return FuzzSecurityReport{
		TotalTrials:      len(payloads),
		BlockedCount:     blockedCount,
		AllowedCount:     allowedCount,
		FalseNegatives:   falseNegatives,
		ResilienceScore:  resilience,
		AverageLatencyMs: avgLatency,
		Trials:           trials,
		ExecutedAt:       time.Now().UTC(),
		Passed:           allPassed,
	}
}
