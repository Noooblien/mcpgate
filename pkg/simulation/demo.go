package simulation

import (
	"encoding/json"
	"time"
)

// RunSimulationDemo executes a demonstration of speculative dry-run simulations across standard scenarios.
func RunSimulationDemo() SimulationSummary {
	start := time.Now()
	gov := NewSimulationGovernor(DefaultConfig())

	scenarios := []struct {
		agentID  string
		toolName string
		args     map[string]interface{}
	}{
		{
			agentID:  "agent_worker_01",
			toolName: "read_file",
			args:     map[string]interface{}{"path": "config.yaml"},
		},
		{
			agentID:  "agent_worker_02",
			toolName: "sql_query",
			args:     map[string]interface{}{"query": "SELECT * FROM accounts WHERE status = 'active'"},
		},
		{
			agentID:  "agent_devops",
			toolName: "restart_service",
			args:     map[string]interface{}{"service": "cache-redis"},
		},
		{
			agentID:  "agent_finance",
			toolName: "create_payment_intent",
			args:     map[string]interface{}{"amount": 450.0, "currency": "usd", "destination": "acct_vendor_99"},
		},
		{
			agentID:  "agent_rogue",
			toolName: "bash_exec",
			args:     map[string]interface{}{"cmd": "rm -rf / --no-preserve-root"},
		},
		{
			agentID:  "agent_dba",
			toolName: "sql_query",
			args:     map[string]interface{}{"query": "DROP TABLE production_customers"},
		},
	}

	var results []*SimulationReport
	totalRisk := 0.0
	totalFinancial := 0.0
	allowed := 0
	stepUp := 0
	blocked := 0

	for _, sc := range scenarios {
		raw, _ := json.Marshal(sc.args)
		res := gov.Simulate(sc.agentID, sc.toolName, raw)
		results = append(results, res)

		totalRisk += res.BlastRadius.DestructiveRiskScore
		totalFinancial += res.BlastRadius.EstimatedFinancialRiskUSD

		switch res.Decision {
		case DecisionAllowImmediate:
			allowed++
		case DecisionRequireDualCustodyApproval:
			stepUp++
		case DecisionBlockHighBlastRadius:
			blocked++
		}
	}

	avgRisk := 0.0
	if len(results) > 0 {
		avgRisk = totalRisk / float64(len(results))
	}

	return SimulationSummary{
		TotalSimulations:          len(results),
		AllowedImmediate:          allowed,
		RequireStepUp:             stepUp,
		Blocked:                   blocked,
		AverageRiskScore:          avgRisk,
		TotalFinancialExposureUSD: totalFinancial,
		Simulations:               results,
		Duration:                  time.Since(start),
	}
}
