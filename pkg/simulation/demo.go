package simulation

import (
	"encoding/json"
	"fmt"
)

// RunSimulationDemo executes a demonstration of speculative dry-run simulations.
func RunSimulationDemo() {
	gov := NewSimulationGovernor(DefaultConfig())

	fmt.Println("=== MCPGate Speculative Dry-Run Simulation Demo ===")

	// 1. Safe Read-Only
	args1, _ := json.Marshal(map[string]interface{}{"path": "config.yaml"})
	plan1 := gov.Simulate("agent-001", "read_file", args1)
	fmt.Printf("[1] %s: Category=%s, Decision=%s\n", plan1.ToolName, plan1.Category, plan1.Decision)

	// 2. High Risk Financial Allocation
	args2, _ := json.Marshal(map[string]interface{}{"amount": 2500.0, "currency": "usd"})
	plan2 := gov.Simulate("agent-002", "create_payment_intent", args2)
	fmt.Printf("[2] %s: Category=%s, Decision=%s, Exposure=$%.2f\n", plan2.ToolName, plan2.Category, plan2.Decision, plan2.BlastRadius.EstimatedFinancialRiskUSD)

	// 3. Catastrophic Destructive Action
	args3, _ := json.Marshal(map[string]interface{}{"db": "production_users"})
	plan3 := gov.Simulate("agent-003", "delete_database", args3)
	fmt.Printf("[3] %s: Category=%s, Decision=%s, Scope=%s\n", plan3.ToolName, plan3.Category, plan3.Decision, plan3.BlastRadius.ScopeLevel)
}
