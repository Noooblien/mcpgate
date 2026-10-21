package tests

import (
	"encoding/json"
	"testing"

	"github.com/Noooblien/mcpgate/pkg/simulation"
)

func TestIntegration_Simulation_EndToEnd(t *testing.T) {
	gov := simulation.NewSimulationGovernor(simulation.DefaultConfig())

	// Test 1: Safe read tool
	rawSafe, _ := json.Marshal(map[string]interface{}{
		"query": "SELECT * FROM users WHERE id = 1",
	})
	planSafe := gov.Simulate("agent-alpha", "db_query", rawSafe)
	if planSafe.Decision != simulation.DecisionAllowImmediate {
		t.Fatalf("expected DecisionAllowImmediate, got %s", planSafe.Decision)
	}
	if planSafe.Category != simulation.CategoryReadOnly {
		t.Fatalf("expected CategoryReadOnly, got %s", planSafe.Category)
	}

	// Test 2: Catastrophic tool
	rawDrop, _ := json.Marshal(map[string]interface{}{
		"query": "DROP TABLE customers",
	})
	planDrop := gov.Simulate("agent-alpha", "db_query", rawDrop)
	if planDrop.Decision != simulation.DecisionBlockHighBlastRadius {
		t.Fatalf("expected DecisionBlockHighBlastRadius, got %s", planDrop.Decision)
	}

	// Test 3: Dual Custody threshold (financial, amount = $500 triggers Dual Custody since score=7.8 <= 9.0 and financial > $100)
	rawPay, _ := json.Marshal(map[string]interface{}{
		"amount": 500.0,
	})
	planPay := gov.Simulate("agent-alpha", "stripe_charge", rawPay)
	if planPay.Decision != simulation.DecisionRequireDualCustodyApproval {
		t.Fatalf("expected DecisionRequireDualCustodyApproval, got %s", planPay.Decision)
	}

	// Test 4: Scorecard & Mermaid rendering
	card := gov.GenerateScorecardMarkdown(planPay)
	if len(card) == 0 {
		t.Fatalf("expected non-empty markdown scorecard")
	}

	mermaid := gov.GenerateMermaidDiagram(planPay)
	if len(mermaid) == 0 {
		t.Fatalf("expected non-empty mermaid diagram")
	}

	// Test 5: Demo runner
	simulation.RunSimulationDemo()
}
