package simulation

import (
	"strings"
	"sync"
	"testing"
)

func TestSimulation_ReadOnlySafe(t *testing.T) {
	gov := NewSimulationGovernor(DefaultConfig())

	// 1. Safe file read
	report1 := gov.Simulate("agent_analyst", "read_file", []byte(`{"path": "config.json"}`))
	if report1.Decision != DecisionAllowImmediate {
		t.Errorf("expected read_file to be allowed immediately, got: %s", report1.Decision)
	}
	if report1.Category != CategoryReadOnly {
		t.Errorf("expected CategoryReadOnly, got: %s", report1.Category)
	}
	if report1.BlastRadius.DestructiveRiskScore != 0.0 {
		t.Errorf("expected zero destructive risk score, got: %.1f", report1.BlastRadius.DestructiveRiskScore)
	}
	if report1.RequiresHumanStepUp {
		t.Errorf("read_file should not require human step up")
	}

	// 2. Safe SQL SELECT
	report2 := gov.Simulate("agent_analyst", "execute_sql", []byte(`{"query": "SELECT id, name FROM users WHERE active = true"}`))
	if report2.Decision != DecisionAllowImmediate {
		t.Errorf("expected SELECT query to be allowed, got: %s", report2.Decision)
	}
	if report2.Category != CategoryReadOnly {
		t.Errorf("expected CategoryReadOnly, got: %s", report2.Category)
	}
}

func TestSimulation_CatastrophicBlocked(t *testing.T) {
	gov := NewSimulationGovernor(DefaultConfig())

	// 1. Destructive shell command rm -rf /
	report1 := gov.Simulate("agent_rogue", "run_command", []byte(`{"command": "rm -rf /"}`))
	if report1.Decision != DecisionBlockHighBlastRadius {
		t.Errorf("expected rm -rf / to be blocked, got: %s", report1.Decision)
	}
	if report1.BlastRadius.DestructiveRiskScore < 9.0 {
		t.Errorf("expected catastrophic risk score >= 9.0, got: %.1f", report1.BlastRadius.DestructiveRiskScore)
	}
	if report1.BlastRadius.ReversibilityLevel != Irreversible {
		t.Errorf("expected Irreversible level, got: %s", report1.BlastRadius.ReversibilityLevel)
	}

	// 2. SQL DROP TABLE
	report2 := gov.Simulate("agent_rogue", "sql_exec", []byte(`{"query": "DROP TABLE customers CASCADE"}`))
	if report2.Decision != DecisionBlockHighBlastRadius {
		t.Errorf("expected DROP TABLE to be blocked, got: %s", report2.Decision)
	}
	if report2.Category != CategoryIrreversibleDestructive {
		t.Errorf("expected CategoryIrreversibleDestructive, got: %s", report2.Category)
	}
}

func TestSimulation_DualCustodyStepUp(t *testing.T) {
	gov := NewSimulationGovernor(DefaultConfig())

	// 1. SQL unconstrained DELETE without WHERE
	report1 := gov.Simulate("agent_worker", "execute_sql", []byte(`{"query": "DELETE FROM audit_logs"}`))
	if report1.Decision != DecisionRequireDualCustodyApproval {
		t.Errorf("expected unconstrained DELETE to require dual custody, got: %s", report1.Decision)
	}
	if !report1.RequiresHumanStepUp {
		t.Errorf("expected RequiresHumanStepUp to be true")
	}

	// 2. High-value financial transfer exceeding $100 ceiling
	report2 := gov.Simulate("agent_treasury", "stripe_transfer", []byte(`{"amount": 500.0, "currency": "USD", "recipient": "acct_123"}`))
	if report2.Decision != DecisionRequireDualCustodyApproval {
		t.Errorf("expected $500 transfer to require dual custody, got: %s", report2.Decision)
	}
	if report2.BlastRadius.EstimatedFinancialRiskUSD != 500.0 {
		t.Errorf("expected financial risk $500, got: %.2f", report2.BlastRadius.EstimatedFinancialRiskUSD)
	}

	// 3. Cloud resource modification
	report3 := gov.Simulate("agent_devops", "aws_run_instances", []byte(`{"instance_type": "c5.4xlarge", "count": 10}`))
	if report3.Decision != DecisionRequireDualCustodyApproval {
		t.Errorf("expected cloud provisioning to require step-up approval, got: %s", report3.Decision)
	}
}

func TestSimulation_RollbackStrategyGeneration(t *testing.T) {
	gov := NewSimulationGovernor(DefaultConfig())

	report := gov.Simulate("agent_editor", "write_file", []byte(`{"path": "/app/config.yaml", "content": "env: prod"}`))
	if report.RollbackStrategy == "" {
		t.Fatalf("expected rollback strategy to be populated")
	}
	if !strings.Contains(report.RollbackStrategy, "shadow file copy") {
		t.Errorf("unexpected rollback strategy text: %s", report.RollbackStrategy)
	}
	if report.SpeculativeDiff == "" {
		t.Errorf("expected speculative diff to be generated for mutation")
	}
}

func TestSimulation_ScorecardAndMermaid(t *testing.T) {
	gov := NewSimulationGovernor(DefaultConfig())
	report := gov.Simulate("agent_tester", "execute_sql", []byte(`{"query": "DROP TABLE test_users"}`))

	card := gov.GenerateScorecardMarkdown(report)
	if !strings.Contains(card, "BLOCKED: HIGH BLAST RADIUS") {
		t.Errorf("expected card to show blocked badge")
	}
	if !strings.Contains(card, "Destructive Risk Score") {
		t.Errorf("expected card to have risk score metrics")
	}

	mermaid := gov.GenerateMermaidDiagram(report)
	if !strings.Contains(mermaid, "sequenceDiagram") {
		t.Errorf("expected valid Mermaid sequence diagram")
	}
	if !strings.Contains(mermaid, "HTTP 403 BLOCKED") {
		t.Errorf("expected Mermaid to show blocked outcome")
	}
}

func TestSimulation_ConcurrentExecution(t *testing.T) {
	gov := NewSimulationGovernor(DefaultConfig())
	var wg sync.WaitGroup
	workers := 25

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				if id%2 == 0 {
					_ = gov.Simulate("agent_read", "read_file", []byte(`{"path": "data.txt"}`))
				} else {
					_ = gov.Simulate("agent_write", "write_file", []byte(`{"path": "out.txt"}`))
				}
				_ = gov.History()
			}
		}(i)
	}

	wg.Wait()

	if len(gov.History()) != workers*40 {
		t.Errorf("expected %d history records, got %d", workers*40, len(gov.History()))
	}
}
