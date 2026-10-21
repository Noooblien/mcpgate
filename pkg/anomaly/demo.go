package anomaly

import (
	"math"
	"strings"
	"time"
)

// RunDemoSuite runs 4 production enterprise scenarios demonstrating behavioral tool call anomaly detection.
func RunDemoSuite(policy AnomalyPolicy) AnomalySummary {
	detector := NewDetector(policy)

	// Step 1: Pre-train Baseline for authorized SecOps Agent
	trainSecOpsBaseline(detector, "agent-secops-01")
	trainFinanceBaseline(detector, "agent-finance-02")
	trainDevOpsBaseline(detector, "agent-devops-03")
	trainSupportBaseline(detector, "agent-support-04")

	var assessments []AnomalyAssessment

	// -------------------------------------------------------------
	// Scenario 1: Normal Authorized Workflow (Clean Standard Call)
	// -------------------------------------------------------------
	obs1 := ToolCallObservation{
		ObservationID: "obs-clean-01",
		SessionID:     "sess-secops-8901",
		AgentID:       "agent-secops-01",
		ToolName:      "run_static_analysis",
		PriorTool:     "git_diff_tree",
		Arguments: map[string]interface{}{
			"repo":       "openbot/core",
			"linter":     "golangci-lint",
			"severity":   "error",
			"max_issues": 10,
		},
		Timestamp: time.Now(),
	}
	assessments = append(assessments, *detector.Evaluate(obs1))

	// -------------------------------------------------------------
	// Scenario 2: Unprecedented Sequence Jump (Direct Exfiltration)
	// -------------------------------------------------------------
	obs2 := ToolCallObservation{
		ObservationID: "obs-jump-02",
		SessionID:     "sess-finance-1102",
		AgentID:       "agent-finance-02",
		ToolName:      "s3_put_object_unrestricted",
		PriorTool:     "query_customer_records",
		Arguments: map[string]interface{}{
			"bucket": "dark-exfil-staging-2026",
			"key":    "customer_ssn_dump.csv",
		},
		Timestamp: time.Now(),
	}
	assessments = append(assessments, *detector.Evaluate(obs2))

	// -------------------------------------------------------------
	// Scenario 3: Extreme Payload Z-Score & High-Entropy Injection
	// -------------------------------------------------------------
	// Generate high-entropy obfuscated pseudo-payload
	var highEntropyPayload strings.Builder
	for i := 0; i < 500; i++ {
		highEntropyPayload.WriteString("f3a9e1bc70d9a842f61e403d528b17ca921470efd43b2a1975e8c60a")
	}
	obs3 := ToolCallObservation{
		ObservationID: "obs-payload-03",
		SessionID:     "sess-devops-9911",
		AgentID:       "agent-devops-03",
		ToolName:      "run_container_task",
		PriorTool:     "list_containers",
		Arguments: map[string]interface{}{
			"cluster":  "prod-k8s-us-east-1",
			"image":    "internal/worker:v2.1",
			"env_init": highEntropyPayload.String(), // Massive unexpected length & entropy
		},
		Timestamp: time.Now(),
	}
	assessments = append(assessments, *detector.Evaluate(obs3))

	// -------------------------------------------------------------
	// Scenario 4: Rogue Parameter Injection / Schema Drift Attack
	// -------------------------------------------------------------
	obs4 := ToolCallObservation{
		ObservationID: "obs-param-04",
		SessionID:     "sess-support-4404",
		AgentID:       "agent-support-04",
		ToolName:      "lookup_order_status",
		PriorTool:     "search_tickets",
		Arguments: map[string]interface{}{
			"order_id":         "ORD-98412-X",
			"__proto__":        "malicious_override",
			"raw_sql_override": "SELECT * FROM users WHERE admin=1;",
			"bypass_auth_gate": true,
		},
		Timestamp: time.Now(),
	}
	assessments = append(assessments, *detector.Evaluate(obs4))

	// Compute summary statistics
	summary := AnomalySummary{
		TotalEvaluated: len(assessments),
		Assessments:    assessments,
	}

	totalScore := 0.0
	for _, a := range assessments {
		totalScore += a.CompositeScore
		if a.CompositeScore > summary.MaxScore {
			summary.MaxScore = a.CompositeScore
		}
		switch a.Verdict {
		case VerdictAllow:
			summary.Allowed++
		case VerdictAlert:
			summary.Alerted++
		case VerdictQuarantine:
			summary.Quarantined++
		case VerdictBlock:
			summary.Blocked++
		}
	}
	if summary.TotalEvaluated > 0 {
		summary.AverageScore = math.Round((totalScore/float64(summary.TotalEvaluated))*1000) / 1000
	}

	return summary
}

func trainSecOpsBaseline(d *Detector, agentID string) {
	for i := 0; i < 20; i++ {
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-secops",
			AgentID:   agentID,
			ToolName:  "repo_list_branches",
			Arguments: map[string]interface{}{"repo": "openbot/core"},
		})
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-secops",
			AgentID:   agentID,
			ToolName:  "git_diff_tree",
			PriorTool: "repo_list_branches",
			Arguments: map[string]interface{}{"repo": "openbot/core", "commit_sha": "a1b2c3d4"},
		})
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-secops",
			AgentID:   agentID,
			ToolName:  "run_static_analysis",
			PriorTool: "git_diff_tree",
			Arguments: map[string]interface{}{"repo": "openbot/core", "linter": "golangci-lint", "severity": "error", "max_issues": 10},
		})
	}
}

func trainFinanceBaseline(d *Detector, agentID string) {
	for i := 0; i < 20; i++ {
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-fin",
			AgentID:   agentID,
			ToolName:  "search_invoices",
			Arguments: map[string]interface{}{"quarter": "Q3", "limit": 50},
		})
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-fin",
			AgentID:   agentID,
			ToolName:  "query_customer_records",
			PriorTool: "search_invoices",
			Arguments: map[string]interface{}{"customer_id": "cust_123", "include_tax": true},
		})
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-fin",
			AgentID:   agentID,
			ToolName:  "generate_financial_statement",
			PriorTool: "query_customer_records",
			Arguments: map[string]interface{}{"format": "pdf", "signed": true},
		})
	}
}

func trainDevOpsBaseline(d *Detector, agentID string) {
	for i := 0; i < 20; i++ {
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-devops",
			AgentID:   agentID,
			ToolName:  "list_containers",
			Arguments: map[string]interface{}{"namespace": "production"},
		})
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-devops",
			AgentID:   agentID,
			ToolName:  "run_container_task",
			PriorTool: "list_containers",
			Arguments: map[string]interface{}{"cluster": "prod-k8s-us-east-1", "image": "internal/worker:v2.1", "env_init": "LOG_LEVEL=info"},
		})
	}
}

func trainSupportBaseline(d *Detector, agentID string) {
	for i := 0; i < 20; i++ {
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-supp",
			AgentID:   agentID,
			ToolName:  "search_tickets",
			Arguments: map[string]interface{}{"status": "open", "tag": "billing"},
		})
		d.RecordObservation(ToolCallObservation{
			SessionID: "train-supp",
			AgentID:   agentID,
			ToolName:  "lookup_order_status",
			PriorTool: "search_tickets",
			Arguments: map[string]interface{}{"order_id": "ORD-12345"},
		})
	}
}
