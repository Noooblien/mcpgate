package fuzz

import (
	"fmt"
	"strings"
)

// RenderFuzzScorecard formats fuzz testing results into an ANSI terminal scorecard.
func RenderFuzzScorecard(report FuzzSecurityReport) string {
	var sb strings.Builder

	sb.WriteString("\033[1;35m========================================================================================\033[0m\n")
	sb.WriteString("  \033[1;37mMCPGATE // ADVERSARIAL SECURITY FUZZING & INJECTION RESILIENCE SCORECARD\033[0m\n")
	sb.WriteString("\033[1;35m========================================================================================\033[0m\n\n")

	statusColor := "\033[1;32m" // Green
	statusText := "[OPTIMAL - ZERO EXPLOITS COMPROMISED]"
	if report.FalseNegatives > 0 || report.ResilienceScore < 95.0 {
		statusColor = "\033[1;31m" // Red
		statusText = fmt.Sprintf("[VULNERABLE - %d FALSE NEGATIVES DETECTED]", report.FalseNegatives)
	}

	sb.WriteString(fmt.Sprintf("  \033[1;33mSecurity Posture:\033[0m    %s%s\033[0m\n", statusColor, statusText))
	sb.WriteString(fmt.Sprintf("  \033[1;33mResilience Score:\033[0m    %s%.1f%%\033[0m (Neutralized: %d/%d attacks)\n",
		statusColor, report.ResilienceScore, report.BlockedCount, report.TotalTrials-report.AllowedCount+report.BlockedCount))
	sb.WriteString(fmt.Sprintf("  \033[1;33mLatency Overhead:\033[0m    \033[1;32m%.2f ms\033[0m avg per inspection\n\n", report.AverageLatencyMs))

	sb.WriteString("  \033[1;37mADVERSARIAL TRIAL MATRIX & EXPLOIT NEUTRALIZATION:\033[0m\n")
	sb.WriteString("  ────────────────────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString("  STATUS   CATEGORY                TRIAL NAME                      TOOL         LATENCY\n")
	sb.WriteString("  ────────────────────────────────────────────────────────────────────────────────────────\n")

	for _, t := range report.Trials {
		var tag string
		if t.Passed {
			if t.Blocked {
				tag = "\033[32m[BLOCKED]\033[0m"
			} else {
				tag = "\033[36m[ALLOWED]\033[0m"
			}
		} else {
			tag = "\033[1;31m[BYPASS!]\033[0m"
		}

		cat := string(t.Payload.Category)
		if len(cat) > 23 {
			cat = cat[:20] + "..."
		}

		name := t.Payload.Name
		if len(name) > 31 {
			name = name[:28] + "..."
		}

		tool := t.Payload.ToolName
		if len(tool) > 12 {
			tool = tool[:9] + "..."
		}

		sb.WriteString(fmt.Sprintf("  %-9s %-23s %-31s %-12s %5.2fms\n",
			tag, cat, name, tool, t.LatencyMs))
	}

	sb.WriteString("  ────────────────────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString("\033[1;35m========================================================================================\033[0m\n")

	return sb.String()
}

// RenderFuzzMermaid generates a Mermaid flowchart visualization of the adversarial attack surface.
func RenderFuzzMermaid(report FuzzSecurityReport) string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("graph TD\n")
	sb.WriteString("    ADV[\"Adversarial Fuzzer (8 Vulnerability Classes)\"] --> GATE[\"MCPGate Security Inspection Engine\"]\n")
	sb.WriteString("    GATE --> RBAC{\"RBAC & Global Banned\"}\n")
	sb.WriteString("    GATE --> FW{\"Prompt Injection Firewall\"}\n")
	sb.WriteString("    GATE --> LOOP{\"Loop Detector (OWASP-LLM08)\"}\n")

	var blockedNodes []string
	var passedNodes []string

	for i, t := range report.Trials {
		nodeID := fmt.Sprintf("T%d", i+1)
		cleanName := strings.ReplaceAll(t.Payload.Name, "\"", "'")
		if t.Blocked {
			sb.WriteString(fmt.Sprintf("    FW -->|Blocked| %s[\"%s<br/>(%s)\"]\n", nodeID, cleanName, t.Payload.Category))
			blockedNodes = append(blockedNodes, nodeID)
		} else if !t.Payload.ExpectedBlocked {
			sb.WriteString(fmt.Sprintf("    GATE -->|Approved Benign| %s[\"%s<br/>(Allowed Control)\"]\n", nodeID, cleanName))
			passedNodes = append(passedNodes, nodeID)
		}
	}

	for _, n := range blockedNodes {
		sb.WriteString(fmt.Sprintf("    style %s fill:#f8d7da,stroke:#dc3545,stroke-width:2px\n", n))
	}
	for _, n := range passedNodes {
		sb.WriteString(fmt.Sprintf("    style %s fill:#d4edda,stroke:#28a745,stroke-width:2px\n", n))
	}

	sb.WriteString("```\n")
	return sb.String()
}
