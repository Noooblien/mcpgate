package risk

import (
	"fmt"
	"math"
	"strings"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiPurple = "\033[35m"
	ansiDim    = "\033[2m"
)

// RenderRiskScorecard formats an assessment into a rich ANSI terminal scorecard.
func RenderRiskScorecard(a *RiskAssessment) string {
	var sb strings.Builder

	verdictColor := ansiGreen
	switch a.Verdict {
	case VerdictWarning:
		verdictColor = ansiYellow
	case VerdictStepUpApproval:
		verdictColor = ansiPurple
	case VerdictQuarantinedBlock:
		verdictColor = ansiRed
	}

	riskColor := ansiGreen
	switch a.RiskLevel {
	case RiskLevelLow:
		riskColor = ansiCyan
	case RiskLevelMedium:
		riskColor = ansiYellow
	case RiskLevelHigh:
		riskColor = ansiRed
	case RiskLevelCritical:
		riskColor = ansiPurple
	}

	sb.WriteString(fmt.Sprintf("%s%s=== MCPGATE ADAPTIVE BLAST RADIUS & RISK SCORECARD ===%s\n", ansiBold, ansiCyan, ansiReset))
	sb.WriteString(fmt.Sprintf("Assessment ID:   %s (%s)\n", a.AssessmentID, a.Timestamp.Format("15:04:05.000Z07:00")))
	sb.WriteString(fmt.Sprintf("Agent / Role:    %s%s%s (Role: %s)\n", ansiBold, a.AgentID, ansiReset, a.Role))
	sb.WriteString(fmt.Sprintf("Session ID:      %s\n", a.SessionID))
	sb.WriteString(fmt.Sprintf("Target Tool:     %s%s%s\n", ansiBold, a.ToolName, ansiReset))
	sb.WriteString(fmt.Sprintf("Verdict:         %s%s[%s]%s\n", ansiBold, verdictColor, a.Verdict, ansiReset))
	sb.WriteString(fmt.Sprintf("Instant Score:   %s%.1f / 100.0%s (Level: %s%s%s)\n",
		riskColor, a.InstantaneousScore, ansiReset, ansiBold, a.RiskLevel, ansiReset))
	sb.WriteString(fmt.Sprintf("Cumulative Risk: %.1f / %.1f pts (Remaining Budget: %s%.1f pts%s)\n",
		a.CumulativeScore, a.BudgetLimit, ansiGreen, a.BudgetRemaining, ansiReset))
	sb.WriteString(fmt.Sprintf("Velocity Score:  %.1f pts (in sliding window)\n", a.VelocityScore))
	sb.WriteString(fmt.Sprintf("Latency:         %d µs\n", a.DurationUs))
	sb.WriteString(strings.Repeat("─", 82) + "\n")

	// Blast Radius Gauge
	sb.WriteString(fmt.Sprintf("%s%sBLAST RADIUS BUDGET CONSUMPTION:%s\n", ansiBold, ansiCyan, ansiReset))
	pct := 0.0
	if a.BudgetLimit > 0 {
		pct = math.Min(100.0, (a.CumulativeScore/a.BudgetLimit)*100.0)
	}
	sb.WriteString(renderGauge(pct, 40))
	sb.WriteString(fmt.Sprintf("  %.1f%%\n", pct))
	sb.WriteString(strings.Repeat("─", 82) + "\n")

	// Multi-Dimensional Vector Contribution
	sb.WriteString(fmt.Sprintf("%s%sMULTI-DIMENSIONAL BLAST RADIUS SURFACE:%s\n", ansiBold, ansiCyan, ansiReset))
	sb.WriteString(fmt.Sprintf("  • Filesystem Mutation:   %5.1f pts  %s\n", a.Dimensions.Filesystem, renderMiniBar(a.Dimensions.Filesystem)))
	sb.WriteString(fmt.Sprintf("  • Network Egress:        %5.1f pts  %s\n", a.Dimensions.Network, renderMiniBar(a.Dimensions.Network)))
	sb.WriteString(fmt.Sprintf("  • Financial Cost:        %5.1f pts  %s\n", a.Dimensions.Financial, renderMiniBar(a.Dimensions.Financial)))
	sb.WriteString(fmt.Sprintf("  • Privilege Escalation:  %5.1f pts  %s\n", a.Dimensions.Privilege, renderMiniBar(a.Dimensions.Privilege)))
	sb.WriteString(fmt.Sprintf("  • Data Exfiltration:     %5.1f pts  %s\n", a.Dimensions.Exfiltration, renderMiniBar(a.Dimensions.Exfiltration)))
	sb.WriteString(fmt.Sprintf("  • Irreversibility:       %5.1f pts  %s\n", a.Dimensions.Permanent, renderMiniBar(a.Dimensions.Permanent)))
	sb.WriteString(strings.Repeat("─", 82) + "\n")

	if len(a.RiskFactors) > 0 {
		sb.WriteString(fmt.Sprintf("%sRisk Factors:%s\n", ansiBold, ansiReset))
		for _, f := range a.RiskFactors {
			sb.WriteString(fmt.Sprintf("  %s⚠  %s%s\n", ansiYellow, f, ansiReset))
		}
	}
	sb.WriteString(fmt.Sprintf("Rationale:       %s%s%s\n", ansiDim, a.Explanation, ansiReset))
	sb.WriteString(strings.Repeat("─", 82) + "\n")

	return sb.String()
}

// RenderRiskMermaid outputs a Mermaid diagram visualizing the blast radius governance flow.
func RenderRiskMermaid(a *RiskAssessment) string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart TD\n")
	sb.WriteString("    subgraph Request [1. Inbound MCP Tool Call]\n")
	sb.WriteString(fmt.Sprintf("        A[\"Tool: %s\"] --> B[\"Agent: %s (Role: %s)\"]\n", a.ToolName, a.AgentID, a.Role))
	sb.WriteString("    end\n\n")

	sb.WriteString("    subgraph Scoring [2. Multi-Dimensional Scorer]\n")
	sb.WriteString(fmt.Sprintf("        B --> C[\"Filesystem: %.1f pts\"]\n", a.Dimensions.Filesystem))
	sb.WriteString(fmt.Sprintf("        B --> D[\"Network: %.1f pts\"]\n", a.Dimensions.Network))
	sb.WriteString(fmt.Sprintf("        B --> E[\"Financial: %.1f pts\"]\n", a.Dimensions.Financial))
	sb.WriteString(fmt.Sprintf("        B --> F[\"Privilege: %.1f pts\"]\n", a.Dimensions.Privilege))
	sb.WriteString(fmt.Sprintf("        C --> G[\"Instantaneous Score: %.1f pts\"]\n", a.InstantaneousScore))
	sb.WriteString("        D --> G\n")
	sb.WriteString("        E --> G\n")
	sb.WriteString("        F --> G\n")
	sb.WriteString("    end\n\n")

	sb.WriteString("    subgraph Governor [3. Blast Radius & Velocity Governor]\n")
	sb.WriteString(fmt.Sprintf("        G --> H{\"Cumulative: %.1f / %.1f\"}\n", a.CumulativeScore, a.BudgetLimit))
	sb.WriteString(fmt.Sprintf("        H --> I{\"Velocity: %.1f pts\"}\n", a.VelocityScore))
	sb.WriteString(fmt.Sprintf("        I --> J[\"Verdict: %s\"]\n", a.Verdict))
	sb.WriteString("    end\n")
	sb.WriteString("```\n")

	return sb.String()
}

// RenderMarkdownReport aggregates multiple risk assessments into a comprehensive compliance report.
func RenderMarkdownReport(assessments []*RiskAssessment) string {
	var sb strings.Builder

	sb.WriteString("# MCPGate Adaptive Blast Radius & Risk Governor Report\n\n")
	sb.WriteString("This report details the multi-dimensional risk evaluation, velocity tracking, and blast radius budget enforcement across agent tool invocations.\n\n")

	sb.WriteString("## Evaluation Summary\n\n")
	sb.WriteString("| Assessment ID | Agent | Role | Target Tool | Instant Score | Risk Level | Cumulative | Verdict |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, a := range assessments {
		verdictBadge := fmt.Sprintf("**%s**", a.Verdict)
		if a.Verdict == VerdictQuarantinedBlock {
			verdictBadge = "🔴 **QUARANTINED**"
		} else if a.Verdict == VerdictStepUpApproval {
			verdictBadge = "🟣 **STEP-UP HITL**"
		} else if a.Verdict == VerdictWarning {
			verdictBadge = "🟡 **WARNING**"
		} else {
			verdictBadge = "🟢 **ALLOWED**"
		}

		sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | %.1f | %s | %.1f / %.1f | %s |\n",
			a.AssessmentID,
			a.AgentID,
			a.Role,
			a.ToolName,
			a.InstantaneousScore,
			a.RiskLevel,
			a.CumulativeScore,
			a.BudgetLimit,
			verdictBadge,
		))
	}

	sb.WriteString("\n## Dimension Contribution Breakdown\n\n")
	sb.WriteString("| Tool Name | Filesystem | Network | Financial | Privilege | Exfiltration | Irreversible | Factors |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, a := range assessments {
		factors := "None"
		if len(a.RiskFactors) > 0 {
			factors = strings.Join(a.RiskFactors, ", ")
		}

		sb.WriteString(fmt.Sprintf("| `%s` | %.1f | %.1f | %.1f | %.1f | %.1f | %.1f | *%s* |\n",
			a.ToolName,
			a.Dimensions.Filesystem,
			a.Dimensions.Network,
			a.Dimensions.Financial,
			a.Dimensions.Privilege,
			a.Dimensions.Exfiltration,
			a.Dimensions.Permanent,
			factors,
		))
	}

	return sb.String()
}

func renderGauge(pct float64, width int) string {
	filled := int((pct / 100.0) * float64(width))
	if filled > width {
		filled = width
	}
	color := ansiGreen
	if pct >= 85.0 {
		color = ansiRed
	} else if pct >= 65.0 {
		color = ansiYellow
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return fmt.Sprintf("[%s%s%s]", color, bar, ansiReset)
}

func renderMiniBar(val float64) string {
	maxVal := 50.0
	width := 15
	filled := int((val / maxVal) * float64(width))
	if filled > width {
		filled = width
	}
	if filled == 0 && val > 0 {
		filled = 1
	}
	return "[" + strings.Repeat("■", filled) + strings.Repeat(" ", width-filled) + "]"
}
