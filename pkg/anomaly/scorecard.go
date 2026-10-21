package anomaly

import (
	"fmt"
	"strings"
	"time"
)

// ANSI color escapes for terminal scorecard rendering.
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorRed     = "\033[1;31m"
	colorGreen   = "\033[1;32m"
	colorYellow  = "\033[1;33m"
	colorBlue    = "\033[1;34m"
	colorMagenta = "\033[1;35m"
	colorCyan    = "\033[1;36m"
	colorGray    = "\033[0;90m"
)

// RenderAnomalyScorecard renders a high-visibility terminal scorecard of evaluated tool calls.
func RenderAnomalyScorecard(summary AnomalySummary) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s┌────────────────────────────────────────────────────────────────────────┐%s\n", colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│ %s%-70s%s%s │%s\n", colorCyan, colorBold, "  MCPGATE BEHAVIORAL TOOL ANOMALY & MARKOV ENGINE SCORECARD", colorReset, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────┤%s\n", colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Total Invocations Evaluated: %-42d %s│%s\n", colorCyan, colorReset, summary.TotalEvaluated, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Approved (Clean / Low Risk): %s%-42d%s %s│%s\n", colorCyan, colorReset, colorGreen, summary.Allowed, colorReset, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Alerted (Medium Deviation):   %s%-42d%s %s│%s\n", colorCyan, colorReset, colorYellow, summary.Alerted, colorReset, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Quarantined (Suspicious):     %s%-42d%s %s│%s\n", colorCyan, colorReset, colorMagenta, summary.Quarantined, colorReset, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Blocked (Critical Anomaly):   %s%-42d%s %s│%s\n", colorCyan, colorReset, colorRed, summary.Blocked, colorReset, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Max Composite Anomaly Score:  %-42.3f %s│%s\n", colorCyan, colorReset, summary.MaxScore, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Average Anomaly Score:        %-42.3f %s│%s\n", colorCyan, colorReset, summary.AverageScore, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s└────────────────────────────────────────────────────────────────────────┘%s\n\n", colorCyan, colorReset))

	// Per-invocation breakdown table
	sb.WriteString(fmt.Sprintf("%s%s%-10s %-18s %-20s %-7s %-12s %-10s%s\n", colorBold, colorBlue, "ID", "AGENT", "TRANSITION", "SCORE", "VERDICT", "SEVERITY", colorReset))
	sb.WriteString(fmt.Sprintf("%s%s%s\n", colorGray, strings.Repeat("─", 82), colorReset))

	for _, a := range summary.Assessments {
		vColor := colorGreen
		switch a.Verdict {
		case VerdictAlert:
			vColor = colorYellow
		case VerdictQuarantine:
			vColor = colorMagenta
		case VerdictBlock:
			vColor = colorRed
		}

		trans := a.ToolName
		if a.PriorTool != "" {
			trans = fmt.Sprintf("%s->%s", truncate(a.PriorTool, 8), truncate(a.ToolName, 10))
		}

		sb.WriteString(fmt.Sprintf("%-10s %-18s %-20s %-7.3f %s%-12s%s %-10s\n",
			truncate(a.ObservationID, 9),
			truncate(a.AgentID, 17),
			truncate(trans, 19),
			a.CompositeScore,
			vColor, a.Verdict, colorReset,
			a.Severity,
		))

		if len(a.ContributingFactors) > 0 {
			sb.WriteString(fmt.Sprintf("  %s└─ Factors: %s%s\n", colorGray, strings.Join(a.ContributingFactors, ", "), colorReset))
		}
	}
	sb.WriteString("\n")

	return sb.String()
}

// RenderAnomalyMermaid produces a Mermaid state diagram of observed tool sequence transitions.
func RenderAnomalyMermaid(assessments []AnomalyAssessment) string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("stateDiagram-v2\n")
	sb.WriteString("    direction LR\n\n")

	seenEdges := make(map[string]bool)

	for _, a := range assessments {
		from := a.PriorTool
		if from == "" {
			from = "[*]"
		}
		to := a.ToolName
		edgeKey := fmt.Sprintf("%s-->%s", from, to)

		if !seenEdges[edgeKey] {
			seenEdges[edgeKey] = true
			if a.Verdict == VerdictBlock || a.Verdict == VerdictQuarantine {
				sb.WriteString(fmt.Sprintf("    %s --> %s: ANOMALY [%.2f: %s]\n", sanitizeMermaidNode(from), sanitizeMermaidNode(to), a.CompositeScore, a.Verdict))
			} else {
				sb.WriteString(fmt.Sprintf("    %s --> %s: Safe [%.2f]\n", sanitizeMermaidNode(from), sanitizeMermaidNode(to), a.CompositeScore))
			}
		}
	}

	sb.WriteString("```\n")
	return sb.String()
}

// RenderAnomalyMarkdownReport creates a GitHub-flavored markdown report of anomaly evaluations.
func RenderAnomalyMarkdownReport(summary AnomalySummary) string {
	var sb strings.Builder

	sb.WriteString("# MCPGate Behavioral Tool Anomaly & Markov Sequence Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("*Generated at: %s*\n\n", time.Now().UTC().Format(time.RFC3339)))

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| **Total Tool Invocations** | `%d` |\n", summary.TotalEvaluated))
	sb.WriteString(fmt.Sprintf("| **Approved (Clean)** | `%d` |\n", summary.Allowed))
	sb.WriteString(fmt.Sprintf("| **Alerted (Audited)** | `%d` |\n", summary.Alerted))
	sb.WriteString(fmt.Sprintf("| **Quarantined (Suspended)** | `%d` |\n", summary.Quarantined))
	sb.WriteString(fmt.Sprintf("| **Blocked (Attacks)** | `%d` |\n", summary.Blocked))
	sb.WriteString(fmt.Sprintf("| **Average Anomaly Score** | `%.3f` |\n", summary.AverageScore))
	sb.WriteString(fmt.Sprintf("| **Max Anomaly Score** | `%.3f` |\n\n", summary.MaxScore))

	sb.WriteString("## Detailed Assessment Breakdown\n\n")
	sb.WriteString("| ID | Agent | Prior Tool | Target Tool | Score | Verdict | Severity | Contributing Factors |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |\n")

	for _, a := range summary.Assessments {
		prior := a.PriorTool
		if prior == "" {
			prior = "*(session start)*"
		}
		factors := "None (Clean)"
		if len(a.ContributingFactors) > 0 {
			factors = fmt.Sprintf("`%s`", strings.Join(a.ContributingFactors, "`, `"))
		}

		sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | `%.3f` | **%s** | `%s` | %s |\n",
			a.ObservationID,
			a.AgentID,
			prior,
			a.ToolName,
			a.CompositeScore,
			a.Verdict,
			a.Severity,
			factors,
		))
	}

	sb.WriteString("\n## Mitigation Recommendations\n\n")
	for _, a := range summary.Assessments {
		if a.Verdict != VerdictAllow {
			sb.WriteString(fmt.Sprintf("- **[%s] %s**: %s\n", a.Verdict, a.ObservationID, a.MitigationAdvice))
		}
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-2] + ".."
}

func sanitizeMermaidNode(s string) string {
	if s == "[*]" {
		return s
	}
	replacer := strings.NewReplacer("-", "_", " ", "_", ".", "_", ":", "_", "/", "_")
	return replacer.Replace(s)
}
