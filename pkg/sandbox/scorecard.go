package sandbox

import (
	"fmt"
	"strings"
)

// ANSI terminal color constants.
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
)

// RenderSandboxScorecard formats an ANSI terminal table summarizing sandbox evaluations.
func RenderSandboxScorecard(summary *SandboxSummary) string {
	var sb strings.Builder

	sb.WriteString("\n" + colorBold + colorCyan + "========================================================================================================\n" + colorReset)
	sb.WriteString(colorBold + colorWhite + "  MCPGATE // VIRTUAL TOOL SANDBOX, COMMAND AST DECONSTRUCTION & PATH JAIL ISOLATION\n" + colorReset)
	sb.WriteString(colorBold + colorCyan + "========================================================================================================\n" + colorReset)

	sb.WriteString(fmt.Sprintf("  %sTotal Invocations:%s %d  |  %sAuthorized:%s %d  |  %sQuarantined:%s %d  |  %sAvg Risk:%s %.1f/100  |  %sLatency:%s %s\n",
		colorBold, colorReset, summary.TotalEvaluated,
		colorGreen, colorReset, summary.AllowedCount,
		colorRed, colorReset, summary.BlockedCount,
		colorYellow, colorReset, summary.AverageRiskScore,
		colorGray, colorReset, summary.Duration))
	sb.WriteString(colorGray + "--------------------------------------------------------------------------------------------------------\n" + colorReset)

	sb.WriteString(fmt.Sprintf("%-16s %-18s %-20s %-12s %-10s %s\n",
		"AGENT ID", "TOOL NAME", "DECISION", "TIER", "RISK", "STATUS"))
	sb.WriteString(colorGray + "--------------------------------------------------------------------------------------------------------\n" + colorReset)

	for _, ev := range summary.Evaluations {
		statusColor := colorGreen
		statusIcon := "✓ ALLOWED"

		if !ev.IsAllowed {
			statusColor = colorRed
			statusIcon = "✗ QUARANTINED"
		}

		tierColor := colorGreen
		switch ev.IsolationTier {
		case TierPristine:
			tierColor = colorGreen
		case TierGuarded:
			tierColor = colorCyan
		case TierSuspicious:
			tierColor = colorYellow
		case TierHostile:
			tierColor = colorRed
		}

		sb.WriteString(fmt.Sprintf("%-16s %-18s %-20s %s%-12s%s %-10.1f %s%s%s\n",
			truncate(ev.AgentID, 15),
			truncate(ev.ToolName, 17),
			truncate(string(ev.Decision), 19),
			tierColor, string(ev.IsolationTier), colorReset,
			ev.RiskScore,
			statusColor, statusIcon, colorReset))

		sb.WriteString(fmt.Sprintf("  %s↳ Containment Note:%s %s\n", colorGray, colorReset, ev.ContainmentNote))
		if len(ev.Violations) > 0 {
			sb.WriteString(fmt.Sprintf("  %s↳ Violations:%s %s\n", colorRed, colorReset, strings.Join(ev.Violations, "; ")))
		}
	}

	sb.WriteString(colorBold + colorCyan + "========================================================================================================\n\n" + colorReset)
	return sb.String()
}

// RenderSandboxMermaid generates a Mermaid flowchart showing the multi-barrier sandbox verification DAG.
func RenderSandboxMermaid(summary *SandboxSummary) string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart TD\n")
	sb.WriteString("    Req([Agent Tool Invocation]) --> Parse{Inspect Tool Parameters}\n")
	sb.WriteString("    Parse --> PathJail{Path Jailing<br/>Workspace Root &amp; '..' Check}\n")
	sb.WriteString("    PathJail -- Escaped or Protected Dir --> BlockPath[Quarantine: PATH_JAIL_ESCAPE]\n")
	sb.WriteString("    PathJail -- Clean Inside Workspace --> AST{Command AST Analyzer<br/>Dangerous Syscalls &amp; Sockets}\n")
	sb.WriteString("    AST -- 'rm -rf /' / 'mkfs' --> BlockDestruct[Quarantine: DESTRUCTIVE_COMMAND]\n")
	sb.WriteString("    AST -- '/dev/tcp' / 'nc -e' --> BlockShell[Quarantine: REVERSE_SHELL]\n")
	sb.WriteString("    AST -- 'sudo' / 'su' --> BlockPriv[Quarantine: PRIVILEGE_ESCALATION]\n")
	sb.WriteString("    AST -- ':(){ :|:& };:' --> BlockFork[Quarantine: FORK_BOMB]\n")
	sb.WriteString("    AST -- 'curl | sh' --> BlockPipe[Quarantine: PIPELINE_INJECTION]\n")
	sb.WriteString("    AST -- Bounded Commands --> ScoreCheck{Composite Risk Score<br/>Risk &lt; 70 &amp; 0 Violations?}\n")
	sb.WriteString("    ScoreCheck -- Exceeded --> BlockRisk[Quarantine: HIGH_RISK]\n")
	sb.WriteString("    ScoreCheck -- Passed --> Allowed([Authorized: Sandboxed Tool Execution])\n")
	sb.WriteString("```\n")

	return sb.String()
}

// RenderSandboxMarkdown formats a GitHub markdown report of the sandbox audits.
func RenderSandboxMarkdown(summary *SandboxSummary) string {
	var sb strings.Builder

	sb.WriteString("## MCPGate Virtual Tool Sandbox & Path Jail Isolation Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Invocations**: %d\n", summary.TotalEvaluated))
	sb.WriteString(fmt.Sprintf("- **Authorized**: %d\n", summary.AllowedCount))
	sb.WriteString(fmt.Sprintf("- **Quarantined**: %d\n", summary.BlockedCount))
	sb.WriteString(fmt.Sprintf("- **Average Risk Score**: `%.1f / 100`\n", summary.AverageRiskScore))
	sb.WriteString(fmt.Sprintf("- **Verification Latency**: `%s`\n\n", summary.Duration))

	sb.WriteString("| Agent ID | Tool Name | Decision | Isolation Tier | Risk Score | Status |\n")
	sb.WriteString("|:---|:---|:---|:---|:---|:---|\n")

	for _, ev := range summary.Evaluations {
		status := "✅ ALLOWED"
		if !ev.IsAllowed {
			status = "❌ QUARANTINED"
		}
		sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | `%.1f` | %s |\n",
			ev.AgentID, ev.ToolName, ev.Decision, ev.IsolationTier, ev.RiskScore, status))
	}

	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
