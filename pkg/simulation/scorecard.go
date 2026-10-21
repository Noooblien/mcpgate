package simulation

import (
	"fmt"
	"strings"
	"time"
)

// SimulationSummary aggregates multiple speculative dry-run evaluations.
type SimulationSummary struct {
	TotalSimulations int
	AllowedImmediate int
	RequireStepUp    int
	Blocked          int
	AverageRiskScore float64
	TotalFinancialExposureUSD float64
	Simulations      []*SimulationReport
	Duration         time.Duration
}

// RenderSimulationScorecard prints an ANSI terminal scorecard for simulation evaluations.
func RenderSimulationScorecard(summary SimulationSummary) string {
	sb := &strings.Builder{}

	sb.WriteString("\n\033[1;36m========================================================================================\033[0m\n")
	sb.WriteString("   \033[1;37mMCPGATE SPECULATIVE DRY-RUN SIMULATION & BLAST RADIUS SCORECARD\033[0m\n")
	sb.WriteString("\033[1;36m========================================================================================\033[0m\n\n")

	sb.WriteString(fmt.Sprintf("  \033[1;33mTotal Simulations:\033[0m           %d\n", summary.TotalSimulations))
	sb.WriteString(fmt.Sprintf("  \033[1;32mImmediate Allow (Safe):\033[0m      %d\n", summary.AllowedImmediate))
	sb.WriteString(fmt.Sprintf("  \033[1;33mStep-Up Dual Custody:\033[0m        %d\n", summary.RequireStepUp))
	sb.WriteString(fmt.Sprintf("  \033[1;31mBlocked (High Blast Radius):\033[0m %d\n", summary.Blocked))
	sb.WriteString(fmt.Sprintf("  \033[1;35mAverage Risk Score:\033[0m          %.2f / 10.0\n", summary.AverageRiskScore))
	sb.WriteString(fmt.Sprintf("  \033[1;34mTotal Financial Exposure:\033[0m    $%.2f USD\n", summary.TotalFinancialExposureUSD))
	sb.WriteString(fmt.Sprintf("  \033[1;36mEvaluation Latency:\033[0m          %v\n\n", summary.Duration))

	sb.WriteString("\033[1;34m----------------------------------------------------------------------------------------\033[0m\n")
	sb.WriteString("  \033[1;37mSIMULATION EVALUATION DETAILS:\033[0m\n")
	sb.WriteString("\033[1;34m----------------------------------------------------------------------------------------\033[0m\n")

	for i, sim := range summary.Simulations {
		verdictColor := "\033[1;32mALLOW_IMMEDIATE\033[0m"
		if sim.Decision == DecisionRequireDualCustodyApproval {
			verdictColor = "\033[1;33mREQUIRE_DUAL_CUSTODY\033[0m"
		} else if sim.Decision == DecisionBlockHighBlastRadius {
			verdictColor = "\033[1;31mBLOCK_HIGH_BLAST_RADIUS\033[0m"
		}

		sb.WriteString(fmt.Sprintf("  [%d] Tool: \033[1;37m%-24s\033[0m | Agent: %-12s | Category: %-18s\n",
			i+1, sim.ToolName, sim.AgentID, sim.Category))
		sb.WriteString(fmt.Sprintf("      Verdict: %s | Risk: %.1f/10.0 | Reversibility: %.2f (%s)\n",
			verdictColor, sim.BlastRadius.DestructiveRiskScore, sim.BlastRadius.ReversibilityQuotient, sim.BlastRadius.ReversibilityLevel))
		sb.WriteString(fmt.Sprintf("      Entities: %d | Financial: $%.2f | Scope: %s\n",
			sim.BlastRadius.EstimatedEntitiesAffected, sim.BlastRadius.EstimatedFinancialRiskUSD, sim.BlastRadius.ScopeLevel))
		sb.WriteString(fmt.Sprintf("      Rollback: \033[0;37m%s\033[0m\n", sim.RollbackStrategy))
		sb.WriteString(fmt.Sprintf("      Action:   \033[0;33m%s\033[0m\n\n", sim.RecommendedAction))
	}

	sb.WriteString("\033[1;36m========================================================================================\033[0m\n")
	return sb.String()
}

// RenderSimulationMarkdown produces an executive markdown report for dry-run simulations.
func RenderSimulationMarkdown(summary SimulationSummary) string {
	sb := &strings.Builder{}

	sb.WriteString("# 🔮 MCPGate Speculative Dry-Run Simulation & Blast Radius Report\n\n")
	sb.WriteString(fmt.Sprintf("**Timestamp:** `%s`  \n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Total Simulations:** `%d`  \n", summary.TotalSimulations))
	sb.WriteString(fmt.Sprintf("**Allowed Immediately:** `%d` | **Step-Up Dual Custody:** `%d` | **Blocked:** `%d`  \n",
		summary.AllowedImmediate, summary.RequireStepUp, summary.Blocked))
	sb.WriteString(fmt.Sprintf("**Average Risk Score:** `%.2f / 10.0`  \n", summary.AverageRiskScore))
	sb.WriteString(fmt.Sprintf("**Total Financial Exposure:** `$%.2f USD`  \n", summary.TotalFinancialExposureUSD))
	sb.WriteString(fmt.Sprintf("**Evaluation Latency:** `%v`  \n\n", summary.Duration))

	sb.WriteString("## Evaluation Matrix\n\n")
	sb.WriteString("| # | Target Tool | Agent | Category | Decision | Risk | Reversibility | Financial | Rollback Strategy |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|---|\n")

	for i, sim := range summary.Simulations {
		badge := "🟢 ALLOW"
		if sim.Decision == DecisionRequireDualCustodyApproval {
			badge = "🟡 STEP-UP"
		} else if sim.Decision == DecisionBlockHighBlastRadius {
			badge = "🔴 BLOCK"
		}

		sb.WriteString(fmt.Sprintf("| %d | `%s` | `%s` | `%s` | %s | `%.1f` | `%.2f (%s)` | `$%.2f` | %s |\n",
			i+1, sim.ToolName, sim.AgentID, sim.Category, badge,
			sim.BlastRadius.DestructiveRiskScore, sim.BlastRadius.ReversibilityQuotient, sim.BlastRadius.ReversibilityLevel,
			sim.BlastRadius.EstimatedFinancialRiskUSD, sim.RollbackStrategy))
	}

	sb.WriteString("\n## Remediation & Rollback Recommendations\n\n")
	for i, sim := range summary.Simulations {
		sb.WriteString(fmt.Sprintf("### %d. `%s` (%s)\n", i+1, sim.ToolName, sim.Category))
		sb.WriteString(fmt.Sprintf("- **Decision:** `%s`\n", sim.Decision))
		sb.WriteString(fmt.Sprintf("- **Blast Radius Scope:** `%s` (Affected Entities: %d)\n", sim.BlastRadius.ScopeLevel, sim.BlastRadius.EstimatedEntitiesAffected))
		sb.WriteString(fmt.Sprintf("- **Rollback Guide:** %s\n", sim.RollbackStrategy))
		sb.WriteString(fmt.Sprintf("- **Recommended Action:** %s\n\n", sim.RecommendedAction))
	}

	return sb.String()
}

// RenderSimulationMermaid generates a Mermaid sequence diagram for a simulation summary.
func RenderSimulationMermaid(simulations []*SimulationReport) string {
	sb := &strings.Builder{}
	sb.WriteString("```mermaid\nsequenceDiagram\n")
	sb.WriteString("    autonumber\n")
	sb.WriteString("    participant Agent as Autonomous Agent\n")
	sb.WriteString("    participant Gate as MCPGate Gateway\n")
	sb.WriteString("    participant Sim as Speculative Simulator\n")
	sb.WriteString("    participant Upstream as Target MCP Server\n\n")

	for _, sim := range simulations {
		sb.WriteString(fmt.Sprintf("    Agent->>Gate: tools/call (%s)\n", sim.ToolName))
		sb.WriteString("    Gate->>Sim: Speculative Dry-Run & Blast Radius Assessment\n")
		sb.WriteString(fmt.Sprintf("    Sim-->>Gate: Risk: %.1f | Reversibility: %.2f | Scope: %s\n",
			sim.BlastRadius.DestructiveRiskScore, sim.BlastRadius.ReversibilityQuotient, sim.BlastRadius.ScopeLevel))

		switch sim.Decision {
		case DecisionAllowImmediate:
			sb.WriteString("    Gate->>Upstream: Forward Verified Safe Call\n")
			sb.WriteString("    Upstream-->>Agent: Execution Result\n")
		case DecisionRequireDualCustodyApproval:
			sb.WriteString("    Gate-->>Agent: 403 Suspended (Dual-Custody Approval Required)\n")
		case DecisionBlockHighBlastRadius:
			sb.WriteString("    Gate-->>Agent: 403 Forbidden (Catastrophic Blast Radius Blocked)\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("```\n")
	return sb.String()
}
