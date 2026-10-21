package simulation

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// SimulationGovernor evaluates tool executions speculatively and applies zero-trust blast radius gates.
type SimulationGovernor struct {
	mu         sync.RWMutex
	config     SimulationConfig
	classifier *Classifier
	history    []*SimulationReport
}

// NewSimulationGovernor creates a new governor with the specified config.
func NewSimulationGovernor(cfg SimulationConfig) *SimulationGovernor {
	return &SimulationGovernor{
		config:     cfg,
		classifier: NewClassifier(),
		history:    make([]*SimulationReport, 0),
	}
}

// Simulate evaluates the target tool call speculatively before allowing downstream invocation.
func (g *SimulationGovernor) Simulate(agentID, toolName string, rawArgs []byte) *SimulationReport {
	g.mu.Lock()
	defer g.mu.Unlock()

	category, blastRadius, rollbackStrategy := g.classifier.Classify(toolName, rawArgs)

	decision := DecisionAllowImmediate
	recommendation := "Tool call is within safety boundaries. Execution permitted immediately."
	requiresStepUp := false

	// Policy Gate 1: Catastrophic destruction is unconditionally blocked
	if blastRadius.DestructiveRiskScore >= g.config.BlockCatastrophicAt {
		decision = DecisionBlockHighBlastRadius
		recommendation = fmt.Sprintf("CRITICAL: Unacceptable blast radius (Risk Score %.1f/10.0, Scope: %s). Operation blocked to prevent permanent destruction.", blastRadius.DestructiveRiskScore, blastRadius.ScopeLevel)
	} else if blastRadius.DestructiveRiskScore > g.config.MaxAllowedDestructiveScore ||
		blastRadius.ReversibilityQuotient < g.config.MinRequiredReversibility ||
		blastRadius.EstimatedFinancialRiskUSD > g.config.FinancialCeilingUSD {
		// Policy Gate 2: High blast radius or poor reversibility requires step-up dual custody
		decision = DecisionRequireDualCustodyApproval
		requiresStepUp = true
		recommendation = fmt.Sprintf("ELEVATED RISK: Operation requires dual-custody approval (Risk: %.1f, Reversibility: %.2f, Financial: $%.2f). Awaiting secondary authorization.", blastRadius.DestructiveRiskScore, blastRadius.ReversibilityQuotient, blastRadius.EstimatedFinancialRiskUSD)
	}

	report := &SimulationReport{
		ToolName:            toolName,
		AgentID:             agentID,
		Category:            category,
		Decision:            decision,
		BlastRadius:         blastRadius,
		RollbackStrategy:    rollbackStrategy,
		RecommendedAction:   recommendation,
		RequiresHumanStepUp: requiresStepUp,
		Timestamp:           time.Now().UTC(),
	}

	// Synthesize speculative diff preview for mutation operations
	if category == CategoryReversibleMutation || category == CategoryIrreversibleDestructive {
		report.SpeculativeDiff = fmt.Sprintf("[SPECULATIVE DIFF PREVIEW]\n--- BEFORE: %s (State: Stable, Scope: %s)\n+++ AFTER: Mutated (Est. Entities Affected: %d, Financial Est: $%.2f)",
			toolName, blastRadius.ScopeLevel, blastRadius.EstimatedEntitiesAffected, blastRadius.EstimatedFinancialRiskUSD)
	}

	g.history = append(g.history, report)
	return report
}

// History returns a copy of past simulation reports.
func (g *SimulationGovernor) History() []*SimulationReport {
	g.mu.RLock()
	defer g.mu.RUnlock()
	copied := make([]*SimulationReport, len(g.history))
	copy(copied, g.history)
	return copied
}

// GenerateScorecardMarkdown formats a simulation report into an executive security card.
func (g *SimulationGovernor) GenerateScorecardMarkdown(r *SimulationReport) string {
	statusBadge := "🟢 **ALLOWED**"
	if r.Decision == DecisionRequireDualCustodyApproval {
		statusBadge = "🟡 **REQUIRES DUAL-CUSTODY APPROVAL**"
	} else if r.Decision == DecisionBlockHighBlastRadius {
		statusBadge = "🔴 **BLOCKED: HIGH BLAST RADIUS**"
	}

	return fmt.Sprintf(`### 🛡️ MCPGate Speculative Dry-Run Simulation Report

| Parameter | Assessment |
| :--- | :--- |
| **Tool Name** | `+"`%s`"+` |
| **Agent ID** | `+"`%s`"+` |
| **Operational Category** | **%s** |
| **Simulation Decision** | %s |
| **Destructive Risk Score** | **%.1f / 10.0** |
| **Reversibility Quotient** | **%.2f (Level: %s)** |
| **Estimated Entities Affected**| **%d** |
| **Estimated Financial Risk** | **$%.2f USD** |
| **Scope Level** | **%s** |
| **Requires Step-Up Approval** | **%v** |

#### 🔄 Rollback & Compensation Strategy
> %s

#### 📋 Recommended Action
> %s
`, r.ToolName, r.AgentID, r.Category, statusBadge, r.BlastRadius.DestructiveRiskScore,
		r.BlastRadius.ReversibilityQuotient, r.BlastRadius.ReversibilityLevel,
		r.BlastRadius.EstimatedEntitiesAffected, r.BlastRadius.EstimatedFinancialRiskUSD,
		r.BlastRadius.ScopeLevel, r.RequiresHumanStepUp, r.RollbackStrategy, r.RecommendedAction)
}

// GenerateMermaidDiagram produces a sequence flow visualizing the speculative interception.
func (g *SimulationGovernor) GenerateMermaidDiagram(r *SimulationReport) string {
	sb := &strings.Builder{}
	sb.WriteString("```mermaid\nsequenceDiagram\n")
	sb.WriteString("    autonumber\n")
	sb.WriteString("    participant Agent as Autonomous Agent\n")
	sb.WriteString("    participant Gate as MCPGate Interceptor\n")
	sb.WriteString("    participant Sim as Speculative Simulator\n")
	sb.WriteString("    participant Target as Upstream MCP Tool\n\n")

	sb.WriteString(fmt.Sprintf("    Agent->>Gate: JSON-RPC tools/call (%s)\n", r.ToolName))
	sb.WriteString("    Gate->>Sim: Classify Blast Radius & Side-Effects\n")
	sb.WriteString(fmt.Sprintf("    Sim-->>Gate: Risk: %.1f | Reversibility: %.2f | Decision: %s\n",
		r.BlastRadius.DestructiveRiskScore, r.BlastRadius.ReversibilityQuotient, r.Decision))

	switch r.Decision {
	case DecisionAllowImmediate:
		sb.WriteString("    Gate->>Target: Forward Request (Safe Execution)\n")
		sb.WriteString("    Target-->>Gate: Tool Execution Result\n")
		sb.WriteString("    Gate-->>Agent: Return Sanitized Result\n")
	case DecisionRequireDualCustodyApproval:
		sb.WriteString("    Gate-->>Agent: HTTP 403 Step-Up Required (Dual-Custody Token Needed)\n")
	case DecisionBlockHighBlastRadius:
		sb.WriteString("    Gate-->>Agent: HTTP 403 BLOCKED (High Blast Radius Violation)\n")
	}

	sb.WriteString("```\n")
	return sb.String()
}
