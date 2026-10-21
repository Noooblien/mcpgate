package simulation

import (
	"time"
)

// SideEffectCategory designates the operational nature of an MCP tool execution.
type SideEffectCategory string

const (
	CategoryReadOnly               SideEffectCategory = "read_only"
	CategoryReversibleMutation      SideEffectCategory = "reversible_mutation"
	CategoryIrreversibleDestructive SideEffectCategory = "irreversible_destructive"
	CategoryExternalEgress          SideEffectCategory = "external_egress"
	CategoryResourceAllocation      SideEffectCategory = "resource_allocation"
)

// ReversibilityLevel designates the ease of rolling back or compensating for side-effects.
type ReversibilityLevel string

const (
	ReversibleFully             ReversibilityLevel = "fully_reversible"
	ReversibleWithManualEffort  ReversibilityLevel = "manual_effort_required"
	Irreversible                ReversibilityLevel = "irreversible"
)

// SimulationDecision indicates the policy outcome after speculative dry-run inspection.
type SimulationDecision string

const (
	DecisionAllowImmediate             SimulationDecision = "allow_immediate"
	DecisionRequireDualCustodyApproval SimulationDecision = "require_dual_custody"
	DecisionBlockHighBlastRadius       SimulationDecision = "block_high_blast_radius"
)

// BlastRadiusEstimate captures the quantitative magnitude of potential impact.
type BlastRadiusEstimate struct {
	EstimatedEntitiesAffected int                `json:"estimated_entities_affected"`
	EstimatedFinancialRiskUSD float64            `json:"estimated_financial_risk_usd"`
	ScopeLevel                string             `json:"scope_level"` // "isolated", "tenant_wide", "infrastructure_wide"
	DestructiveRiskScore      float64            `json:"destructive_risk_score"` // 0.0 (safe) to 10.0 (catastrophic)
	ReversibilityQuotient     float64            `json:"reversibility_quotient"` // 1.0 (trivial undo) to 0.0 (permanent)
	ReversibilityLevel        ReversibilityLevel `json:"reversibility_level"`
}

// SimulationReport represents the complete assessment produced by the speculative simulation engine.
type SimulationReport struct {
	ToolName            string              `json:"tool_name"`
	AgentID             string              `json:"agent_id"`
	Category            SideEffectCategory  `json:"category"`
	Decision            SimulationDecision  `json:"decision"`
	BlastRadius         BlastRadiusEstimate `json:"blast_radius"`
	RollbackStrategy    string              `json:"rollback_strategy"`
	RecommendedAction   string              `json:"recommended_action"`
	SpeculativeDiff     string              `json:"speculative_diff,omitempty"`
	RequiresHumanStepUp bool                `json:"requires_human_step_up"`
	Timestamp           time.Time           `json:"timestamp"`
}

// SimulationConfig defines thresholds governing speculative execution and dual-custody gates.
type SimulationConfig struct {
	MaxAllowedDestructiveScore float64 // Calls exceeding this are blocked or require dual custody (default 6.0)
	MinRequiredReversibility   float64 // Calls below this reversibility quotient are gated (default 0.4)
	FinancialCeilingUSD        float64 // Calls risking more than this require approval (default 100.0)
	BlockCatastrophicAt        float64 // Score >= this will be unconditionally blocked (default 9.0)
	EnableDryRunInference      bool    // Attempt automated dry-run flag synthesis
}

// DefaultConfig provides conservative, zero-trust security thresholds.
func DefaultConfig() SimulationConfig {
	return SimulationConfig{
		MaxAllowedDestructiveScore: 6.0,
		MinRequiredReversibility:   0.40,
		FinancialCeilingUSD:        100.00,
		BlockCatastrophicAt:        9.0,
		EnableDryRunInference:      true,
	}
}
