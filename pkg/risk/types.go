package risk

import (
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// RiskLevel categorizes the instantaneous or cumulative risk of an agent action.
type RiskLevel string

const (
	RiskLevelNone     RiskLevel = "NONE"     // 0 - 15 points
	RiskLevelLow      RiskLevel = "LOW"      // 16 - 35 points
	RiskLevelMedium   RiskLevel = "MEDIUM"   // 36 - 65 points
	RiskLevelHigh     RiskLevel = "HIGH"     // 66 - 85 points
	RiskLevelCritical RiskLevel = "CRITICAL" // 86 - 100+ points
)

// RiskVerdict specifies the governor's enforcement decision for the tool execution.
type RiskVerdict string

const (
	VerdictAllowed          RiskVerdict = "ALLOWED"            // Within budget, proceed normally
	VerdictWarning          RiskVerdict = "WARNING"            // Near budget ceiling, warn telemetry
	VerdictStepUpApproval   RiskVerdict = "STEP_UP_APPROVAL"   // Exceeds safe autonomous threshold; requires human approval
	VerdictQuarantinedBlock RiskVerdict = "QUARANTINED_BLOCK"  // Budget depleted or burst velocity anomaly; execution locked
)

// RiskDimension represents a fundamental blast radius attack or impact surface.
type RiskDimension string

const (
	DimFilesystemMutation   RiskDimension = "filesystem_mutation"   // File writes, modifications, deletions
	DimNetworkEgress        RiskDimension = "network_egress"        // Outbound HTTP/socket traffic, external data transfer
	DimFinancialCost        RiskDimension = "financial_cost"        // Cloud spend, API billing, payment transfers
	DimPrivilegeEscalation  RiskDimension = "privilege_escalation"  // Shell execution, root/sudo, IAM/credential changes
	DimDataExfiltration     RiskDimension = "data_exfiltration"     // Reading and transmitting sensitive DB/PII tables
	DimIrreversibility      RiskDimension = "irreversibility"       // Permanent unrecoverable actions (drop database, force push)
)

// DimensionBreakdown details the score contribution across all blast radius vectors.
type DimensionBreakdown struct {
	Filesystem   float64 `json:"filesystem_mutation"`
	Network      float64 `json:"network_egress"`
	Financial    float64 `json:"financial_cost"`
	Privilege    float64 `json:"privilege_escalation"`
	Exfiltration float64 `json:"data_exfiltration"`
	Permanent    float64 `json:"irreversibility"`
}

// ToolRiskProfile defines base hazard characteristics for a known or inferred tool.
type ToolRiskProfile struct {
	ToolName        string             `json:"tool_name"`
	BaseScore       float64            `json:"base_score"`       // Baseline risk (0.0 to 100.0)
	Dimensions      DimensionBreakdown `json:"dimensions"`       // Primary dimension weights
	IsMutating      bool               `json:"is_mutating"`      // Whether action mutates state
	IsIrreversible  bool               `json:"is_irreversible"`  // Whether action cannot be rolled back
	RequiresHITL    bool               `json:"requires_hitl"`    // Requires Human-in-the-Loop regardless of score
}

// RiskAssessment encapsulates the evaluated risk of a single tool execution within a session.
type RiskAssessment struct {
	AssessmentID       string             `json:"assessment_id"`
	Timestamp          time.Time          `json:"timestamp"`
	SessionID          string             `json:"session_id"`
	AgentID            string             `json:"agent_id"`
	Role               rbac.AgentRole     `json:"role"`
	ToolName           string             `json:"tool_name"`
	InstantaneousScore float64            `json:"instantaneous_score"` // 0.0 to 100.0
	RiskLevel          RiskLevel          `json:"risk_level"`
	Verdict            RiskVerdict        `json:"verdict"`
	CumulativeScore    float64            `json:"cumulative_score"`    // Current session cumulative risk
	BudgetLimit        float64            `json:"budget_limit"`        // Max cumulative score allowed
	BudgetRemaining    float64            `json:"budget_remaining"`
	VelocityScore      float64            `json:"velocity_score"`      // Points accrued in the last sliding window
	Dimensions         DimensionBreakdown `json:"dimensions"`
	RiskFactors        []string           `json:"risk_factors"`
	Explanation        string             `json:"explanation"`
	DurationUs         int64              `json:"duration_us"`
}

// SessionRiskState tracks cumulative blast radius and activity history for an agent session.
type SessionRiskState struct {
	SessionID       string            `json:"session_id"`
	AgentID         string            `json:"agent_id"`
	Role            rbac.AgentRole    `json:"role"`
	CumulativeScore float64           `json:"cumulative_score"`
	LastDecayTime   time.Time         `json:"last_decay_time"`
	TotalCalls      int               `json:"total_calls"`
	BlockedCalls    int               `json:"blocked_calls"`
	IsQuarantined   bool              `json:"is_quarantined"`
	QuarantineReason string           `json:"quarantine_reason,omitempty"`
	History         []RiskScorePoint  `json:"history"`
}

// RiskScorePoint records a timestamped risk accrual event.
type RiskScorePoint struct {
	Timestamp time.Time `json:"timestamp"`
	ToolName  string    `json:"tool_name"`
	Score     float64   `json:"score"`
}

// RiskGovernorConfig configures thresholds and decay kinetics for the blast radius governor.
type RiskGovernorConfig struct {
	SessionRiskBudget      float64       `json:"session_risk_budget"`       // Default 100.0 cumulative points
	WarningThresholdPct    float64       `json:"warning_threshold_pct"`     // Default 70.0% of budget
	HalfLifeDecay          time.Duration `json:"half_life_decay"`           // Risk halves every N minutes (default 15m)
	VelocityWindow         time.Duration `json:"velocity_window"`           // Velocity inspection window (default 30s)
	VelocityThreshold      float64       `json:"velocity_threshold"`        // Rapid burst threshold in velocity window (default 50.0 pts)
	RoleBudgetMultipliers  map[rbac.AgentRole]float64 `json:"role_multipliers"` // Role-based budget adjustments
}

// DefaultRiskGovernorConfig returns enterprise-hardened zero-trust defaults.
func DefaultRiskGovernorConfig() RiskGovernorConfig {
	return RiskGovernorConfig{
		SessionRiskBudget:   100.0,
		WarningThresholdPct: 70.0,
		HalfLifeDecay:       15 * time.Minute,
		VelocityWindow:      30 * time.Second,
		VelocityThreshold:   50.0,
		RoleBudgetMultipliers: map[rbac.AgentRole]float64{
			rbac.RoleAdmin:      2.0,  // 200 pt budget
			rbac.RoleStandard:   1.0,  // 100 pt budget
			rbac.RoleRestricted: 0.5,  // 50 pt budget
			rbac.RoleReadOnly:   0.25, // 25 pt budget
		},
	}
}
