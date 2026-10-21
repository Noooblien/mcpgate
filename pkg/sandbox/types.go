package sandbox

import (
	"time"
)

// SandboxMode specifies the enforcement posture of the sandbox container.
type SandboxMode string

const (
	ModeEnforcing SandboxMode = "ENFORCING" // Hard blocks on sandbox and path-jail violations
	ModeAudit     SandboxMode = "AUDIT"     // Permits execution with comprehensive telemetry alerts
	ModeDisabled  SandboxMode = "DISABLED"  // Bypass sandbox checks
)

// SandboxDecision classifies the outcome of the sandbox inspection.
type SandboxDecision string

const (
	DecisionAllowed             SandboxDecision = "ALLOWED"
	DecisionDestructiveCommand  SandboxDecision = "DESTRUCTIVE_COMMAND"
	DecisionPathJailEscape      SandboxDecision = "PATH_JAIL_ESCAPE"
	DecisionReverseShell        SandboxDecision = "REVERSE_SHELL"
	DecisionPrivilegeEscalation SandboxDecision = "PRIVILEGE_ESCALATION"
	DecisionForkBombPattern     SandboxDecision = "FORK_BOMB"
	DecisionProtectedPathAccess SandboxDecision = "PROTECTED_PATH"
	DecisionPipelineInjection   SandboxDecision = "PIPELINE_INJECTION"
)

// IsolationTier categorizes the overall threat posture and confinement level.
type IsolationTier string

const (
	TierPristine   IsolationTier = "PRISTINE"   // Risk 0-15: Safe, bounded command within virtual workspace
	TierGuarded    IsolationTier = "GUARDED"    // Risk 16-45: Standard developer operation with containment boundaries
	TierSuspicious IsolationTier = "SUSPICIOUS" // Risk 46-75: Anomalous arguments or traversal attempts flagged
	TierHostile    IsolationTier = "HOSTILE"    // Risk 76-100: Malicious destructive exploit, reverse shell, or jail escape
)

// SandboxConfig governs the filesystem jailing and command AST boundaries.
type SandboxConfig struct {
	Mode               SandboxMode `json:"mode"`
	WorkspaceRoot      string      `json:"workspace_root"`
	BlockedSystemDirs  []string    `json:"blocked_system_dirs"`
	SensitiveFiles     []string    `json:"sensitive_files"`
	MaxCommandPipes    int         `json:"max_command_pipes"`
	MaxArgLength       int         `json:"max_arg_length"`
	StrictPathJailing  bool        `json:"strict_path_jailing"`
	AllowNetworkPipes  bool        `json:"allow_network_pipes"`
}

// SandboxRequest captures incoming tool invocation parameters for sandboxing.
type SandboxRequest struct {
	RequestID string                 `json:"request_id"`
	AgentID   string                 `json:"agent_id"`
	ToolName  string                 `json:"tool_name"`
	Command   string                 `json:"command,omitempty"`
	Path      string                 `json:"path,omitempty"`
	Args      map[string]interface{} `json:"args,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// SandboxEvaluation details the security analysis, risk score, and containment decision.
type SandboxEvaluation struct {
	RequestID       string          `json:"request_id"`
	AgentID         string          `json:"agent_id"`
	ToolName        string          `json:"tool_name"`
	Decision        SandboxDecision `json:"decision"`
	IsAllowed       bool            `json:"is_allowed"`
	IsolationTier   IsolationTier   `json:"isolation_tier"`
	RiskScore       float64         `json:"risk_score"` // 0.0 to 100.0
	Violations      []string        `json:"violations"`
	SanitizedPath   string          `json:"sanitized_path,omitempty"`
	ParsedCommands  []string        `json:"parsed_commands,omitempty"`
	ContainmentNote string          `json:"containment_note"`
	Duration        time.Duration   `json:"duration"`
	EvaluatedAt     time.Time       `json:"evaluated_at"`
}

// SandboxSummary aggregates multiple sandbox evaluations for scorecard reporting.
type SandboxSummary struct {
	TotalEvaluated  int                   `json:"total_evaluated"`
	AllowedCount    int                   `json:"allowed_count"`
	BlockedCount    int                   `json:"blocked_count"`
	AverageRiskScore float64              `json:"average_risk_score"`
	TierBreakdown   map[IsolationTier]int `json:"tier_breakdown"`
	Evaluations     []*SandboxEvaluation  `json:"evaluations"`
	Duration        time.Duration         `json:"duration"`
}
