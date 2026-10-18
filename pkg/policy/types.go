package policy

import (
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// PolicyAction defines the enforcement action taken upon rule match.
type PolicyAction string

const (
	ActionAllow           PolicyAction = "ALLOW"
	ActionDeny            PolicyAction = "DENY"
	ActionRequireApproval PolicyAction = "REQUIRE_APPROVAL"
	ActionForceRedaction  PolicyAction = "FORCE_REDACTION"
)

// ArgConstraint represents field-level validation rules on tool arguments.
type ArgConstraint struct {
	FieldName        string `json:"field_name"`
	Required         bool   `json:"required,omitempty"`
	AllowedPattern   string `json:"allowed_pattern,omitempty"`
	ForbiddenPattern string `json:"forbidden_pattern,omitempty"`
	MaxLength        int    `json:"max_length,omitempty"`
	MinLength        int    `json:"min_length,omitempty"`
}

// TemporalWindow specifies allowed operational time windows.
type TemporalWindow struct {
	Enabled     bool           `json:"enabled"`
	AllowedDays []time.Weekday `json:"allowed_days,omitempty"`
	StartHour   int            `json:"start_hour"` // 0-23
	EndHour     int            `json:"end_hour"`   // 0-23
	Timezone    string         `json:"timezone,omitempty"`
}

// PolicyRule defines an individual zero-trust rule.
type PolicyRule struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Description         string          `json:"description,omitempty"`
	Priority            int             `json:"priority"` // Higher number = higher priority
	AgentPattern        string          `json:"agent_pattern"` // Glob or regex, e.g. "agent-prod-*", "*"
	Roles               []rbac.AgentRole `json:"roles"`
	ToolPattern         string          `json:"tool_pattern"` // Glob e.g. "filesystem:*", "read_*", "*"
	ArgConstraints      []ArgConstraint `json:"arg_constraints,omitempty"`
	Temporal            *TemporalWindow `json:"temporal,omitempty"`
	Action              PolicyAction    `json:"action"`
	RequireApproval     bool            `json:"require_approval,omitempty"`
	CustomRateLimitRPM  int             `json:"custom_ratelimit_rpm,omitempty"`
	Reason              string          `json:"reason,omitempty"`
}

// PolicyManifest is the declarative specification for MCPGate policies.
type PolicyManifest struct {
	APIVersion    string       `json:"apiVersion"` // "mcpgate.io/v1"
	Kind          string       `json:"kind"`       // "SecurityPolicy"
	Metadata      PolicyMeta   `json:"metadata"`
	DefaultAction PolicyAction `json:"default_action"` // Typically DENY
	Rules         []PolicyRule `json:"rules"`
}

// PolicyMeta holds metadata for the policy document.
type PolicyMeta struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// PolicyRequest wraps the context for an incoming tool invocation.
type PolicyRequest struct {
	AgentID   string                 `json:"agent_id"`
	Role      rbac.AgentRole         `json:"role"`
	ToolName  string                 `json:"tool_name"`
	Args      map[string]interface{} `json:"args"`
	Timestamp time.Time              `json:"timestamp"`
}

// PolicyDecision encapsulates the evaluation verdict of the policy engine.
type PolicyDecision struct {
	Allowed         bool            `json:"allowed"`
	Action          PolicyAction    `json:"action"`
	MatchedRuleID   string          `json:"matched_rule_id,omitempty"`
	MatchedRuleName string          `json:"matched_rule_name,omitempty"`
	Reason          string          `json:"reason"`
	RequireApproval bool            `json:"require_approval"`
	Violations      []string        `json:"violations,omitempty"`
	EffectiveRPM    int             `json:"effective_rpm,omitempty"`
}
