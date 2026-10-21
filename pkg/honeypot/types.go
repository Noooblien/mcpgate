package honeypot

import (
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// DeceptionMode defines the gateway's deception response behavior when a canary tripwire is hit.
type DeceptionMode string

const (
	// ModeHoneyedPayload returns plausible synthetic decoy data to confuse the adversary.
	ModeHoneyedPayload DeceptionMode = "HONEYED_PAYLOAD"
	// ModeSyntheticError returns realistic internal errors to simulate a failed privilege check without alerting the attacker.
	ModeSyntheticError DeceptionMode = "SYNTHETIC_ERROR"
	// ModeHardQuarantine immediately drops/blocks the call with an explicit security tripwire violation.
	ModeHardQuarantine DeceptionMode = "HARD_QUARANTINE"
	// ModeTarpit delays the response to exhaust the attacker's automation and rate limits.
	ModeTarpit DeceptionMode = "TARPIT"
)

// TrapSeverity indicates the threat level of the triggered deception tripwire.
type TrapSeverity string

const (
	SeverityCritical TrapSeverity = "CRITICAL" // Root/admin tool invocation, credential exfiltration attempt
	SeverityHigh     TrapSeverity = "HIGH"     // Privilege escalation probe, sensitive schema dump
	SeverityMedium   TrapSeverity = "MEDIUM"   // Canary token parameter detected in standard tool
	SeverityLow      TrapSeverity = "LOW"      // Reconnaissance scan against decoy tool list
)

// CanaryTool defines a decoy MCP tool injected into `tools/list` to attract attackers.
type CanaryTool struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	InputSchema     map[string]interface{} `json:"inputSchema"`
	Severity        TrapSeverity           `json:"severity"`
	DefaultAction   DeceptionMode          `json:"default_action"`
	Category        string                 `json:"category"`        // e.g. "credentials", "execution", "database", "infrastructure"
	SyntheticResult string                 `json:"synthetic_result"` // Plausible JSON string returned in HONEYED_PAYLOAD mode
	SyntheticError  string                 `json:"synthetic_error"`  // Plausible error returned in SYNTHETIC_ERROR mode
}

// TrapEvent records the forensic details of an adversarial probe against a canary tool or token.
type TrapEvent struct {
	EventID        string                 `json:"event_id"`
	Timestamp      time.Time              `json:"timestamp"`
	SessionID      string                 `json:"session_id"`
	AgentID        string                 `json:"agent_id"`
	Role           rbac.AgentRole         `json:"role"`
	ToolName       string                 `json:"tool_name"`
	Arguments      map[string]interface{} `json:"arguments"`
	TrapType       string                 `json:"trap_type"` // "TOOL_DECOY" or "CANARY_TOKEN"
	Severity       TrapSeverity           `json:"severity"`
	DeceptionMode  DeceptionMode          `json:"deception_mode"`
	ResponseSpoof  string                 `json:"response_spoof"`
	Quarantined    bool                   `json:"quarantined"`
	TriggerDetail  string                 `json:"trigger_detail"`
	FingerprintSHA string                 `json:"fingerprint_sha"`
}

// HoneypotConfig defines parameters for decoy injection, tripwires, and deception responses.
type HoneypotConfig struct {
	Enabled               bool          `json:"enabled"`
	DefaultDeceptionMode  DeceptionMode `json:"default_deception_mode"`
	AutoQuarantineSession bool          `json:"auto_quarantine_session"`
	TarpitDelay           time.Duration `json:"tarpit_delay"`
	CanaryTokens          []string      `json:"canary_tokens"` // Known decoy tokens placed in prompts or mock data
}

// HoneypotVerdict is the result of intercepting a tool call through the honeypot engine.
type HoneypotVerdict struct {
	Allowed        bool           `json:"allowed"`
	IsHoneypotHit  bool           `json:"is_honeypot_hit"`
	SessionLocked  bool           `json:"session_locked"`
	DeceptionMode  DeceptionMode  `json:"deception_mode"`
	SpoofedPayload string         `json:"spoofed_payload,omitempty"`
	SpoofedError   string         `json:"spoofed_error,omitempty"`
	Reason         string         `json:"reason"`
	TrapEvent      *TrapEvent     `json:"trap_event,omitempty"`
	AuditLogEntry  map[string]any `json:"audit_log_entry,omitempty"`
}

// HoneypotSummary contains aggregate metrics across multiple honeypot evaluations or scenarios.
type HoneypotSummary struct {
	TotalEvaluated    int          `json:"total_evaluated"`
	TrapsTriggered    int          `json:"traps_triggered"`
	DecoyToolHits     int          `json:"decoy_tool_hits"`
	CanaryTokenHits   int          `json:"canary_token_hits"`
	SessionsLocked    int          `json:"sessions_locked"`
	CleanPassed       int          `json:"clean_passed"`
	CriticalIncidents int          `json:"critical_incidents"`
	HighIncidents     int          `json:"high_incidents"`
	TrappedEvents     []*TrapEvent `json:"trapped_events"`
	Duration          time.Duration `json:"duration"`
}
