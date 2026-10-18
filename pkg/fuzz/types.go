package fuzz

import "time"

// AttackCategory classifies the security vulnerability vector being fuzzed.
type AttackCategory string

const (
	AttackPromptInjection    AttackCategory = "PROMPT_INJECTION"
	AttackCommandInjection   AttackCategory = "COMMAND_INJECTION"
	AttackPathTraversal      AttackCategory = "PATH_TRAVERSAL"
	AttackSSRF               AttackCategory = "SSRF_CLOUD_METADATA"
	AttackSecretExfiltration AttackCategory = "SECRET_EXFILTRATION"
	AttackRecursiveLoop      AttackCategory = "RECURSIVE_LOOP"
	AttackBufferOverflow     AttackCategory = "BUFFER_OVERFLOW"
	AttackUnicodeBypass      AttackCategory = "UNICODE_EVASION"
)

// FuzzPayload represents an automated adversarial test case targeting an MCP tool.
type FuzzPayload struct {
	ID              string                 `json:"id"`
	Category        AttackCategory         `json:"category"`
	Name            string                 `json:"name"`
	ToolName        string                 `json:"tool_name"`
	Arguments       map[string]interface{} `json:"arguments"`
	ExpectedBlocked bool                   `json:"expected_blocked"`
	Description     string                 `json:"description"`
}

// TrialResult records the outcome of a single adversarial trial through MCPGate.
type TrialResult struct {
	Payload     FuzzPayload `json:"payload"`
	Blocked     bool        `json:"blocked"`
	BlockReason string      `json:"block_reason"`
	ThreatScore float64     `json:"threat_score"`
	LatencyMs   float64     `json:"latency_ms"`
	Passed      bool        `json:"passed"` // Successfully blocked if malicious, allowed if benign
}

// FuzzSecurityReport summarizes the adversarial fuzz testing suite execution.
type FuzzSecurityReport struct {
	TotalTrials      int           `json:"total_trials"`
	BlockedCount     int           `json:"blocked_count"`
	AllowedCount     int           `json:"allowed_count"`
	FalseNegatives   int           `json:"false_negatives"`
	ResilienceScore  float64       `json:"resilience_score"` // Percentage of attacks neutralized
	AverageLatencyMs float64       `json:"average_latency_ms"`
	Trials           []TrialResult `json:"trials"`
	ExecutedAt       time.Time     `json:"executed_at"`
	Passed           bool          `json:"passed"`
}
