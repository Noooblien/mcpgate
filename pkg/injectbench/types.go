package injectbench

import (
	"time"
)

// AttackCategory defines the threat taxonomy of an MCP injection test case.
type AttackCategory string

const (
	CatDirectOverride      AttackCategory = "direct_prompt_override"
	CatSystemHijack        AttackCategory = "system_delimiter_smuggling"
	CatCanaryExfiltration  AttackCategory = "honeytoken_exfiltration"
	CatObfuscation         AttackCategory = "obfuscated_unicode_evasion"
	CatPathTraversalSSRF   AttackCategory = "path_traversal_cloud_ssrf"
	CatCommandExecRCE      AttackCategory = "destructive_command_rce"
	CatBenignControl       AttackCategory = "benign_developer_control"
)

// ExpectedAction specifies ground-truth mitigation expectation.
type ExpectedAction string

const (
	ActionBlock  ExpectedAction = "block"
	ActionRedact ExpectedAction = "redact"
	ActionAllow  ExpectedAction = "allow"
)

// TestCase represents an individual standardized MCP tool call benchmark item.
type TestCase struct {
	ID             string                 `json:"id"`
	Category       AttackCategory         `json:"category"`
	ToolName       string                 `json:"tool_name"`
	Args           map[string]interface{} `json:"args"`
	IsMalicious    bool                   `json:"is_malicious"`
	ExpectedAction ExpectedAction         `json:"expected_action"`
	Description    string                 `json:"description"`
}

// BenchmarkConfig controls execution parameters and threshold gates.
type BenchmarkConfig struct {
	Iterations         int     `json:"iterations"`
	StrictMode         bool    `json:"strict_mode"`
	TargetRole         string  `json:"target_role"`
	OutputFormat       string  `json:"output_format"` // "text", "markdown", "json"
	MaxLatencyBudgetMs float64 `json:"max_latency_budget_ms"`
	MinResilienceScore float64 `json:"min_resilience_score"`
}

// DefaultBenchmarkConfig returns standard calibration settings.
func DefaultBenchmarkConfig() BenchmarkConfig {
	return BenchmarkConfig{
		Iterations:         100,
		StrictMode:         false,
		TargetRole:         "standard",
		OutputFormat:       "text",
		MaxLatencyBudgetMs: 5.0,
		MinResilienceScore: 100.0,
	}
}

// CategoryResult tracks empirical defense metrics for a specific vulnerability class.
type CategoryResult struct {
	Category        AttackCategory `json:"category"`
	TotalInvocations int           `json:"total_invocations"`
	BlockedCount    int            `json:"blocked_count"`
	RedactedCount   int            `json:"redacted_count"`
	AllowedCount    int            `json:"allowed_count"`
	FalsePositives  int            `json:"false_positives"`
	FalseNegatives  int            `json:"false_negatives"`
	RecallRate      float64        `json:"recall_rate"`
	FalsePositiveRate float64      `json:"false_positive_rate"`
	MeanLatencyMs   float64        `json:"mean_latency_ms"`
	P95LatencyMs    float64        `json:"p95_latency_ms"`
	Passed          bool           `json:"passed"`
}

// BenchmarkSummary contains aggregate results across all categories.
type BenchmarkSummary struct {
	Timestamp          time.Time        `json:"timestamp"`
	TotalInvocations   int              `json:"total_invocations"`
	TotalAttacks       int              `json:"total_attacks"`
	TotalBenign        int              `json:"total_benign"`
	AttacksMitigated   int              `json:"attacks_mitigated"`
	AttacksBypassed    int              `json:"attacks_bypassed"`
	FalsePositives     int              `json:"false_positives"`
	OverallRecallRate  float64          `json:"overall_recall_rate"`
	ResilienceScore    float64          `json:"resilience_score"` // 0.0 - 100.0
	OverallPassed      bool             `json:"overall_passed"`
	ThroughputOpsSec   float64          `json:"throughput_ops_sec"`
	P50LatencyMs       float64          `json:"p50_latency_ms"`
	P95LatencyMs       float64          `json:"p95_latency_ms"`
	P99LatencyMs       float64          `json:"p99_latency_ms"`
	TotalDuration      time.Duration    `json:"total_duration"`
	Categories         []CategoryResult `json:"categories"`
	BypassDetails      []string         `json:"bypass_details,omitempty"`
}
