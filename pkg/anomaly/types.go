package anomaly

import "time"

// AnomalyVerdict represents the operational gating action taken by the anomaly engine.
type AnomalyVerdict string

const (
	VerdictAllow      AnomalyVerdict = "ALLOW"      // Normal tool call within standard statistical variance
	VerdictAlert      AnomalyVerdict = "ALERT"      // Mild statistical deviation; logged to security audit trail
	VerdictQuarantine AnomalyVerdict = "QUARANTINE" // Severe deviation; agent execution temporarily suspended
	VerdictBlock      AnomalyVerdict = "BLOCK"      // Out-of-bounds illegal sequence or attack; call rejected immediately
)

// AnomalySeverity categorizes the risk intensity.
type AnomalySeverity string

const (
	SeverityLow      AnomalySeverity = "LOW"
	SeverityMedium   AnomalySeverity = "MEDIUM"
	SeverityHigh     AnomalySeverity = "HIGH"
	SeverityCritical AnomalySeverity = "CRITICAL"
)

// TransitionKey represents a directed edge in the Markov tool execution graph: "fromTool->toTool".
type TransitionKey string

// FormatTransitionKey formats two tool names into a canonical TransitionKey.
func FormatTransitionKey(fromTool, toTool string) TransitionKey {
	return TransitionKey(fromTool + "->" + toTool)
}

// PayloadDistribution tracks rolling statistical dispersion metrics for tool arguments.
type PayloadDistribution struct {
	Count       int     `json:"count"`
	MeanLength  float64 `json:"mean_length"`
	M2Length    float64 `json:"m2_length"` // For Welford's algorithm variance
	MinLength   int     `json:"min_length"`
	MaxLength   int     `json:"max_length"`
	MeanEntropy float64 `json:"mean_entropy"`
	M2Entropy   float64 `json:"m2_entropy"`
	MinEntropy  float64 `json:"min_entropy"`
	MaxEntropy  float64 `json:"max_entropy"`
}

// ToolProfile stores baseline parameters and payload metrics for a specific tool.
type ToolProfile struct {
	ToolName        string                 `json:"tool_name"`
	AllowedKeys     map[string]bool        `json:"allowed_keys"`
	PayloadStats    PayloadDistribution    `json:"payload_stats"`
	TotalInvocations int                   `json:"total_invocations"`
}

// AgentBehavioralBaseline contains the trained behavioral profile of an authorized agent.
type AgentBehavioralBaseline struct {
	AgentID             string                  `json:"agent_id"`
	TotalCalls          int                     `json:"total_calls"`
	ToolProfiles        map[string]*ToolProfile `json:"tool_profiles"`
	MarkovTransitions   map[TransitionKey]int   `json:"markov_transitions"`
	SourceToolCounts    map[string]int          `json:"source_tool_counts"`
	LastUpdated         time.Time               `json:"last_updated"`
}

// ToolCallObservation encapsulates a live tool invocation being evaluated.
type ToolCallObservation struct {
	ObservationID string                 `json:"observation_id"`
	SessionID     string                 `json:"session_id"`
	AgentID       string                 `json:"agent_id"`
	ToolName      string                 `json:"tool_name"`
	PriorTool     string                 `json:"prior_tool,omitempty"`
	Arguments     map[string]interface{} `json:"arguments"`
	Timestamp     time.Time              `json:"timestamp"`
}

// AnomalyAssessment reports detailed multi-dimensional anomaly scores and verdicts.
type AnomalyAssessment struct {
	ObservationID          string          `json:"observation_id"`
	Timestamp              time.Time       `json:"timestamp"`
	SessionID              string          `json:"session_id"`
	AgentID                string          `json:"agent_id"`
	ToolName               string          `json:"tool_name"`
	PriorTool              string          `json:"prior_tool,omitempty"`
	SequenceAnomalyScore   float64         `json:"sequence_anomaly_score"`
	PayloadAnomalyScore    float64         `json:"payload_anomaly_score"`
	EntropyAnomalyScore    float64         `json:"entropy_anomaly_score"`
	ParameterAnomalyScore  float64         `json:"parameter_anomaly_score"`
	CompositeScore         float64         `json:"composite_score"`
	Verdict                AnomalyVerdict  `json:"verdict"`
	Severity               AnomalySeverity `json:"severity"`
	ContributingFactors    []string        `json:"contributing_factors"`
	MitigationAdvice       string          `json:"mitigation_advice"`
	LatencyDuration        time.Duration   `json:"latency_duration"`
}

// AnomalyPolicy defines configurable scoring weights, decision thresholds, and limits.
type AnomalyPolicy struct {
	AlertThreshold       float64 `json:"alert_threshold"`       // e.g. 0.40
	QuarantineThreshold  float64 `json:"quarantine_threshold"`  // e.g. 0.70
	BlockThreshold       float64 `json:"block_threshold"`       // e.g. 0.85
	WeightSequence       float64 `json:"weight_sequence"`       // e.g. 0.40
	WeightPayload        float64 `json:"weight_payload"`        // e.g. 0.25
	WeightEntropy        float64 `json:"weight_entropy"`        // e.g. 0.20
	WeightParameters     float64 `json:"weight_parameters"`     // e.g. 0.15
	LaplaceSmoothingAlpha float64 `json:"laplace_smoothing_alpha"` // e.g. 1.0
	MaxZScore            float64 `json:"max_z_score"`            // e.g. 3.0
	MinObservations      int     `json:"min_observations"`      // Minimum baseline history
}

// DefaultAnomalyPolicy provides enterprise-calibrated zero-trust anomaly policy defaults.
func DefaultAnomalyPolicy() AnomalyPolicy {
	return AnomalyPolicy{
		AlertThreshold:        0.40,
		QuarantineThreshold:   0.70,
		BlockThreshold:        0.85,
		WeightSequence:        0.40,
		WeightPayload:         0.25,
		WeightEntropy:         0.20,
		WeightParameters:      0.15,
		LaplaceSmoothingAlpha: 1.0,
		MaxZScore:             3.0,
		MinObservations:       5,
	}
}

// AnomalySummary aggregates the results of multiple evaluations for reporting.
type AnomalySummary struct {
	TotalEvaluated int                 `json:"total_evaluated"`
	Allowed        int                 `json:"allowed"`
	Alerted        int                 `json:"alerted"`
	Quarantined    int                 `json:"quarantined"`
	Blocked        int                 `json:"blocked"`
	AverageScore   float64             `json:"average_score"`
	MaxScore       float64             `json:"max_score"`
	Assessments    []AnomalyAssessment `json:"assessments"`
}
