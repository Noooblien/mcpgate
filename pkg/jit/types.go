package jit

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// LeaseStatus defines the lifecycle state of an ephemeral JIT capability lease.
type LeaseStatus string

const (
	StatusPendingApproval LeaseStatus = "PENDING_APPROVAL" // Awaiting dual-custody / supervisor sign-off
	StatusActive          LeaseStatus = "ACTIVE"           // Valid, signed, and ready for execution
	StatusConsumed        LeaseStatus = "CONSUMED"         // Single-use execution completed successfully
	StatusRevoked         LeaseStatus = "REVOKED"          // Administratively or defensively revoked
	StatusExpired         LeaseStatus = "EXPIRED"          // TTL deadline passed without execution
	StatusDenied          LeaseStatus = "DENIED"           // Privilege escalation rejected by policy
)

// EscalationRiskTier categorizes the blast radius of the requested tool invocation.
type EscalationRiskTier string

const (
	RiskLow      EscalationRiskTier = "LOW"      // Read-only or bounded diagnostics (Auto-grantable with short TTL)
	RiskMedium   EscalationRiskTier = "MEDIUM"   // Reversible changes, cache modifications (Auto-grantable with telemetry)
	RiskHigh     EscalationRiskTier = "HIGH"     // Data mutation, write access, external messaging (Requires verification)
	RiskCritical EscalationRiskTier = "CRITICAL" // Schema alterations, credential changes, payments, deletions (Requires step-up)
)

// JITRequest represents an agent's runtime request for elevated capability lease.
type JITRequest struct {
	RequestID     string                 `json:"request_id"`
	AgentID       string                 `json:"agent_id"`
	ToolName      string                 `json:"tool_name"`
	Args          map[string]interface{} `json:"args"`
	PayloadDigest string                 `json:"payload_digest"`
	Justification string                 `json:"justification"`
	RequestedTTL  time.Duration          `json:"requested_ttl"`
	ClientIP      string                 `json:"client_ip,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// EphemeralLease represents a cryptographically signed, time-bound capability lease.
type EphemeralLease struct {
	LeaseID           string                 `json:"lease_id"`
	RequestID         string                 `json:"request_id"`
	AgentID           string                 `json:"agent_id"`
	ToolName          string                 `json:"tool_name"`
	PayloadDigest     string                 `json:"payload_digest"`
	ScopedConstraints map[string]interface{} `json:"scoped_constraints,omitempty"`
	RiskTier          EscalationRiskTier     `json:"risk_tier"`
	Status            LeaseStatus            `json:"status"`
	IssuedAt          time.Time              `json:"issued_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	OneTimeUse        bool                   `json:"one_time_use"`
	ConsumedAt        *time.Time             `json:"consumed_at,omitempty"`
	ApprovedBy        string                 `json:"approved_by"`
	Signature         string                 `json:"signature"` // HMAC-SHA256 signature
}

// VerificationResult captures the outcome of validating a lease prior to tool execution.
type VerificationResult struct {
	LeaseID          string          `json:"lease_id"`
	ToolName         string          `json:"tool_name"`
	AgentID          string          `json:"agent_id"`
	Status           LeaseStatus     `json:"status"`
	ExecutionAllowed bool            `json:"execution_allowed"`
	Reason           string          `json:"reason"`
	ViolationCode    string          `json:"violation_code,omitempty"`
	RiskTier         EscalationRiskTier `json:"risk_tier"`
	Lease            *EphemeralLease `json:"lease,omitempty"`
	Duration         time.Duration   `json:"duration"`
}

// JITSummary aggregates telemetry across multiple JIT delegation events.
type JITSummary struct {
	TotalRequests   int                   `json:"total_requests"`
	ActiveLeases    int                   `json:"active_leases"`
	ConsumedLeases  int                   `json:"consumed_leases"`
	ExpiredLeases   int                   `json:"expired_leases"`
	DeniedRequests  int                   `json:"denied_requests"`
	StepUpRequired  int                   `json:"step_up_required"`
	Evaluations     []*VerificationResult `json:"evaluations"`
	Duration        time.Duration         `json:"duration"`
}

// JITConfig defines parameters and policies for Just-In-Time capability delegation.
type JITConfig struct {
	SigningSecret        []byte                        `json:"-"`
	DefaultTTL           time.Duration                 `json:"default_ttl"`
	MaxTTL               time.Duration                 `json:"max_ttl"`
	AutoApproveTiers     []EscalationRiskTier          `json:"auto_approve_tiers"`
	CriticalTools        map[string]EscalationRiskTier `json:"critical_tools"`
	ForbiddenArgPatterns []string                      `json:"forbidden_arg_patterns"`
}

// DefaultJITConfig returns production-grade zero-trust defaults.
func DefaultJITConfig() JITConfig {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	return JITConfig{
		SigningSecret: secret,
		DefaultTTL:    60 * time.Second,
		MaxTTL:        300 * time.Second,
		AutoApproveTiers: []EscalationRiskTier{
			RiskLow,
			RiskMedium,
		},
		CriticalTools: map[string]EscalationRiskTier{
			"database.drop_table":        RiskCritical,
			"database.truncate_table":    RiskCritical,
			"aws.terminate_instance":     RiskCritical,
			"stripe.create_refund":       RiskHigh,
			"stripe.payout":              RiskCritical,
			"github.force_push":          RiskCritical,
			"github.merge_pr":            RiskHigh,
			"slack.broadcast_channel":    RiskMedium,
			"cache.flush_all":            RiskMedium,
			"diagnostics.query_metrics":  RiskLow,
		},
		ForbiddenArgPatterns: []string{
			`rm\s+(-rf|-fr|--recursive)`,
			`169\.254\.169\.254`,
			`/etc/(shadow|passwd)`,
		},
	}
}

// GenerateRandomHex creates a cryptographically secure random hex string.
func GenerateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
