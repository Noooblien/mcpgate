package jit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Engine governs Just-In-Time capability delegation, ephemeral lease issuance, and execution verification.
type Engine struct {
	config          JITConfig
	leases          map[string]*EphemeralLease
	consumedIDs     map[string]bool
	forbiddenRegs   []*regexp.Regexp
	mu              sync.RWMutex
}

// NewEngine initializes the JIT capability delegation engine.
func NewEngine(cfg JITConfig) *Engine {
	if len(cfg.SigningSecret) == 0 {
		cfg = DefaultJITConfig()
	}

	regs := make([]*regexp.Regexp, 0, len(cfg.ForbiddenArgPatterns))
	for _, p := range cfg.ForbiddenArgPatterns {
		if r, err := regexp.Compile("(?i)" + p); err == nil {
			regs = append(regs, r)
		}
	}

	return &Engine{
		config:        cfg,
		leases:        make(map[string]*EphemeralLease),
		consumedIDs:   make(map[string]bool),
		forbiddenRegs: regs,
	}
}

// RequestLease evaluates an agent request and issues an ephemeral capability lease.
func (e *Engine) RequestLease(req JITRequest) (*EphemeralLease, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if req.RequestID == "" {
		req.RequestID = "req_" + GenerateRandomHex(8)
	}
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now()
	}

	// 1. Determine Risk Classification
	riskTier := e.classifyRisk(req.ToolName)

	// 2. Canonical Payload Digest Computation
	payloadDigest := ComputeCanonicalPayloadDigest(req.Args)

	// 3. Scan for strictly forbidden destructive patterns
	argsJSON, _ := json.Marshal(req.Args)
	argsStr := string(argsJSON)
	for _, reg := range e.forbiddenRegs {
		if reg.MatchString(argsStr) {
			deniedLease := &EphemeralLease{
				LeaseID:       "jit_denied_" + GenerateRandomHex(8),
				RequestID:     req.RequestID,
				AgentID:       req.AgentID,
				ToolName:      req.ToolName,
				PayloadDigest: payloadDigest,
				RiskTier:      riskTier,
				Status:        StatusDenied,
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now(),
				ApprovedBy:    "policy_forbidden_violation",
			}
			e.leases[deniedLease.LeaseID] = deniedLease
			return deniedLease, fmt.Errorf("JIT elevation denied: payload matches forbidden system attack signature (%s)", reg.String())
		}
	}

	// 4. Bound Requested TTL
	ttl := req.RequestedTTL
	if ttl <= 0 {
		ttl = e.config.DefaultTTL
	}
	if ttl > e.config.MaxTTL {
		ttl = e.config.MaxTTL
	}
	if ttl < 5*time.Millisecond {
		ttl = 5 * time.Millisecond
	}

	issuedAt := time.Now()
	expiresAt := issuedAt.Add(ttl)

	// 5. Evaluate Step-Up Gate
	status := StatusPendingApproval
	approvedBy := "pending_step_up_authorization"

	isAutoApprove := false
	for _, tier := range e.config.AutoApproveTiers {
		if tier == riskTier {
			isAutoApprove = true
			break
		}
	}

	if isAutoApprove {
		status = StatusActive
		approvedBy = "zero_trust_auto_policy"
	}

	leaseID := "jit_" + GenerateRandomHex(12)
	signature := e.computeSignature(leaseID, req.ToolName, payloadDigest, string(status), expiresAt.Unix())

	lease := &EphemeralLease{
		LeaseID:           leaseID,
		RequestID:         req.RequestID,
		AgentID:           req.AgentID,
		ToolName:          req.ToolName,
		PayloadDigest:     payloadDigest,
		ScopedConstraints: req.Args,
		RiskTier:          riskTier,
		Status:            status,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
		OneTimeUse:        true,
		ApprovedBy:        approvedBy,
		Signature:         signature,
	}

	e.leases[leaseID] = lease
	return lease, nil
}

// ApproveStepUp grants human-in-the-loop or supervisor approval for high-risk pending leases.
func (e *Engine) ApproveStepUp(leaseID string, approver string) (*EphemeralLease, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	lease, exists := e.leases[leaseID]
	if !exists {
		return nil, fmt.Errorf("lease %s not found", leaseID)
	}

	if lease.Status != StatusPendingApproval {
		return nil, fmt.Errorf("lease %s is in state %s, not PENDING_APPROVAL", leaseID, lease.Status)
	}

	if time.Now().After(lease.ExpiresAt) {
		lease.Status = StatusExpired
		return nil, fmt.Errorf("lease %s has already expired", leaseID)
	}

	lease.Status = StatusActive
	lease.ApprovedBy = approver
	// Extend expiry by default TTL from time of human approval
	lease.ExpiresAt = time.Now().Add(e.config.DefaultTTL)
	lease.Signature = e.computeSignature(lease.LeaseID, lease.ToolName, lease.PayloadDigest, string(lease.Status), lease.ExpiresAt.Unix())

	return lease, nil
}

// ValidateAndConsume checks lease validity, binds arguments, and enforces single-use destruction.
func (e *Engine) ValidateAndConsume(leaseID string, toolName string, args map[string]interface{}) *VerificationResult {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	lease, exists := e.leases[leaseID]
	if !exists {
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			Status:           StatusDenied,
			ExecutionAllowed: false,
			Reason:           "Ephemeral capability lease not found or invalid identifier",
			ViolationCode:    "ERR_LEASE_NOT_FOUND",
			Duration:         time.Since(start),
		}
	}

	// 1. Check if already consumed (Replay attack defense)
	if e.consumedIDs[leaseID] || lease.Status == StatusConsumed {
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			AgentID:          lease.AgentID,
			Status:           StatusConsumed,
			ExecutionAllowed: false,
			Reason:           "Lease replay detected: single-use capability has already been consumed",
			ViolationCode:    "ERR_LEASE_REPLAY_ATTEMPT",
			RiskTier:         lease.RiskTier,
			Lease:            lease,
			Duration:         time.Since(start),
		}
	}

	// 2. Check Expiration
	if time.Now().After(lease.ExpiresAt) || lease.Status == StatusExpired {
		lease.Status = StatusExpired
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			AgentID:          lease.AgentID,
			Status:           StatusExpired,
			ExecutionAllowed: false,
			Reason:           fmt.Sprintf("Ephemeral lease expired at %s", lease.ExpiresAt.Format(time.RFC3339)),
			ViolationCode:    "ERR_LEASE_EXPIRED",
			RiskTier:         lease.RiskTier,
			Lease:            lease,
			Duration:         time.Since(start),
		}
	}

	// 3. Cryptographic Signature Verification
	expectedSig := e.computeSignature(lease.LeaseID, lease.ToolName, lease.PayloadDigest, string(lease.Status), lease.ExpiresAt.Unix())
	if !hmac.Equal([]byte(lease.Signature), []byte(expectedSig)) {
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			AgentID:          lease.AgentID,
			Status:           StatusRevoked,
			ExecutionAllowed: false,
			Reason:           "Cryptographic lease signature tampering detected",
			ViolationCode:    "ERR_SIGNATURE_FORGED",
			RiskTier:         lease.RiskTier,
			Lease:            lease,
			Duration:         time.Since(start),
		}
	}

	// 4. Tool Name Match
	if lease.ToolName != toolName {
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			AgentID:          lease.AgentID,
			Status:           lease.Status,
			ExecutionAllowed: false,
			Reason:           fmt.Sprintf("Lease scoped to tool '%s', attempted execution on '%s'", lease.ToolName, toolName),
			ViolationCode:    "ERR_TOOL_MISMATCH",
			RiskTier:         lease.RiskTier,
			Lease:            lease,
			Duration:         time.Since(start),
		}
	}

	// 5. Parameter Substitution Tamper Detection
	currentDigest := ComputeCanonicalPayloadDigest(args)
	if lease.PayloadDigest != currentDigest {
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			AgentID:          lease.AgentID,
			Status:           lease.Status,
			ExecutionAllowed: false,
			Reason:           "Parameter substitution attack detected: runtime tool arguments do not match approved cryptographic lease digest",
			ViolationCode:    "ERR_PARAMETER_SUBSTITUTION_ATTACK",
			RiskTier:         lease.RiskTier,
			Lease:            lease,
			Duration:         time.Since(start),
		}
	}

	// 6. Check Active Status
	if lease.Status == StatusPendingApproval {
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			AgentID:          lease.AgentID,
			Status:           StatusPendingApproval,
			ExecutionAllowed: false,
			Reason:           "Step-up dual-custody authorization required before execution",
			ViolationCode:    "ERR_STEP_UP_REQUIRED",
			RiskTier:         lease.RiskTier,
			Lease:            lease,
			Duration:         time.Since(start),
		}
	}

	if lease.Status != StatusActive {
		return &VerificationResult{
			LeaseID:          leaseID,
			ToolName:         toolName,
			AgentID:          lease.AgentID,
			Status:           lease.Status,
			ExecutionAllowed: false,
			Reason:           fmt.Sprintf("Lease is in non-executable state: %s", lease.Status),
			ViolationCode:    "ERR_INACTIVE_LEASE",
			RiskTier:         lease.RiskTier,
			Lease:            lease,
			Duration:         time.Since(start),
		}
	}

	// 7. Successful Execution -> Consume and Invalidate
	now := time.Now()
	lease.Status = StatusConsumed
	lease.ConsumedAt = &now
	e.consumedIDs[leaseID] = true

	return &VerificationResult{
		LeaseID:          leaseID,
		ToolName:         toolName,
		AgentID:          lease.AgentID,
		Status:           StatusConsumed,
		ExecutionAllowed: true,
		Reason:           fmt.Sprintf("Capability verified. Authorized by %s. Ephemerally consumed.", lease.ApprovedBy),
		RiskTier:         lease.RiskTier,
		Lease:            lease,
		Duration:         time.Since(start),
	}
}

// RevokeLease immediately revokes an outstanding lease.
func (e *Engine) RevokeLease(leaseID string, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	lease, exists := e.leases[leaseID]
	if !exists {
		return fmt.Errorf("lease %s not found", leaseID)
	}

	lease.Status = StatusRevoked
	lease.ApprovedBy = fmt.Sprintf("revoked: %s", reason)
	return nil
}

// GetLease retrieves lease state without mutating it.
func (e *Engine) GetLease(leaseID string) (*EphemeralLease, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	lease, exists := e.leases[leaseID]
	return lease, exists
}

// classifyRisk looks up or infers the escalation risk tier.
func (e *Engine) classifyRisk(toolName string) EscalationRiskTier {
	if tier, found := e.config.CriticalTools[toolName]; found {
		return tier
	}

	lower := strings.ToLower(toolName)
	switch {
	case strings.Contains(lower, "drop") || strings.Contains(lower, "delete") ||
		strings.Contains(lower, "terminate") || strings.Contains(lower, "payout") ||
		strings.Contains(lower, "kill") || strings.Contains(lower, "force"):
		return RiskCritical
	case strings.Contains(lower, "write") || strings.Contains(lower, "update") ||
		strings.Contains(lower, "post") || strings.Contains(lower, "refund") ||
		strings.Contains(lower, "mutate") || strings.Contains(lower, "push"):
		return RiskHigh
	case strings.Contains(lower, "flush") || strings.Contains(lower, "restart") ||
		strings.Contains(lower, "broadcast"):
		return RiskMedium
	default:
		return RiskLow
	}
}

// computeSignature computes an HMAC-SHA256 signature for lease authenticity.
func (e *Engine) computeSignature(leaseID, toolName, payloadDigest, status string, expiryUnix int64) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%d", leaseID, toolName, payloadDigest, status, expiryUnix)
	mac := hmac.New(sha256.New, e.config.SigningSecret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// ComputeCanonicalPayloadDigest produces a deterministic SHA-256 hash of tool arguments.
func ComputeCanonicalPayloadDigest(args map[string]interface{}) string {
	if args == nil || len(args) == 0 {
		h := sha256.Sum256([]byte("{}"))
		return hex.EncodeToString(h[:])
	}

	// Sort keys deterministically
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		valBytes, _ := json.Marshal(args[k])
		sb.WriteString(fmt.Sprintf("%s:%s;", k, string(valBytes)))
	}

	h := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(h[:])
}
