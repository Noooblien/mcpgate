package risk

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// RiskGovernor manages stateful agent sessions, blast radius budgets, velocity thresholds, and decay kinetics.
type RiskGovernor struct {
	mu       sync.RWMutex
	config   RiskGovernorConfig
	scorer   *ToolScorer
	sessions map[string]*SessionRiskState
}

// NewRiskGovernor initializes a thread-safe blast radius governor.
func NewRiskGovernor(cfg RiskGovernorConfig, scorer *ToolScorer) *RiskGovernor {
	if scorer == nil {
		scorer = NewToolScorer()
	}
	if cfg.SessionRiskBudget <= 0 {
		cfg.SessionRiskBudget = 100.0
	}
	if cfg.WarningThresholdPct <= 0 || cfg.WarningThresholdPct > 100.0 {
		cfg.WarningThresholdPct = 70.0
	}
	if cfg.HalfLifeDecay <= 0 {
		cfg.HalfLifeDecay = 15 * time.Minute
	}
	if cfg.VelocityWindow <= 0 {
		cfg.VelocityWindow = 30 * time.Second
	}
	if cfg.VelocityThreshold <= 0 {
		cfg.VelocityThreshold = 50.0
	}
	if cfg.RoleBudgetMultipliers == nil {
		cfg.RoleBudgetMultipliers = DefaultRiskGovernorConfig().RoleBudgetMultipliers
	}

	return &RiskGovernor{
		config:   cfg,
		scorer:   scorer,
		sessions: make(map[string]*SessionRiskState),
	}
}

// Config returns the active governor configuration.
func (g *RiskGovernor) Config() RiskGovernorConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
}

// AssessToolCall evaluates a proposed tool execution against the session's cumulative blast radius budget and velocity.
func (g *RiskGovernor) AssessToolCall(sessionID, agentID string, role rbac.AgentRole, toolName string, args map[string]interface{}) *RiskAssessment {
	start := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	session := g.getOrCreateSessionLocked(sessionID, agentID, role)
	g.applyDecayLocked(session)

	// Compute instantaneous score
	instantScore, dimensions, factors, requiresHITL := g.scorer.EvaluateToolCall(toolName, args)

	// Calculate velocity within the sliding window
	velocityScore := g.calculateVelocityLocked(session, g.config.VelocityWindow)

	// Determine role-adjusted budget
	multiplier, ok := g.config.RoleBudgetMultipliers[role]
	if !ok {
		multiplier = 1.0
	}
	budgetLimit := g.config.SessionRiskBudget * multiplier
	warningLimit := budgetLimit * (g.config.WarningThresholdPct / 100.0)

	assessmentID := generateAssessmentID()
	projectedCumulative := session.CumulativeScore + instantScore

	var verdict RiskVerdict
	var explanation string

	// Decision Rule 1: Quarantined session
	if session.IsQuarantined {
		verdict = VerdictQuarantinedBlock
		explanation = fmt.Sprintf("Session '%s' is quarantined: %s", sessionID, session.QuarantineReason)
		session.BlockedCalls++
	} else if requiresHITL {
		// Decision Rule 2: Explicit Human-in-the-Loop requirement (e.g. destructive, high financial amount)
		verdict = VerdictStepUpApproval
		explanation = "Action requires explicit Step-Up Human-in-the-Loop confirmation due to hazardous risk factors"
	} else if len(session.History) >= 1 && (velocityScore+instantScore) >= g.config.VelocityThreshold {
		// Decision Rule 3: Blast radius velocity burst (runaway loop / rapid sequence across sliding window)
		verdict = VerdictQuarantinedBlock
		session.IsQuarantined = true
		session.QuarantineReason = fmt.Sprintf("Velocity limit exceeded (%.1f pts in %v)", velocityScore+instantScore, g.config.VelocityWindow)
		explanation = session.QuarantineReason
		session.BlockedCalls++
		factors = append(factors, "runaway_burst_velocity_anomaly")
	} else if projectedCumulative > budgetLimit {
		// Decision Rule 4: Cumulative budget exhaustion
		if projectedCumulative > budgetLimit*1.5 || role == rbac.RoleRestricted || role == rbac.RoleReadOnly {
			verdict = VerdictQuarantinedBlock
			explanation = fmt.Sprintf("Session blast radius budget depleted (%.1f / %.1f points)", projectedCumulative, budgetLimit)
			session.BlockedCalls++
		} else {
			verdict = VerdictStepUpApproval
			explanation = fmt.Sprintf("Action would exceed remaining risk budget (%.1f / %.1f pts); requires step-up confirmation", projectedCumulative, budgetLimit)
		}
	} else if projectedCumulative >= warningLimit {
		// Decision Rule 5: Approaching risk budget ceiling
		verdict = VerdictWarning
		explanation = fmt.Sprintf("Warning: Cumulative blast radius approaching budget (%.1f / %.1f pts)", projectedCumulative, budgetLimit)
	} else {
		// Decision Rule 6: Normal safe execution within budget
		verdict = VerdictAllowed
		explanation = "Tool execution evaluated within safe autonomous blast radius limits"
	}

	// Determine risk level based on instantaneous score
	riskLevel := categorizeRiskLevel(instantScore)

	budgetRemaining := math.Max(0.0, budgetLimit-session.CumulativeScore)

	return &RiskAssessment{
		AssessmentID:       assessmentID,
		Timestamp:          time.Now().UTC(),
		SessionID:          sessionID,
		AgentID:            agentID,
		Role:               role,
		ToolName:           toolName,
		InstantaneousScore: instantScore,
		RiskLevel:          riskLevel,
		Verdict:            verdict,
		CumulativeScore:    session.CumulativeScore,
		BudgetLimit:        budgetLimit,
		BudgetRemaining:    budgetRemaining,
		VelocityScore:      velocityScore,
		Dimensions:         dimensions,
		RiskFactors:        factors,
		Explanation:        explanation,
		DurationUs:         time.Since(start).Microseconds(),
	}
}

// CommitToolExecution records that a tool call was actually executed and accrues its risk score to the session.
func (g *RiskGovernor) CommitToolExecution(sessionID, toolName string, score float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	session := g.getOrCreateSessionLocked(sessionID, "agent-default", rbac.RoleStandard)

	g.applyDecayLocked(session)
	session.CumulativeScore += score
	session.TotalCalls++
	session.History = append(session.History, RiskScorePoint{
		Timestamp: time.Now().UTC(),
		ToolName:  toolName,
		Score:     score,
	})

	// Prune history older than 1 hour to prevent unbounded growth
	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	startIdx := 0
	for i, pt := range session.History {
		if pt.Timestamp.After(cutoff) {
			startIdx = i
			break
		}
	}
	if startIdx > 0 {
		session.History = session.History[startIdx:]
	}
}

// ApproveStepUp unlocks an escalated session or resets a pending requirement.
func (g *RiskGovernor) ApproveStepUp(sessionID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	session, ok := g.sessions[sessionID]
	if !ok {
		return false
	}

	// Lift quarantine if active
	session.IsQuarantined = false
	session.QuarantineReason = ""
	return true
}

// ResetSession clears all accumulated risk and resets the session to baseline.
func (g *RiskGovernor) ResetSession(sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.sessions, sessionID)
}

// GetSessionState retrieves a copy of the current session state.
func (g *RiskGovernor) GetSessionState(sessionID string) (*SessionRiskState, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	session, ok := g.sessions[sessionID]
	if !ok {
		return nil, false
	}
	g.applyDecayLocked(session)

	copied := *session
	copied.History = make([]RiskScorePoint, len(session.History))
	copy(copied.History, session.History)
	return &copied, true
}

func (g *RiskGovernor) getOrCreateSessionLocked(sessionID, agentID string, role rbac.AgentRole) *SessionRiskState {
	session, ok := g.sessions[sessionID]
	if !ok {
		session = &SessionRiskState{
			SessionID:       sessionID,
			AgentID:         agentID,
			Role:            role,
			CumulativeScore: 0.0,
			LastDecayTime:   time.Now().UTC(),
			TotalCalls:      0,
			BlockedCalls:    0,
			IsQuarantined:   false,
			History:         make([]RiskScorePoint, 0),
		}
		g.sessions[sessionID] = session
	}
	return session
}

// applyDecayLocked applies half-life exponential decay to accumulated session risk.
func (g *RiskGovernor) applyDecayLocked(session *SessionRiskState) {
	now := time.Now().UTC()
	elapsed := now.Sub(session.LastDecayTime)
	if elapsed <= 0 || session.CumulativeScore <= 0 {
		session.LastDecayTime = now
		return
	}

	// Half-life decay: score = score * 2^(-elapsed / halfLife)
	halfLifeFloat := float64(g.config.HalfLifeDecay)
	decayRatio := math.Pow(2.0, -float64(elapsed)/halfLifeFloat)

	session.CumulativeScore = math.Max(0.0, session.CumulativeScore*decayRatio)
	session.LastDecayTime = now
}

// calculateVelocityLocked computes the sum of risk scores accrued within the sliding window.
func (g *RiskGovernor) calculateVelocityLocked(session *SessionRiskState, window time.Duration) float64 {
	cutoff := time.Now().UTC().Add(-window)
	var sum float64
	for i := len(session.History) - 1; i >= 0; i-- {
		pt := session.History[i]
		if pt.Timestamp.Before(cutoff) {
			break
		}
		sum += pt.Score
	}
	return sum
}

func categorizeRiskLevel(score float64) RiskLevel {
	switch {
	case score >= 86.0:
		return RiskLevelCritical
	case score >= 66.0:
		return RiskLevelHigh
	case score >= 36.0:
		return RiskLevelMedium
	case score >= 16.0:
		return RiskLevelLow
	default:
		return RiskLevelNone
	}
}

func generateAssessmentID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "risk_" + hex.EncodeToString(b[:])
}
