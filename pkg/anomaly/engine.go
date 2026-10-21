package anomaly

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

// Detector is the core engine for behavioral tool anomaly detection and Markov sequence deviation analysis.
type Detector struct {
	mu            sync.RWMutex
	policy        AnomalyPolicy
	baselines     map[string]*AgentBehavioralBaseline
	sessionState  map[string]string            // sessionID -> lastToolName
	quarantined   map[string]time.Time         // agentID -> quarantine expiration
}

// NewDetector initializes an instance of Detector with the provided policy.
func NewDetector(policy AnomalyPolicy) *Detector {
	return &Detector{
		policy:       policy,
		baselines:    make(map[string]*AgentBehavioralBaseline),
		sessionState: make(map[string]string),
		quarantined:  make(map[string]time.Time),
	}
}

// RegisterBaseline registers or overrides the behavioral baseline for a given agent.
func (d *Detector) RegisterBaseline(agentID string, baseline *AgentBehavioralBaseline) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.baselines[agentID] = baseline
}

// GetBaseline retrieves the baseline for a specific agent.
func (d *Detector) GetBaseline(agentID string) (*AgentBehavioralBaseline, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	b, ok := d.baselines[agentID]
	return b, ok
}

// IsAgentQuarantined checks if an agent is currently quarantined.
func (d *Detector) IsAgentQuarantined(agentID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	exp, exists := d.quarantined[agentID]
	if !exists {
		return false
	}
	if time.Now().Before(exp) {
		return true
	}
	return false
}

// ReleaseQuarantine removes quarantine on an agent.
func (d *Detector) ReleaseQuarantine(agentID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.quarantined, agentID)
}

// RecordObservation incorporates a clean, verified tool call into the agent's baseline model.
func (d *Detector) RecordObservation(obs ToolCallObservation) {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, exists := d.baselines[obs.AgentID]
	if !exists {
		b = &AgentBehavioralBaseline{
			AgentID:           obs.AgentID,
			ToolProfiles:      make(map[string]*ToolProfile),
			MarkovTransitions: make(map[TransitionKey]int),
			SourceToolCounts:  make(map[string]int),
			LastUpdated:       time.Now(),
		}
		d.baselines[obs.AgentID] = b
	}

	b.TotalCalls++
	b.LastUpdated = time.Now()

	// Prior tool resolution
	priorTool := obs.PriorTool
	if priorTool == "" && obs.SessionID != "" {
		priorTool = d.sessionState[obs.SessionID]
	}

	if priorTool != "" {
		key := FormatTransitionKey(priorTool, obs.ToolName)
		b.MarkovTransitions[key]++
		b.SourceToolCounts[priorTool]++
	}

	if obs.SessionID != "" {
		d.sessionState[obs.SessionID] = obs.ToolName
	}

	// Tool Profile update
	tp, ok := b.ToolProfiles[obs.ToolName]
	if !ok {
		tp = &ToolProfile{
			ToolName:    obs.ToolName,
			AllowedKeys: make(map[string]bool),
		}
		b.ToolProfiles[obs.ToolName] = tp
	}
	tp.TotalInvocations++

	// Record argument keys
	for k := range obs.Arguments {
		tp.AllowedKeys[k] = true
	}

	// Payload serialization and metrics
	payloadBytes, _ := json.Marshal(obs.Arguments)
	length := len(payloadBytes)
	entropy := CalculateShannonEntropy(payloadBytes)
	tp.PayloadStats.Update(length, entropy)
}

// Evaluate performs multi-dimensional anomaly detection on an incoming tool invocation.
func (d *Detector) Evaluate(obs ToolCallObservation) *AnomalyAssessment {
	startTime := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	assessment := &AnomalyAssessment{
		ObservationID:   obs.ObservationID,
		Timestamp:       obs.Timestamp,
		SessionID:       obs.SessionID,
		AgentID:         obs.AgentID,
		ToolName:        obs.ToolName,
		PriorTool:       obs.PriorTool,
		ContributingFactors: make([]string, 0),
	}
	if assessment.Timestamp.IsZero() {
		assessment.Timestamp = time.Now()
	}
	if assessment.ObservationID == "" {
		assessment.ObservationID = fmt.Sprintf("eval-%d", time.Now().UnixNano())
	}

	// Check existing active quarantine
	if exp, exists := d.quarantined[obs.AgentID]; exists && time.Now().Before(exp) {
		assessment.Verdict = VerdictQuarantine
		assessment.Severity = SeverityCritical
		assessment.CompositeScore = 1.0
		assessment.ContributingFactors = append(assessment.ContributingFactors, "agent_currently_quarantined")
		assessment.MitigationAdvice = fmt.Sprintf("Agent is quarantined until %s. Await security review or reset quarantine.", exp.Format(time.RFC3339))
		assessment.LatencyDuration = time.Since(startTime)
		return assessment
	}

	// Resolve prior tool from session state if omitted
	if assessment.PriorTool == "" && obs.SessionID != "" {
		assessment.PriorTool = d.sessionState[obs.SessionID]
	}

	baseline, exists := d.baselines[obs.AgentID]
	if !exists || baseline.TotalCalls < d.policy.MinObservations {
		// Insufficient baseline: evaluate heuristically without blocking normal tools
		assessment.SequenceAnomalyScore = 0.10
		assessment.PayloadAnomalyScore = 0.10
		assessment.EntropyAnomalyScore = 0.10
		assessment.ParameterAnomalyScore = 0.10
		assessment.CompositeScore = 0.10
		assessment.Verdict = VerdictAllow
		assessment.Severity = SeverityLow
		assessment.ContributingFactors = append(assessment.ContributingFactors, "insufficient_baseline_warmup")
		assessment.MitigationAdvice = "Observation recorded to build behavioral baseline profile."
		assessment.LatencyDuration = time.Since(startTime)

		if obs.SessionID != "" {
			d.sessionState[obs.SessionID] = obs.ToolName
		}
		return assessment
	}

	// 1. Markov Sequence Transition Anomaly Analysis
	seqAnomaly, seqFactors := d.evaluateSequenceTransition(baseline, assessment.PriorTool, obs.ToolName)
	assessment.SequenceAnomalyScore = seqAnomaly
	assessment.ContributingFactors = append(assessment.ContributingFactors, seqFactors...)

	// 2. Payload Distribution & Entropy Analysis
	payloadBytes, _ := json.Marshal(obs.Arguments)
	payloadLen := len(payloadBytes)
	entropy := CalculateShannonEntropy(payloadBytes)

	payloadAnomaly, entropyAnomaly, paramAnomaly, dataFactors := d.evaluatePayloadAndParameters(baseline, obs.ToolName, payloadLen, entropy, obs.Arguments)
	assessment.PayloadAnomalyScore = payloadAnomaly
	assessment.EntropyAnomalyScore = entropyAnomaly
	assessment.ParameterAnomalyScore = paramAnomaly
	assessment.ContributingFactors = append(assessment.ContributingFactors, dataFactors...)

	// 3. Composite Anomaly Score Computation
	wTotal := d.policy.WeightSequence + d.policy.WeightPayload + d.policy.WeightEntropy + d.policy.WeightParameters
	if wTotal <= 0 {
		wTotal = 1.0
	}
	composite := (d.policy.WeightSequence*seqAnomaly +
		d.policy.WeightPayload*payloadAnomaly +
		d.policy.WeightEntropy*entropyAnomaly +
		d.policy.WeightParameters*paramAnomaly) / wTotal

	// Extreme single-dimension breach guard (e.g. rogue sequence jumps, payload explosions, parameter tampering)
	maxSingleDim := math.Max(seqAnomaly, math.Max(payloadAnomaly, math.Max(entropyAnomaly, paramAnomaly)))
	if maxSingleDim >= 0.90 {
		composite = math.Max(composite, maxSingleDim*0.92)
	} else if maxSingleDim >= 0.75 {
		composite = math.Max(composite, maxSingleDim*0.85)
	}

	if composite > 1.0 {
		composite = 1.0
	}
	assessment.CompositeScore = math.Round(composite*1000) / 1000

	// 4. Decision Gate Enforcement
	if assessment.CompositeScore >= d.policy.BlockThreshold {
		assessment.Verdict = VerdictBlock
		assessment.Severity = SeverityCritical
		assessment.MitigationAdvice = "Tool call rejected due to critical behavioral deviation and zero-trust policy breach."
	} else if assessment.CompositeScore >= d.policy.QuarantineThreshold {
		assessment.Verdict = VerdictQuarantine
		assessment.Severity = SeverityHigh
		// Enforce 15-minute operational quarantine
		d.quarantined[obs.AgentID] = time.Now().Add(15 * time.Minute)
		assessment.MitigationAdvice = "Agent isolated under 15-minute quarantine. Immediate SOC investigation recommended."
	} else if assessment.CompositeScore >= d.policy.AlertThreshold {
		assessment.Verdict = VerdictAlert
		assessment.Severity = SeverityMedium
		assessment.MitigationAdvice = "Call permitted under enhanced audit logging. Anomaly flagged in security ledger."
	} else {
		assessment.Verdict = VerdictAllow
		assessment.Severity = SeverityLow
		assessment.MitigationAdvice = "Normal tool execution approved within baseline statistical tolerance."
	}

	// Update session tracking if call is allowed or alerted
	if assessment.Verdict == VerdictAllow || assessment.Verdict == VerdictAlert {
		if obs.SessionID != "" {
			d.sessionState[obs.SessionID] = obs.ToolName
		}
	}

	assessment.LatencyDuration = time.Since(startTime)
	return assessment
}

// evaluateSequenceTransition calculates transition probability and sequence jump deviation.
func (d *Detector) evaluateSequenceTransition(b *AgentBehavioralBaseline, fromTool, toTool string) (float64, []string) {
	var factors []string
	if fromTool == "" {
		// First tool in session. Check if target tool is a common entry tool.
		if tp, ok := b.ToolProfiles[toTool]; ok && tp.TotalInvocations > 0 {
			return 0.05, nil
		}
		// Unprecedented starting tool
		factors = append(factors, fmt.Sprintf("unprecedented_session_entry_tool:%s", toTool))
		return 0.65, factors
	}

	sourceCount := b.SourceToolCounts[fromTool]
	if sourceCount == 0 {
		factors = append(factors, fmt.Sprintf("unprecedented_source_tool:%s", fromTool))
		return 0.75, factors
	}

	transKey := FormatTransitionKey(fromTool, toTool)
	transCount := b.MarkovTransitions[transKey]

	// Number of unique tools observed
	k := float64(len(b.ToolProfiles))
	if k < 2 {
		k = 2.0
	}

	// Laplace-smoothed probability: P(to | from) = (count + alpha) / (sourceCount + alpha * k)
	alpha := d.policy.LaplaceSmoothingAlpha
	prob := (float64(transCount) + alpha) / (float64(sourceCount) + alpha*k)

	if transCount == 0 {
		// Zero-probability unprecedented transition jump
		factors = append(factors, fmt.Sprintf("unprecedented_sequence_jump:%s->%s", fromTool, toTool))
		return 0.95, factors
	}

	// Anomaly score is inversely proportional to transition probability
	score := 1.0 - math.Min(1.0, prob*2.5)
	if score < 0.02 {
		score = 0.02
	}
	return score, factors
}

// evaluatePayloadAndParameters evaluates argument length, entropy, and parameter key legitimacy.
func (d *Detector) evaluatePayloadAndParameters(b *AgentBehavioralBaseline, toolName string, length int, entropy float64, args map[string]interface{}) (float64, float64, float64, []string) {
	var factors []string
	tp, ok := b.ToolProfiles[toolName]
	if !ok || tp.PayloadStats.Count < 2 {
		// Novel tool or unprofiled payload
		factors = append(factors, fmt.Sprintf("unprofiled_tool_payload:%s", toolName))
		return 0.30, 0.20, 0.25, factors
	}

	// 1. Payload Length Z-Score
	meanLen := tp.PayloadStats.MeanLength
	varLen := tp.PayloadStats.VarianceLength()
	stdLen := math.Sqrt(varLen)
	if stdLen < 1.0 {
		stdLen = 1.0 // Minimum dispersion floor
	}

	diffLen := float64(length) - meanLen
	zLen := 0.0
	if diffLen > 0 {
		zLen = diffLen / stdLen
	}
	payloadAnomaly := math.Min(1.0, zLen/d.policy.MaxZScore)
	if zLen > d.policy.MaxZScore {
		factors = append(factors, fmt.Sprintf("payload_length_z_score_exceeded:%.2f", zLen))
	}

	// 2. Entropy Analysis
	meanEntropy := tp.PayloadStats.MeanEntropy
	varEntropy := tp.PayloadStats.VarianceEntropy()
	stdEntropy := math.Sqrt(varEntropy)
	if stdEntropy < 0.1 {
		stdEntropy = 0.1
	}

	diffEntropy := entropy - meanEntropy
	zEntropy := 0.0
	if diffEntropy > 0 {
		zEntropy = diffEntropy / stdEntropy
	}
	entropyAnomaly := math.Min(1.0, zEntropy/d.policy.MaxZScore)

	// Direct high entropy flag (compressed / encrypted / obfuscated payloads > 5.5 bits)
	if entropy >= 5.5 {
		entropyAnomaly = math.Max(entropyAnomaly, 0.85)
		factors = append(factors, fmt.Sprintf("extreme_entropy_payload:%.2f_bits", entropy))
	} else if zEntropy > d.policy.MaxZScore {
		factors = append(factors, fmt.Sprintf("entropy_z_score_exceeded:%.2f", zEntropy))
	}

	// 3. Parameter Schema Drift
	unknownKeys := 0
	totalKeys := len(args)
	for k := range args {
		if !tp.AllowedKeys[k] {
			unknownKeys++
			factors = append(factors, fmt.Sprintf("novel_parameter_key:%s", k))
		}
	}

	paramAnomaly := 0.0
	if totalKeys > 0 && unknownKeys > 0 {
		paramAnomaly = float64(unknownKeys) / float64(totalKeys)
		if paramAnomaly > 0.5 {
			paramAnomaly = 0.90
		}
	}

	return payloadAnomaly, entropyAnomaly, paramAnomaly, factors
}

// Update incorporates a new sample into PayloadDistribution using Welford's algorithm.
func (d *PayloadDistribution) Update(length int, entropy float64) {
	d.Count++
	if d.Count == 1 {
		d.MinLength = length
		d.MaxLength = length
		d.MeanLength = float64(length)
		d.M2Length = 0
		d.MinEntropy = entropy
		d.MaxEntropy = entropy
		d.MeanEntropy = entropy
		d.M2Entropy = 0
		return
	}

	if length < d.MinLength {
		d.MinLength = length
	}
	if length > d.MaxLength {
		d.MaxLength = length
	}
	deltaL := float64(length) - d.MeanLength
	d.MeanLength += deltaL / float64(d.Count)
	deltaL2 := float64(length) - d.MeanLength
	d.M2Length += deltaL * deltaL2

	if entropy < d.MinEntropy {
		d.MinEntropy = entropy
	}
	if entropy > d.MaxEntropy {
		d.MaxEntropy = entropy
	}
	deltaE := entropy - d.MeanEntropy
	d.MeanEntropy += deltaE / float64(d.Count)
	deltaE2 := entropy - d.MeanEntropy
	d.M2Entropy += deltaE * deltaE2
}

// VarianceLength returns sample variance for argument length.
func (d *PayloadDistribution) VarianceLength() float64 {
	if d.Count < 2 {
		return 0
	}
	return d.M2Length / float64(d.Count-1)
}

// VarianceEntropy returns sample variance for argument Shannon entropy.
func (d *PayloadDistribution) VarianceEntropy() float64 {
	if d.Count < 2 {
		return 0
	}
	return d.M2Entropy / float64(d.Count-1)
}

// CalculateShannonEntropy calculates Shannon entropy in bits for arbitrary bytes.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	total := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
