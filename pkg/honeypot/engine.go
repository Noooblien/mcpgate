package honeypot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// Engine governs active canary tools, parameter canary traps, and deceptive response generation.
type Engine struct {
	mu                  sync.RWMutex
	config              HoneypotConfig
	canaryTools         map[string]CanaryTool
	canaryTokens        map[string]struct{}
	quarantinedSessions map[string]*TrapEvent
	quarantinedAgents   map[string]*TrapEvent
	recordedEvents      []*TrapEvent
}

// NewEngine creates an active honeypot & deception defense engine.
func NewEngine(cfg HoneypotConfig) *Engine {
	e := &Engine{
		config:              cfg,
		canaryTools:         make(map[string]CanaryTool),
		canaryTokens:        make(map[string]struct{}),
		quarantinedSessions: make(map[string]*TrapEvent),
		quarantinedAgents:   make(map[string]*TrapEvent),
		recordedEvents:      make([]*TrapEvent, 0),
	}

	for _, tool := range DefaultCanaryTools() {
		e.canaryTools[tool.Name] = tool
	}

	for _, tok := range cfg.CanaryTokens {
		e.canaryTokens[strings.TrimSpace(tok)] = struct{}{}
	}
	for _, tok := range DefaultCanaryTokens() {
		e.canaryTokens[tok] = struct{}{}
	}

	return e
}

// RegisterCanaryTool adds or overrides a custom decoy tool in the registry.
func (e *Engine) RegisterCanaryTool(tool CanaryTool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.canaryTools[tool.Name] = tool
}

// RegisterCanaryToken registers a tracking token substring to catch exfiltration in arguments.
func (e *Engine) RegisterCanaryToken(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if strings.TrimSpace(token) != "" {
		e.canaryTokens[strings.TrimSpace(token)] = struct{}{}
	}
}

// InjectToolsList seamlessly decorates real MCP tools/list responses with decoy canary tools.
func (e *Engine) InjectToolsList(realTools []map[string]interface{}) []map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.config.Enabled && len(e.canaryTools) == 0 {
		return realTools
	}

	// Make a defensive copy
	merged := make([]map[string]interface{}, 0, len(realTools)+len(e.canaryTools))
	merged = append(merged, realTools...)

	for _, ct := range e.canaryTools {
		toolDef := map[string]interface{}{
			"name":        ct.Name,
			"description": ct.Description,
			"inputSchema": ct.InputSchema,
		}
		merged = append(merged, toolDef)
	}

	return merged
}

// InterceptToolCall inspects an incoming MCP tool invocation for canary tool hits or token exfiltrations.
func (e *Engine) InterceptToolCall(sessionID, agentID string, role rbac.AgentRole, toolName string, args map[string]interface{}) HoneypotVerdict {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Check if session or agent is already quarantined
	if prevEvent, locked := e.quarantinedSessions[sessionID]; locked {
		return HoneypotVerdict{
			Allowed:        false,
			IsHoneypotHit:  false,
			SessionLocked:  true,
			DeceptionMode:  ModeHardQuarantine,
			Reason:         fmt.Sprintf("Session '%s' is quarantined due to prior forensic tripwire (%s on %s)", sessionID, prevEvent.TrapType, prevEvent.ToolName),
			TrapEvent:      prevEvent,
		}
	}

	if prevEvent, locked := e.quarantinedAgents[agentID]; locked {
		return HoneypotVerdict{
			Allowed:        false,
			IsHoneypotHit:  false,
			SessionLocked:  true,
			DeceptionMode:  ModeHardQuarantine,
			Reason:         fmt.Sprintf("Agent '%s' is globally quarantined due to prior breach probe (%s)", agentID, prevEvent.TrapType),
			TrapEvent:      prevEvent,
		}
	}

	now := time.Now().UTC()

	// 2. Check if the tool called is a registered Canary Tool
	if canary, isDecoy := e.canaryTools[toolName]; isDecoy {
		mode := canary.DefaultAction
		if e.config.DefaultDeceptionMode != "" {
			mode = e.config.DefaultDeceptionMode
		}

		eventID := fmt.Sprintf("trap-%d-%s", now.UnixNano(), toolName)
		fp := computeFingerprint(sessionID, agentID, toolName, args)

		event := &TrapEvent{
			EventID:        eventID,
			Timestamp:      now,
			SessionID:      sessionID,
			AgentID:        agentID,
			Role:           role,
			ToolName:       toolName,
			Arguments:      args,
			TrapType:       "TOOL_DECOY",
			Severity:       canary.Severity,
			DeceptionMode:  mode,
			ResponseSpoof:  canary.SyntheticResult,
			Quarantined:    e.config.AutoQuarantineSession,
			TriggerDetail:  fmt.Sprintf("Adversarial agent invoked decoy canary tool '%s' (%s)", toolName, canary.Category),
			FingerprintSHA: fp,
		}

		e.recordedEvents = append(e.recordedEvents, event)
		if e.config.AutoQuarantineSession {
			e.quarantinedSessions[sessionID] = event
		}

		verdict := HoneypotVerdict{
			Allowed:       false, // Never allow actual backend execution
			IsHoneypotHit: true,
			SessionLocked: e.config.AutoQuarantineSession,
			DeceptionMode: mode,
			Reason:        fmt.Sprintf("Forensic Honeypot Tripwire: decoy tool '%s' invoked by agent '%s'", toolName, agentID),
			TrapEvent:     event,
			AuditLogEntry: map[string]any{
				"event_type":  "HONEYPOT_TRAP_TRIGGERED",
				"trap_type":   "TOOL_DECOY",
				"tool":        toolName,
				"severity":    canary.Severity,
				"fingerprint": fp,
			},
		}

		switch mode {
		case ModeHoneyedPayload:
			verdict.SpoofedPayload = canary.SyntheticResult
		case ModeSyntheticError:
			verdict.SpoofedError = canary.SyntheticError
		case ModeHardQuarantine:
			verdict.SpoofedError = fmt.Sprintf("SECURITY_VIOLATION: Zero-Trust tripwire tripped on decoy tool '%s'. Session quarantined.", toolName)
		case ModeTarpit:
			if e.config.TarpitDelay > 0 {
				time.Sleep(e.config.TarpitDelay)
			}
			verdict.SpoofedError = "GATEWAY_TIMEOUT: Upstream tool service did not respond within deadline"
		}

		return verdict
	}

	// 3. Scan arguments for canary secret tokens
	if matchedToken := e.scanForCanaryTokens(args); matchedToken != "" {
		eventID := fmt.Sprintf("tokentrap-%d-%s", now.UnixNano(), toolName)
		fp := computeFingerprint(sessionID, agentID, toolName, args)

		event := &TrapEvent{
			EventID:        eventID,
			Timestamp:      now,
			SessionID:      sessionID,
			AgentID:        agentID,
			Role:           role,
			ToolName:       toolName,
			Arguments:      args,
			TrapType:       "CANARY_TOKEN",
			Severity:       SeverityHigh,
			DeceptionMode:  ModeHardQuarantine,
			Quarantined:    e.config.AutoQuarantineSession,
			TriggerDetail:  fmt.Sprintf("Canary token leak detected in arguments: '%s'", matchedToken),
			FingerprintSHA: fp,
		}

		e.recordedEvents = append(e.recordedEvents, event)
		if e.config.AutoQuarantineSession {
			e.quarantinedSessions[sessionID] = event
		}

		return HoneypotVerdict{
			Allowed:        false,
			IsHoneypotHit:  true,
			SessionLocked:  e.config.AutoQuarantineSession,
			DeceptionMode:  ModeHardQuarantine,
			SpoofedError:   fmt.Sprintf("ZERO_TRUST_BREACH: Canary security token detected in parameters for '%s'. Breach recorded.", toolName),
			Reason:         fmt.Sprintf("Canary token leak '%s' detected in tool parameters", matchedToken),
			TrapEvent:      event,
			AuditLogEntry: map[string]any{
				"event_type":  "CANARY_TOKEN_LEAK_TRIGGERED",
				"trap_type":   "CANARY_TOKEN",
				"token_found": matchedToken,
				"fingerprint": fp,
			},
		}
	}

	// 4. Benign call
	return HoneypotVerdict{
		Allowed:       true,
		IsHoneypotHit: false,
		SessionLocked: false,
		Reason:        "Clean tool call: no canary tools or tokens matched",
	}
}

// scanForCanaryTokens recursively inspects map / slice / string structures for any registered canary token.
func (e *Engine) scanForCanaryTokens(data interface{}) string {
	switch v := data.(type) {
	case string:
		for token := range e.canaryTokens {
			if strings.Contains(v, token) {
				return token
			}
		}
	case map[string]interface{}:
		for _, val := range v {
			if hit := e.scanForCanaryTokens(val); hit != "" {
				return hit
			}
		}
	case []interface{}:
		for _, item := range v {
			if hit := e.scanForCanaryTokens(item); hit != "" {
				return hit
			}
		}
	}
	return ""
}

func computeFingerprint(sessionID, agentID, toolName string, args map[string]interface{}) string {
	b, _ := json.Marshal(args)
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s", sessionID, agentID, toolName, string(b))))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// IsSessionQuarantined returns true if the session ID has been quarantined.
func (e *Engine) IsSessionQuarantined(sessionID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.quarantinedSessions[sessionID]
	return ok
}

// QuarantineSession manually places a session under quarantine with a forensic event.
func (e *Engine) QuarantineSession(sessionID string, event *TrapEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.quarantinedSessions[sessionID] = event
}

// ReleaseSession clears quarantine for a session ID.
func (e *Engine) ReleaseSession(sessionID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.quarantinedSessions, sessionID)
}

// GetRecordedEvents returns all trapped security breach events.
func (e *Engine) GetRecordedEvents() []*TrapEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*TrapEvent, len(e.recordedEvents))
	copy(out, e.recordedEvents)
	return out
}

// ClearState resets quarantined sessions and recorded events for testing.
func (e *Engine) ClearState() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.quarantinedSessions = make(map[string]*TrapEvent)
	e.quarantinedAgents = make(map[string]*TrapEvent)
	e.recordedEvents = make([]*TrapEvent, 0)
}
