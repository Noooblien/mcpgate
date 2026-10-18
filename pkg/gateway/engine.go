package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Noooblien/mcpgate/pkg/audit"
	"github.com/Noooblien/mcpgate/pkg/firewall"
	"github.com/Noooblien/mcpgate/pkg/policy"
	"github.com/Noooblien/mcpgate/pkg/ratelimit"
	"github.com/Noooblien/mcpgate/pkg/rbac"
	"github.com/Noooblien/mcpgate/pkg/redact"
	"github.com/Noooblien/mcpgate/pkg/spec"
)

// GatewayConfig holds configuration parameters for the MCP gateway.
type GatewayConfig struct {
	HMACSeed      string
	MaxRPM        int
	BurstSize     int
	AuditLogPath  string
	CanaryTokens  []string
	PolicyEngine  *policy.PolicyEngine
}

// SecurityVerdict encapsulates the outcome of an intercepted MCP tool request.
type SecurityVerdict struct {
	Allowed        bool                      `json:"allowed"`
	Verdict        spec.GateVerdict          `json:"verdict"`
	BlockReason    string                    `json:"block_reason,omitempty"`
	FirewallResult *firewall.FirewallResult  `json:"firewall_result,omitempty"`
	RedactResult   *redact.RedactResult      `json:"redact_result,omitempty"`
	RBACDecision   *rbac.RBACDecision        `json:"rbac_decision,omitempty"`
	PolicyDecision *policy.PolicyDecision    `json:"policy_decision,omitempty"`
	SanitizedArgs  map[string]interface{}    `json:"sanitized_args"`
	LatencyMs      int64                     `json:"latency_ms"`
	EventID        string                    `json:"event_id"`
}

// MCPGate is the central zero-trust security gateway.
type MCPGate struct {
	cfg          GatewayConfig
	firewall     *firewall.FirewallEngine
	redactor     *redact.Redactor
	rbac         *rbac.RBACManager
	policyEngine *policy.PolicyEngine
	limiter      *ratelimit.TokenBucketLimiter
	audit        *audit.AuditLedger
}

// NewMCPGate constructs an initialized security gateway.
func NewMCPGate(cfg GatewayConfig) (*MCPGate, error) {
	ledger, err := audit.NewAuditLedger(cfg.AuditLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init audit ledger: %w", err)
	}

	fw := firewall.NewFirewallEngine(cfg.CanaryTokens...)
	rd := redact.NewRedactor(cfg.HMACSeed)
	rb := rbac.NewRBACManager()
	lm := ratelimit.NewTokenBucketLimiter(ratelimit.RateLimiterConfig{
		MaxRPM: cfg.MaxRPM,
		Burst:  cfg.BurstSize,
	})

	return &MCPGate{
		cfg:          cfg,
		firewall:     fw,
		redactor:     rd,
		rbac:         rb,
		policyEngine: cfg.PolicyEngine,
		limiter:      lm,
		audit:        ledger,
	}, nil
}

// SetPolicyEngine overrides or hot-swaps the declarative policy engine.
func (g *MCPGate) SetPolicyEngine(pe *policy.PolicyEngine) {
	g.policyEngine = pe
}

// GetPolicyEngine returns the configured declarative policy engine.
func (g *MCPGate) GetPolicyEngine() *policy.PolicyEngine {
	return g.policyEngine
}

// GetRBAC returns the underlying RBAC manager for custom rule configuration.
func (g *MCPGate) GetRBAC() *rbac.RBACManager {
	return g.rbac
}

// RedactObject exposes recursive secret redaction for response/stream payload scrubbing.
func (g *MCPGate) RedactObject(data interface{}) (interface{}, int) {
	return g.redactor.RedactObject(data)
}


// InterceptToolCall inspects, authorizes, sanitizes, and audits an MCP tool execution.
func (g *MCPGate) InterceptToolCall(agentID string, role rbac.AgentRole, toolName string, args map[string]interface{}) SecurityVerdict {
	start := time.Now()
	eventID := fmt.Sprintf("evt_%d", time.Now().UnixNano())

	// Phase 1: Rate Limiting
	if allowed, err := g.limiter.Allow(agentID); !allowed {
		verdict := SecurityVerdict{
			Allowed:       false,
			Verdict:       spec.VerdictBlock,
			BlockReason:   fmt.Sprintf("Rate limit breached: %v", err),
			SanitizedArgs: args,
			LatencyMs:     time.Since(start).Milliseconds(),
			EventID:       eventID,
		}
		g.recordAudit(eventID, agentID, string(role), toolName, spec.VerdictBlock, verdict.BlockReason, 0, verdict.LatencyMs)
		return verdict
	}

	// Phase 2: Zero-Trust Declarative Policy & RBAC Authorization
	var rbacDec rbac.RBACDecision
	var policyDec *policy.PolicyDecision
	if g.policyEngine != nil {
		pDec := g.policyEngine.Evaluate(policy.PolicyRequest{
			AgentID:   agentID,
			Role:      role,
			ToolName:  toolName,
			Args:      args,
			Timestamp: start,
		})
		policyDec = &pDec
		if !pDec.Allowed {
			verdict := SecurityVerdict{
				Allowed:        false,
				Verdict:        spec.VerdictBlock,
				BlockReason:    fmt.Sprintf("Declarative Policy Denied: %s (Rule: %s)", pDec.Reason, pDec.MatchedRuleID),
				PolicyDecision: policyDec,
				SanitizedArgs:  args,
				LatencyMs:      time.Since(start).Milliseconds(),
				EventID:        eventID,
			}
			g.recordAudit(eventID, agentID, string(role), toolName, spec.VerdictBlock, verdict.BlockReason, 0, verdict.LatencyMs)
			return verdict
		}
		if pDec.RequireApproval {
			verdict := SecurityVerdict{
				Allowed:        false,
				Verdict:        spec.VerdictAudit,
				BlockReason:    fmt.Sprintf("Approval Required: %s (Rule: %s)", pDec.Reason, pDec.MatchedRuleID),
				PolicyDecision: policyDec,
				SanitizedArgs:  args,
				LatencyMs:      time.Since(start).Milliseconds(),
				EventID:        eventID,
			}
			g.recordAudit(eventID, agentID, string(role), toolName, spec.VerdictAudit, verdict.BlockReason, 0, verdict.LatencyMs)
			return verdict
		}
	} else {
		rbacDec = g.rbac.Authorize(role, toolName, args)
		if !rbacDec.Allowed {
			verdict := SecurityVerdict{
				Allowed:       false,
				Verdict:       spec.VerdictBlock,
				BlockReason:   fmt.Sprintf("RBAC Authorization Denied: %s (%s)", rbacDec.Reason, rbacDec.ViolationRule),
				RBACDecision:  &rbacDec,
				SanitizedArgs: args,
				LatencyMs:     time.Since(start).Milliseconds(),
				EventID:       eventID,
			}
			g.recordAudit(eventID, agentID, string(role), toolName, spec.VerdictBlock, verdict.BlockReason, 0, verdict.LatencyMs)
			return verdict
		}
	}

	// Phase 3: Prompt Injection Firewall
	sanitizedArgs := make(map[string]interface{})
	var combinedFirewall firewall.FirewallResult
	combinedFirewall.Allowed = true

	totalRedactions := 0
	var lastRedactResult redact.RedactResult

	for k, v := range args {
		valStr, isStr := v.(string)
		if isStr {
			// Scan text with firewall
			fwRes := g.firewall.ScanText(valStr)
			if !fwRes.Allowed {
				combinedFirewall = fwRes
				verdict := SecurityVerdict{
					Allowed:        false,
					Verdict:        spec.VerdictBlock,
					BlockReason:    fmt.Sprintf("Prompt injection detected in argument '%s': score=%.2f finding=%s", k, fwRes.ThreatScore, fwRes.Findings[0].PatternName),
					FirewallResult: &fwRes,
					RBACDecision:   &rbacDec,
					SanitizedArgs:  args,
					LatencyMs:      time.Since(start).Milliseconds(),
					EventID:        eventID,
				}
				g.recordAudit(eventID, agentID, string(role), toolName, spec.VerdictBlock, verdict.BlockReason, 0, verdict.LatencyMs)
				return verdict
			}

			// Phase 4: Sensitive Token & Secret Redaction
			rdRes := g.redactor.Redact(fwRes.CleanedText)
			sanitizedArgs[k] = rdRes.SanitizedText
			totalRedactions += rdRes.TotalRedacted
			if rdRes.TotalRedacted > 0 {
				lastRedactResult = rdRes
			}
		} else {
			sanitizedArgs[k] = v
		}
	}

	finalVerdict := spec.VerdictAllow
	if totalRedactions > 0 {
		finalVerdict = spec.VerdictRedacted
	}

	res := SecurityVerdict{
		Allowed:        true,
		Verdict:        finalVerdict,
		RBACDecision:   &rbacDec,
		PolicyDecision: policyDec,
		FirewallResult: &combinedFirewall,
		SanitizedArgs:  sanitizedArgs,
		LatencyMs:      time.Since(start).Milliseconds(),
		EventID:        eventID,
	}
	if totalRedactions > 0 {
		res.RedactResult = &lastRedactResult
	}

	g.recordAudit(eventID, agentID, string(role), toolName, finalVerdict, "", totalRedactions, res.LatencyMs)
	return res
}

func (g *MCPGate) recordAudit(eventID, agentID, role, toolName string, verdict spec.GateVerdict, reason string, redactions int, latency int64) {
	_ = g.audit.RecordInterception(spec.InterceptEvent{
		EventID:        eventID,
		AgentID:        agentID,
		Role:           role,
		Method:         "tools/call",
		ToolName:       toolName,
		Verdict:        verdict,
		BlockReason:    reason,
		RedactionsMade: redactions,
		LatencyMs:      latency,
		Timestamp:      time.Now().UTC(),
	})
}

// RenderGateScorecard formats an ANSI terminal scorecard for a security inspection.
func RenderGateScorecard(verdict SecurityVerdict, agentID string, toolName string) string {
	var sb strings.Builder

	sb.WriteString("\n\033[1;36m========================================================================================\033[0m\n")
	sb.WriteString("   \033[1;37mMCPGATE ZERO-TRUST MODEL CONTEXT PROTOCOL (MCP) SECURITY INSPECTION\033[0m\n")
	sb.WriteString("\033[1;36m========================================================================================\033[0m\n")

	sb.WriteString(fmt.Sprintf("  \033[1;33mEvent ID:\033[0m              %s\n", verdict.EventID))
	sb.WriteString(fmt.Sprintf("  \033[1;33mAgent ID:\033[0m              %s\n", agentID))
	sb.WriteString(fmt.Sprintf("  \033[1;33mTarget MCP Tool:\033[0m       %s\n", toolName))
	sb.WriteString(fmt.Sprintf("  \033[1;33mInspection Latency:\033[0m    %d ms\n", verdict.LatencyMs))

	switch verdict.Verdict {
	case spec.VerdictAllow:
		sb.WriteString("  \033[1;33mSecurity Verdict:\033[0m      \033[1;32m[PASS / ALLOW] ZERO THREATS DETECTED, ALL POLICIES SATISFIED\033[0m\n")
	case spec.VerdictRedacted:
		sb.WriteString("  \033[1;33mSecurity Verdict:\033[0m      \033[1;33m[REDACTED] SENSITIVE TOKENS SCRUBBED AND PSEUDONYMIZED\033[0m\n")
	case spec.VerdictBlock:
		sb.WriteString(fmt.Sprintf("  \033[1;33mSecurity Verdict:\033[0m      \033[1;31m[BLOCKED] %s\033[0m\n", verdict.BlockReason))
	}
	sb.WriteString("\033[1;34m----------------------------------------------------------------------------------------\033[0m\n")

	sb.WriteString("\033[1;37m  DEFENSE-IN-DEPTH LAYER BREAKDOWN:\033[0m\n")
	if verdict.PolicyDecision != nil {
		pStatus := "\033[1;32mAUTHORIZED\033[0m"
		if !verdict.PolicyDecision.Allowed {
			pStatus = "\033[1;31mDENIED\033[0m"
		} else if verdict.PolicyDecision.RequireApproval {
			pStatus = "\033[1;33mAPPROVAL REQUIRED\033[0m"
		}
		sb.WriteString(fmt.Sprintf("  - Layer 1 (Declarative Policy):     %s (%s: %s)\n", pStatus, verdict.PolicyDecision.Action, verdict.PolicyDecision.MatchedRuleID))
	} else if verdict.RBACDecision != nil {
		rbacStatus := "\033[1;32mAUTHORIZED\033[0m"
		if !verdict.RBACDecision.Allowed {
			rbacStatus = "\033[1;31mDENIED\033[0m"
		}
		sb.WriteString(fmt.Sprintf("  - Layer 1 (Dynamic RBAC):           %s (%s)\n", rbacStatus, verdict.RBACDecision.Role))
	}

	if verdict.FirewallResult != nil {
		fwStatus := "\033[1;32mCLEAN\033[0m"
		if !verdict.FirewallResult.Allowed {
			fwStatus = "\033[1;31mINJECTION DETECTED\033[0m"
		}
		sb.WriteString(fmt.Sprintf("  - Layer 2 (Prompt Firewall):        %s (Threat Score: %.2f)\n", fwStatus, verdict.FirewallResult.ThreatScore))
	}

	redactCount := 0
	if verdict.RedactResult != nil {
		redactCount = verdict.RedactResult.TotalRedacted
	}
	sb.WriteString(fmt.Sprintf("  - Layer 3 (Token & Secret Redactor): %d secrets masked\n", redactCount))
	sb.WriteString("  - Layer 4 (Cryptographic Audit):    SHA-256 rolling ledger hash recorded\n")

	sb.WriteString("\033[1;34m----------------------------------------------------------------------------------------\033[0m\n")
	sb.WriteString("\033[1;37m  SANITIZED PAYLOAD ARGUMENTS (PREVIEW):\033[0m\n")
	argsBytes, _ := json.MarshalIndent(verdict.SanitizedArgs, "  ", "  ")
	sb.WriteString(fmt.Sprintf("  %s\n", string(argsBytes)))

	sb.WriteString("\033[1;36m========================================================================================\033[0m\n")
	return sb.String()
}
