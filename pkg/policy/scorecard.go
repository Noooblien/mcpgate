package policy

import (
	"fmt"
	"strings"
)

// ANSI color codes for terminal rendering.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[1;31m"
	colorGreen  = "\033[1;32m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[1;36m"
	colorGray   = "\033[0;90m"
	colorBold   = "\033[1m"
)

// RenderPolicyScorecard formats a policy evaluation decision as a rich terminal scorecard.
func RenderPolicyScorecard(decision PolicyDecision, req PolicyRequest) string {
	var sb strings.Builder

	statusBadge := fmt.Sprintf("%s[ALLOWED]%s", colorGreen, colorReset)
	if !decision.Allowed {
		statusBadge = fmt.Sprintf("%s[BLOCKED / DENIED]%s", colorRed, colorReset)
	} else if decision.RequireApproval {
		statusBadge = fmt.Sprintf("%s[REQUIRE APPROVAL]%s", colorYellow, colorReset)
	}

	actionColor := colorGreen
	if decision.Action == ActionDeny {
		actionColor = colorRed
	} else if decision.Action == ActionRequireApproval {
		actionColor = colorYellow
	}

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s╭────────────────────────────────────────────────────────────────────────────╮%s\n", colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s  🛡️  %sMCPGate Declarative Security Policy Evaluation%s                       %s│%s\n", colorCyan, colorReset, colorBold, colorReset, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────────┤%s\n", colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("│  %sAgent ID:%s       %-30s  %sRole:%s     %-16s │\n", colorBold, colorReset, req.AgentID, colorBold, colorReset, req.Role))
	sb.WriteString(fmt.Sprintf("│  %sTarget Tool:%s    %-30s  %sDecision:%s %-25s │\n", colorBold, colorReset, req.ToolName, colorBold, colorReset, statusBadge))
	sb.WriteString(fmt.Sprintf("│  %sAction:%s         %s%-28s%s  %sApproval:%s %-16v │\n", colorBold, colorReset, actionColor, decision.Action, colorReset, colorBold, colorReset, decision.RequireApproval))
	if decision.MatchedRuleID != "" {
		sb.WriteString(fmt.Sprintf("│  %sMatched Rule:%s   %-56s │\n", colorBold, colorReset, fmt.Sprintf("%s (%s)", decision.MatchedRuleName, decision.MatchedRuleID)))
	}
	sb.WriteString(fmt.Sprintf("│  %sReason:%s         %-56s │\n", colorBold, colorReset, truncate(decision.Reason, 56)))
	if decision.EffectiveRPM > 0 {
		sb.WriteString(fmt.Sprintf("│  %sCustom RPM:%s     %-56d │\n", colorBold, colorReset, decision.EffectiveRPM))
	}
	if len(decision.Violations) > 0 {
		sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────────┤%s\n", colorCyan, colorReset))
		sb.WriteString(fmt.Sprintf("│  %sPolicy Rule Violations Detected:%s                                       │\n", colorRed, colorReset))
		for _, v := range decision.Violations {
			sb.WriteString(fmt.Sprintf("│  %s• %-68s%s │\n", colorRed, truncate(v, 68), colorReset))
		}
	}
	sb.WriteString(fmt.Sprintf("%s╰────────────────────────────────────────────────────────────────────────────╯%s\n", colorCyan, colorReset))

	return sb.String()
}

// RenderPolicyMermaid generates a Mermaid flowchart documenting the policy ruleset hierarchy.
func RenderPolicyMermaid(manifest *PolicyManifest) string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart TD\n")
	sb.WriteString("    %% MCPGate Declarative Policy Hierarchy\n")
	sb.WriteString("    REQ[\"Incoming MCP Tool Request<br/>(Agent, Role, Tool, Args)\"]\n")
	sb.WriteString("    REQ --> GATE{\"Policy Engine\"}\n\n")

	for i, r := range manifest.Rules {
		nodeID := fmt.Sprintf("R%d", i)
		ruleLabel := fmt.Sprintf("\"Priority %d: %s<br/>Tool: %s\"", r.Priority, escapeMermaid(r.Name), escapeMermaid(r.ToolPattern))
		sb.WriteString(fmt.Sprintf("    GATE -->|Match| %s[%s]\n", nodeID, ruleLabel))

		actNodeID := fmt.Sprintf("ACT%d", i)
		switch r.Action {
		case ActionAllow:
			sb.WriteString(fmt.Sprintf("    %s -->|Authorized| %s[\"ALLOW<br/>Tool Execution Granted\"]\n", nodeID, actNodeID))
			sb.WriteString(fmt.Sprintf("    style %s fill:#d4edda,stroke:#28a745,color:#155724\n", actNodeID))
		case ActionDeny:
			sb.WriteString(fmt.Sprintf("    %s -->|Violation / Block| %s[\"DENY<br/>Execution Blocked\"]\n", nodeID, actNodeID))
			sb.WriteString(fmt.Sprintf("    style %s fill:#f8d7da,stroke:#dc3545,color:#721c24\n", actNodeID))
		case ActionRequireApproval:
			sb.WriteString(fmt.Sprintf("    %s -->|Hold for Review| %s[\"REQUIRE_APPROVAL<br/>Human-in-the-Loop 2FA\"]\n", nodeID, actNodeID))
			sb.WriteString(fmt.Sprintf("    style %s fill:#fff3cd,stroke:#ffc107,color:#856404\n", actNodeID))
		case ActionForceRedaction:
			sb.WriteString(fmt.Sprintf("    %s -->|Mask PII/Secrets| %s[\"FORCE_REDACTION<br/>Scrub and Allow\"]\n", nodeID, actNodeID))
			sb.WriteString(fmt.Sprintf("    style %s fill:#cce5ff,stroke:#007bff,color:#004085\n", actNodeID))
		}
	}

	defNode := "DEF[\"DEFAULT ACTION: " + string(manifest.DefaultAction) + "<br/>(Zero-Trust Boundary)\"]\n"
	sb.WriteString("    GATE -->|No Match| " + defNode)
	if manifest.DefaultAction == ActionDeny {
		sb.WriteString("    style DEF fill:#f8d7da,stroke:#dc3545,color:#721c24\n")
	} else {
		sb.WriteString("    style DEF fill:#d4edda,stroke:#28a745,color:#155724\n")
	}

	sb.WriteString("```\n")
	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func escapeMermaid(s string) string {
	s = strings.ReplaceAll(s, "\"", "'")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
