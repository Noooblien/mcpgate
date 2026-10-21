package jit

import (
	"fmt"
	"strings"
)

// ANSI terminal color constants.
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
)

// RenderJITScorecard formats an ANSI terminal table summarizing JIT capability delegations.
func RenderJITScorecard(summary *JITSummary) string {
	var sb strings.Builder

	sb.WriteString("\n" + colorBold + colorBlue + "========================================================================================================\n" + colorReset)
	sb.WriteString(colorBold + colorWhite + "  MCPGATE // JUST-IN-TIME (JIT) EPHEMERAL CAPABILITY DELEGATION & LEASE GOVERNOR\n" + colorReset)
	sb.WriteString(colorBold + colorBlue + "========================================================================================================\n" + colorReset)

	sb.WriteString(fmt.Sprintf("  %sTotal Invocations:%s %d  |  %sConsumed:%s %d  |  %sStep-Up Blocked:%s %d  |  %sDenied/Tampered:%s %d  |  %sLatency:%s %s\n",
		colorBold, colorReset, summary.TotalRequests,
		colorGreen, colorReset, summary.ConsumedLeases,
		colorYellow, colorReset, summary.StepUpRequired,
		colorRed, colorReset, summary.DeniedRequests,
		colorGray, colorReset, summary.Duration))
	sb.WriteString(colorGray + "--------------------------------------------------------------------------------------------------------\n" + colorReset)

	sb.WriteString(fmt.Sprintf("%-18s %-24s %-16s %-10s %-14s %s\n",
		"LEASE ID", "TOOL NAME", "AGENT ID", "RISK", "STATUS", "DECISION"))
	sb.WriteString(colorGray + "--------------------------------------------------------------------------------------------------------\n" + colorReset)

	for _, ev := range summary.Evaluations {
		statusColor := colorGreen
		statusIcon := "✓"
		decisionStr := "ALLOWED"

		if !ev.ExecutionAllowed {
			decisionStr = "BLOCKED"
			switch ev.Status {
			case StatusPendingApproval:
				statusColor = colorYellow
				statusIcon = "⏳"
			case StatusDenied:
				statusColor = colorRed
				statusIcon = "✗"
			case StatusExpired:
				statusColor = colorGray
				statusIcon = "⌛"
			case StatusConsumed:
				statusColor = colorRed
				statusIcon = "♻️"
			default:
				statusColor = colorRed
				statusIcon = "✗"
			}
		}

		riskColor := colorGreen
		switch ev.RiskTier {
		case RiskCritical:
			riskColor = colorRed
		case RiskHigh:
			riskColor = colorYellow
		case RiskMedium:
			riskColor = colorCyan
		case RiskLow:
			riskColor = colorGreen
		}

		sb.WriteString(fmt.Sprintf("%-18s %-24s %-16s %s%-10s%s %s%s %-12s%s %s%-8s%s\n",
			truncate(ev.LeaseID, 17),
			truncate(ev.ToolName, 23),
			truncate(ev.AgentID, 15),
			colorBold+riskColor, ev.RiskTier, colorReset,
			statusColor, statusIcon, ev.Status, colorReset,
			colorBold+func() string {
				if ev.ExecutionAllowed {
					return colorGreen
				}
				return colorRed
			}(), decisionStr, colorReset))

		if ev.Reason != "" {
			sb.WriteString(fmt.Sprintf("    %s↳ [AUDIT]%s %s", colorGray, colorReset, ev.Reason))
			if ev.ViolationCode != "" {
				sb.WriteString(fmt.Sprintf(" %s(%s)%s", colorRed, ev.ViolationCode, colorReset))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString(colorBold + colorBlue + "========================================================================================================\n" + colorReset)
	sb.WriteString(colorGray + "  NIST SP 800-207 Zero-Trust: Zero standing privileges. Ephemeral scoped leases self-destruct upon use.\n" + colorReset)

	return sb.String()
}

// RenderJITMermaid generates a Mermaid state diagram of the JIT authorization lifecycle.
func RenderJITMermaid(summary *JITSummary) string {
	var sb strings.Builder
	sb.WriteString("```mermaid\nflowchart TD\n")
	sb.WriteString("    subgraph AgentClient [Autonomous Agent Request]\n")
	sb.WriteString("        Agent[\"Agent Tool Call Request\"] --> Classify[\"Risk & Scope Classifier\"]\n")
	sb.WriteString("    end\n\n")

	sb.WriteString("    subgraph PolicyEngine [Zero-Trust Evaluation Gates]\n")
	sb.WriteString("        Classify -->|Low / Medium Risk| AutoPolicy[\"Zero-Trust Auto-Grant (TTL: 60s)\"]\n")
	sb.WriteString("        Classify -->|High / Critical Risk| StepUpGate[\"Step-Up Dual Custody Gate\"]\n")
	sb.WriteString("        Classify -->|Forbidden Attack Signature| DenyGate[\"Immediate Denial & Alert\"]\n")
	sb.WriteString("    end\n\n")

	sb.WriteString("    subgraph LeaseLifecycle [Cryptographic Ephemeral Lease]\n")
	sb.WriteString("        AutoPolicy --> MintLease[\"Mint HMAC-SHA256 Signed Lease\"]\n")
	sb.WriteString("        StepUpGate -->|Supervisor Approval| MintLease\n")
	sb.WriteString("        MintLease --> RuntimeVerify[\"Verify Digest, Nonce & Expiry\"]\n")
	sb.WriteString("    end\n\n")

	sb.WriteString("    subgraph Execution [Execution & Self-Destruction]\n")
	sb.WriteString("        RuntimeVerify -->|Arguments Intact & Within TTL| ExecPass[\"✅ Tool Executed\"]\n")
	sb.WriteString("        RuntimeVerify -->|Replay Attempt| ExecReplay[\"🚨 Blocked: Replay Attempt\"]\n")
	sb.WriteString("        RuntimeVerify -->|Tampered Parameters| ExecTamper[\"🚨 Blocked: Argument Mutation\"]\n")
	sb.WriteString("        ExecPass --> Destroy[\"♻️ One-Time Lease Consumed & Destroyed\"]\n")
	sb.WriteString("    end\n```")
	return sb.String()
}

// RenderJITMarkdown formats an empirical markdown table for PR documentation and security audits.
func RenderJITMarkdown(summary *JITSummary) string {
	var sb strings.Builder

	sb.WriteString("### Just-In-Time (JIT) Capability Delegation & Ephemeral Lease Audit\n\n")
	sb.WriteString(fmt.Sprintf("**Total Invocations**: %d | **Consumed**: %d | **Step-Up Blocked**: %d | **Denied/Tampered**: %d | **Latency**: `%s`\n\n",
		summary.TotalRequests, summary.ConsumedLeases, summary.StepUpRequired, summary.DeniedRequests, summary.Duration))

	sb.WriteString("| Lease ID | Tool Name | Agent ID | Risk Tier | Status | Decision | Violation Code | Audit Notes |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, ev := range summary.Evaluations {
		decisionBadge := "**✅ ALLOWED**"
		if !ev.ExecutionAllowed {
			decisionBadge = "**❌ BLOCKED**"
		}
		violCode := "—"
		if ev.ViolationCode != "" {
			violCode = fmt.Sprintf("`%s`", ev.ViolationCode)
		}

		sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s | %s |\n",
			ev.LeaseID, ev.ToolName, ev.AgentID, ev.RiskTier, ev.Status, decisionBadge, violCode, ev.Reason))
	}

	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-2] + ".."
	}
	return s
}
