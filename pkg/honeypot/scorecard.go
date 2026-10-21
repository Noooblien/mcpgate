package honeypot

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ANSI color escapes for terminal scorecard rendering.
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorRed     = "\033[1;31m"
	colorGreen   = "\033[1;32m"
	colorYellow  = "\033[1;33m"
	colorBlue    = "\033[1;34m"
	colorMagenta = "\033[1;35m"
	colorCyan    = "\033[1;36m"
	colorGray    = "\033[0;90m"
)

// RenderHoneypotScorecard formats a single tool invocation verdict into a high-visibility terminal scorecard.
func RenderHoneypotScorecard(verdict HoneypotVerdict, sessionID, agentID, toolName string) string {
	var sb strings.Builder

	statusColor := colorGreen
	statusBadge := "[CLEAN - ALLOWED]"
	if verdict.IsHoneypotHit {
		statusColor = colorRed
		statusBadge = "[HONEYPOT TRIPPED - BLOCKED]"
	} else if verdict.SessionLocked {
		statusColor = colorRed
		statusBadge = "[SESSION QUARANTINED]"
	}

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s┌────────────────────────────────────────────────────────────────────────┐%s\n", colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│ %s%-70s%s%s │%s\n", colorCyan, colorBold, "  MCPGATE HONEYPOT & ADVERSARIAL DECEPTION ENGINE", colorReset, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────┤%s\n", colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Session ID:     %-52s %s│%s\n", colorCyan, colorReset, sessionID, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Agent ID:       %-52s %s│%s\n", colorCyan, colorReset, agentID, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Target Tool:    %-52s %s│%s\n", colorCyan, colorReset, toolName, colorCyan, colorReset))
	sb.WriteString(fmt.Sprintf("%s│%s Verdict:        %s%-52s%s %s│%s\n", colorCyan, colorReset, statusColor, statusBadge, colorReset, colorCyan, colorReset))

	if verdict.IsHoneypotHit && verdict.TrapEvent != nil {
		ev := verdict.TrapEvent
		sevColor := colorYellow
		if ev.Severity == SeverityCritical {
			sevColor = colorRed
		}
		sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────┤%s\n", colorCyan, colorReset))
		sb.WriteString(fmt.Sprintf("%s│%s Tripwire Type:  %-52s %s│%s\n", colorCyan, colorReset, ev.TrapType, colorCyan, colorReset))
		sb.WriteString(fmt.Sprintf("%s│%s Severity:       %s%-52s%s %s│%s\n", colorCyan, colorReset, sevColor, ev.Severity, colorReset, colorCyan, colorReset))
		sb.WriteString(fmt.Sprintf("%s│%s Deception Mode: %-52s %s│%s\n", colorCyan, colorReset, ev.DeceptionMode, colorCyan, colorReset))
		sb.WriteString(fmt.Sprintf("%s│%s Session Lock:   %-52s %s│%s\n", colorCyan, colorReset, fmt.Sprintf("%v (Auto-Quarantine Active)", ev.Quarantined), colorCyan, colorReset))
		sb.WriteString(fmt.Sprintf("%s│%s Fingerprint:    %-52s %s│%s\n", colorCyan, colorReset, ev.FingerprintSHA, colorCyan, colorReset))
		sb.WriteString(fmt.Sprintf("%s│%s Forensic Note:  %-52s %s│%s\n", colorCyan, colorReset, truncateString(ev.TriggerDetail, 52), colorCyan, colorReset))

		if verdict.SpoofedPayload != "" {
			sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────┤%s\n", colorCyan, colorReset))
			sb.WriteString(fmt.Sprintf("%s│%s %sSpoofed Honeyed Payload (Returned to Attacker):%s                   %s│%s\n", colorCyan, colorMagenta, colorBold, colorReset, colorCyan, colorReset))
			sb.WriteString(fmt.Sprintf("%s│%s   %-67s %s│%s\n", colorCyan, colorGray, truncateString(verdict.SpoofedPayload, 67), colorCyan, colorReset))
		}
		if verdict.SpoofedError != "" {
			sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────┤%s\n", colorCyan, colorReset))
			sb.WriteString(fmt.Sprintf("%s│%s %sSynthesized Deceptive Error (Returned to Attacker):%s               %s│%s\n", colorCyan, colorYellow, colorBold, colorReset, colorCyan, colorReset))
			sb.WriteString(fmt.Sprintf("%s│%s   %-67s %s│%s\n", colorCyan, colorGray, truncateString(verdict.SpoofedError, 67), colorCyan, colorReset))
		}
	} else if verdict.SessionLocked {
		sb.WriteString(fmt.Sprintf("%s│%s Status Note:    %-52s %s│%s\n", colorCyan, colorReset, "Session locked due to prior breach tripwire.", colorCyan, colorReset))
	} else {
		sb.WriteString(fmt.Sprintf("%s│%s Status Note:    %-52s %s│%s\n", colorCyan, colorReset, "No honeytools probed; benign execution permitted.", colorCyan, colorReset))
	}

	sb.WriteString(fmt.Sprintf("%s└────────────────────────────────────────────────────────────────────────┘%s\n", colorCyan, colorReset))
	return sb.String()
}

// RenderHoneypotMermaid generates a Mermaid flowchart depicting the canary trapping lifecycle.
func RenderHoneypotMermaid(event *TrapEvent) string {
	if event == nil {
		return "```mermaid\ngraph TD\n  Agent[Adversarial Agent] --> Gateway[MCPGate]\n  Gateway --> Pass[Clean Tool Execution Allowed]\n```"
	}

	return fmt.Sprintf("```mermaid\nsequenceDiagram\n"+
		"  autonumber\n"+
		"  actor Attacker as Compromised Agent (%s)\n"+
		"  participant Gateway as MCPGate Honeypot Engine\n"+
		"  participant Trap as Tripwire Detector [%s]\n"+
		"  participant SIEM as SOC Forensic Ledger\n"+
		"  participant Decoy as Deception Synthesizer\n\n"+
		"  Attacker->>Gateway: tools/call %s(args)\n"+
		"  Gateway->>Trap: Evaluate Tool & Token Decoys\n"+
		"  Note over Trap: MATCH: %s (%s)\n"+
		"  Trap->>Gateway: TRIPWIRE TRIGGERED (FP: %s)\n"+
		"  Gateway->>SIEM: Emit Forensic Alert & Quarantine Session\n"+
		"  Gateway->>Decoy: Generate Deception Response [%s]\n"+
		"  Decoy-->>Attacker: Spoofed Response / Fake Payload\n"+
		"```",
		event.AgentID, event.Severity, event.ToolName, event.TrapType, event.Severity,
		event.FingerprintSHA, event.DeceptionMode)
}

// RenderMarkdownReport outputs a GitHub-flavored Markdown report summarizing honeypot activity.
func RenderMarkdownReport(summary *HoneypotSummary) string {
	var sb strings.Builder

	sb.WriteString("# 🍯 MCPGate Honeypot & Adversarial Deception Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated At:** `%s`  \n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Total Calls Evaluated:** `%d`  \n", summary.TotalEvaluated))
	sb.WriteString(fmt.Sprintf("**Tripwires Triggered:** `%d`  \n", summary.TrapsTriggered))
	sb.WriteString(fmt.Sprintf("**Sessions Quarantined:** `%d`  \n", summary.SessionsLocked))
	sb.WriteString(fmt.Sprintf("**Execution Duration:** `%v`  \n\n", summary.Duration))

	sb.WriteString("## 📊 Threat & Tripwire Metrics\n\n")
	sb.WriteString("| Metric | Value | Status |\n")
	sb.WriteString("|---|---|---|\n")
	sb.WriteString(fmt.Sprintf("| Decoy Tool Hits | `%d` | %s |\n", summary.DecoyToolHits, threatIcon(summary.DecoyToolHits)))
	sb.WriteString(fmt.Sprintf("| Canary Token Hits | `%d` | %s |\n", summary.CanaryTokenHits, threatIcon(summary.CanaryTokenHits)))
	sb.WriteString(fmt.Sprintf("| Critical Severity Traps | `%d` | %s |\n", summary.CriticalIncidents, threatIcon(summary.CriticalIncidents)))
	sb.WriteString(fmt.Sprintf("| High Severity Traps | `%d` | %s |\n", summary.HighIncidents, threatIcon(summary.HighIncidents)))
	sb.WriteString(fmt.Sprintf("| Clean Tools Permitted | `%d` | ✅ PASSED |\n\n", summary.CleanPassed))

	sb.WriteString("## 🚨 Forensic Breach Ledger\n\n")
	if len(summary.TrappedEvents) == 0 {
		sb.WriteString("*No tripwires triggered during this evaluation window.*\n\n")
	} else {
		sb.WriteString("| Event ID | Timestamp | Agent | Tool | Type | Severity | Action | Fingerprint |\n")
		sb.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, ev := range summary.TrappedEvents {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | `%s` | **%s** | `%s` | `%s` |\n",
				ev.EventID, ev.Timestamp.Format("15:04:05"), ev.AgentID, ev.ToolName,
				ev.TrapType, ev.Severity, ev.DeceptionMode, ev.FingerprintSHA))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func threatIcon(count int) string {
	if count > 0 {
		return "🚨 DETECTED & TRAPPED"
	}
	return "✅ 0 DETECTED"
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// RenderJSON serializes the summary to formatted JSON.
func (s *HoneypotSummary) RenderJSON() (string, error) {
	bytes, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
