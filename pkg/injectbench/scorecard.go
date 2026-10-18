package injectbench

import (
	"fmt"
	"strings"
	"time"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

// RenderTerminalScorecard outputs an ANSI formatted scorecard for the terminal.
func RenderTerminalScorecard(summary *BenchmarkSummary) string {
	var sb strings.Builder

	overallBadge := fmt.Sprintf("%s%s[100%% DEFENSE PASS]%s", ansiBold, ansiGreen, ansiReset)
	if !summary.OverallPassed {
		overallBadge = fmt.Sprintf("%s%s[FAIL: BYPASS OR FALSE POSITIVE]%s", ansiBold, ansiRed, ansiReset)
	}

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s╭────────────────────────────────────────────────────────────────────────────────────────╮%s\n", ansiCyan, ansiReset))
	sb.WriteString(fmt.Sprintf("%s│  🛡️  MCP-INJECTBENCH: EMPIRICAL PROMPT INJECTION & TOOL SECURITY BENCHMARK             │%s\n", ansiBold, ansiReset))
	sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────────────────────┤%s\n", ansiCyan, ansiReset))
	sb.WriteString(fmt.Sprintf("│  Timestamp:         %-35s Duration: %-16s │\n",
		summary.Timestamp.Format(time.RFC3339), summary.TotalDuration.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("│  Throughput:        %-15.0f ops/sec               Resilience Score: %s%.1f / 100%s   │\n",
		summary.ThroughputOpsSec, ansiBold, summary.ResilienceScore, ansiReset))
	sb.WriteString(fmt.Sprintf("│  Total Invocations: %-5d (Attacks: %-4d, Benign: %-4d)  Overall Status:   %-16s │\n",
		summary.TotalInvocations, summary.TotalAttacks, summary.TotalBenign, overallBadge))
	sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────────────────────┤%s\n", ansiCyan, ansiReset))
	sb.WriteString(fmt.Sprintf("│  %-28s │ %-6s │ %-9s │ %-8s │ %-8s │ %-6s │\n",
		"Threat Vulnerability Class", "Tests", "Mitigated", "Bypassed", "Recall %", "Status"))
	sb.WriteString(fmt.Sprintf("%s├──────────────────────────────┼────────┼───────────┼──────────┼──────────┼────────┤%s\n", ansiCyan, ansiReset))

	for _, cat := range summary.Categories {
		status := fmt.Sprintf("%sPASS%s", ansiGreen, ansiReset)
		if !cat.Passed {
			status = fmt.Sprintf("%sFAIL%s", ansiRed, ansiReset)
		}

		recallStr := fmt.Sprintf("%.1f%%", cat.RecallRate*100)
		if cat.Category == CatBenignControl {
			recallStr = fmt.Sprintf("%.1f%% FP", cat.FalsePositiveRate*100)
		}

		name := string(cat.Category)
		if len(name) > 28 {
			name = name[:25] + "..."
		}

		sb.WriteString(fmt.Sprintf("│  %-28s │ %-6d │ %-9d │ %-8d │ %-8s │  [%s]  │\n",
			name, cat.TotalInvocations, cat.BlockedCount, cat.FalseNegatives, recallStr, status))
	}

	sb.WriteString(fmt.Sprintf("%s├────────────────────────────────────────────────────────────────────────────────────────┤%s\n", ansiCyan, ansiReset))
	sb.WriteString(fmt.Sprintf("│  Latency SLA Profile: P50: %-7.3fms │ P95: %-7.3fms │ P99: %-7.3fms (SLA: <5.0ms)     │\n",
		summary.P50LatencyMs, summary.P95LatencyMs, summary.P99LatencyMs))
	sb.WriteString(fmt.Sprintf("│  Overall Detection Recall: %s%.2f%%%s │ False Positive Rate: %s%.2f%%%s                     │\n",
		ansiGreen, summary.OverallRecallRate*100, ansiReset, ansiGreen, float64(summary.FalsePositives)/float64(summary.TotalBenign)*100, ansiReset))
	sb.WriteString(fmt.Sprintf("%s╰────────────────────────────────────────────────────────────────────────────────────────╯%s\n", ansiCyan, ansiReset))

	if len(summary.BypassDetails) > 0 {
		sb.WriteString(fmt.Sprintf("\n%s⚠️  Bypass / Violation Diagnostics:%s\n", ansiYellow, ansiReset))
		for _, b := range summary.BypassDetails {
			sb.WriteString(fmt.Sprintf("   • %s\n", b))
		}
	}

	return sb.String()
}

// RenderMarkdownReport produces a GitHub Flavored Markdown table for documentation and CI PR comments.
func RenderMarkdownReport(summary *BenchmarkSummary) string {
	var sb strings.Builder

	sb.WriteString("### 🛡️ MCP-InjectBench: Empirical Prompt Injection & Tool Security Verification\n\n")
	sb.WriteString(fmt.Sprintf("Verified on `%s UTC` across **%d total tool calls** in **%s**.\n\n",
		summary.Timestamp.Format("2006-01-02 15:04:05"), summary.TotalInvocations, summary.TotalDuration.Round(time.Millisecond)))

	sb.WriteString("| Vulnerability Class | Invocations | Mitigated | Bypassed | Recall / Precision | Status |\n")
	sb.WriteString("|:--------------------|:-----------:|:---------:|:--------:|:------------------:|:------:|\n")

	for _, cat := range summary.Categories {
		status := "✅ PASS"
		if !cat.Passed {
			status = "❌ FAIL"
		}

		rate := fmt.Sprintf("%.1f%% recall", cat.RecallRate*100)
		if cat.Category == CatBenignControl {
			rate = fmt.Sprintf("%.1f%% FP", cat.FalsePositiveRate*100)
		}

		sb.WriteString(fmt.Sprintf("| **%s** | %d | %d | %d | %s | %s |\n",
			cat.Category, cat.TotalInvocations, cat.BlockedCount, cat.FalseNegatives, rate, status))
	}

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("- **Resilience Score**: `%.1f / 100`\n", summary.ResilienceScore))
	sb.WriteString(fmt.Sprintf("- **Latency Distribution**: P50: `%.3f ms` | P95: `%.3f ms` | P99: `%.3f ms`\n",
		summary.P50LatencyMs, summary.P95LatencyMs, summary.P99LatencyMs))
	sb.WriteString(fmt.Sprintf("- **Throughput**: `%.0f ops/sec`\n", summary.ThroughputOpsSec))
	sb.WriteString("\n*Zero external dependencies. Pure Go standard library execution.*\n")

	return sb.String()
}
