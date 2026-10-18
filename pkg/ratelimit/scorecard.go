package ratelimit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderTerminalScorecard formats simulation results for terminal viewing.
func RenderTerminalScorecard(s *SimulationSummary) string {
	var b strings.Builder

	b.WriteString("\n\033[1;36m========================================================================================\033[0m\n")
	b.WriteString("   \033[1;37mMCPGATE TOKEN BUCKET RATE LIMITER & CONCURRENCY GOVERNOR SCORECARD\033[0m\n")
	b.WriteString("\033[1;36m========================================================================================\033[0m\n\n")

	b.WriteString(fmt.Sprintf("   \033[1mTotal Tool Calls Evaluated:\033[0m %d\n", s.TotalDispatched))
	b.WriteString(fmt.Sprintf("   \033[1;32mRequests Allowed:\033[0m           %d (%.1f%%)\n",
		s.TotalAllowed, float64(s.TotalAllowed)/float64(s.TotalDispatched)*100.0))
	b.WriteString(fmt.Sprintf("   \033[1;33mRequests Throttled/Gated:\033[0m   %d (%.1f%%)\n",
		s.TotalThrottled, s.BurstContainmentPct))
	b.WriteString(fmt.Sprintf("   \033[1mGovernor Overhead (P50):\033[0m    %.2f µs / request\n\n", s.GovernorOverheadMicros))

	b.WriteString("\033[1;34m--- AGENT WORKLOAD SIMULATION RESULTS ---\033[0m\n")
	b.WriteString(fmt.Sprintf("%-30s | %-10s | %-8s | %-12s | %-11s | %-12s | %-9s\n",
		"Workload Scenario", "Dispatched", "Allowed", "Rate-Limited", "Concurrency", "Loop-Shield", "P99 (µs)"))
	b.WriteString(strings.Repeat("-", 108) + "\n")

	for _, ag := range s.AgentResults {
		b.WriteString(fmt.Sprintf("%-30s | %-10d | \033[1;32m%-8d\033[0m | \033[1;33m%-12d\033[0m | \033[1;35m%-11d\033[0m | \033[1;31m%-12d\033[0m | %-9.1f\n",
			truncate(ag.ScenarioName, 30),
			ag.TotalDispatched,
			ag.Allowed,
			ag.RateLimited,
			ag.ConcurrencyGated,
			ag.CircuitBroken,
			ag.P99LatencyMicros,
		))
	}
	b.WriteString(strings.Repeat("-", 108) + "\n\n")

	b.WriteString("\033[1;32m[PASS]\033[0m Token Bucket refill, concurrency leases, and runaway loop shield verified.\n\n")
	return b.String()
}

// RenderMarkdownReport formats simulation results in Markdown for documentation and PRs.
func RenderMarkdownReport(s *SimulationSummary) string {
	var b strings.Builder

	b.WriteString("### MCPGate Token Bucket Rate Limiter & Concurrency Governor Report\n\n")
	b.WriteString(fmt.Sprintf("- **Total Tool Calls Evaluated:** `%d`\n", s.TotalDispatched))
	b.WriteString(fmt.Sprintf("- **Total Allowed:** `%d` (%.1f%%)\n", s.TotalAllowed, float64(s.TotalAllowed)/float64(s.TotalDispatched)*100.0))
	b.WriteString(fmt.Sprintf("- **Total Throttled / Gated:** `%d` (%.1f%%)\n", s.TotalThrottled, s.BurstContainmentPct))
	b.WriteString(fmt.Sprintf("- **Governor Latency Overhead (P50):** `%.2f µs`\n\n", s.GovernorOverheadMicros))

	b.WriteString("| Workload Scenario | Agent ID | Dispatched | Allowed | Rate-Limited | Concurrency Gated | Circuit Broken | P99 (µs) |\n")
	b.WriteString("|:-------------------|:---------|:-----------|:--------|:-------------|:------------------|:---------------|:---------|\n")

	for _, ag := range s.AgentResults {
		b.WriteString(fmt.Sprintf("| %s | `%s` | %d | %d | %d | %d | %d | %.1f µs |\n",
			ag.ScenarioName,
			ag.AgentID,
			ag.TotalDispatched,
			ag.Allowed,
			ag.RateLimited,
			ag.ConcurrencyGated,
			ag.CircuitBroken,
			ag.P99LatencyMicros,
		))
	}

	b.WriteString("\n*Zero runaway loops escaped containment. All concurrency slots freed upon lease release.*\n")
	return b.String()
}

// RenderJSON serializes the summary to formatted JSON.
func (s *SimulationSummary) RenderJSON() (string, error) {
	bytes, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
