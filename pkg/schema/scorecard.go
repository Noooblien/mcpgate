package schema

import (
	"fmt"
	"strings"
	"time"
)

// SchemaSummary aggregates multiple tool argument validation checks.
type SchemaSummary struct {
	TotalValidated int
	ValidCount     int
	InvalidCount   int
	Duration       time.Duration
	Evaluations    []SchemaValidationResult
}

// RenderSchemaScorecard produces an ANSI terminal scorecard for schema validation.
func RenderSchemaScorecard(summary SchemaSummary) string {
	sb := &strings.Builder{}

	sb.WriteString("\n\033[1;36m========================================================================================\033[0m\n")
	sb.WriteString("   \033[1;37mMCPGATE SCHEMA & ARGUMENT COMPLIANCE VALIDATOR SCORECARD\033[0m\n")
	sb.WriteString("\033[1;36m========================================================================================\033[0m\n\n")

	sb.WriteString(fmt.Sprintf("  \033[1;33mTotal Tool Calls Evaluated:\033[0m  %d\n", summary.TotalValidated))
	sb.WriteString(fmt.Sprintf("  \033[1;32mSchema Compliant:\033[0m            %d\n", summary.ValidCount))
	sb.WriteString(fmt.Sprintf("  \033[1;31mSchema Violations:\033[0m           %d\n", summary.InvalidCount))
	sb.WriteString(fmt.Sprintf("  \033[1;36mEvaluation Latency:\033[0m          %v\n\n", summary.Duration))

	sb.WriteString("\033[1;34m----------------------------------------------------------------------------------------\033[0m\n")
	sb.WriteString("  \033[1;37mVALIDATION BREAKDOWN:\033[0m\n")
	sb.WriteString("\033[1;34m----------------------------------------------------------------------------------------\033[0m\n")

	for i, eval := range summary.Evaluations {
		status := "\033[1;32mPASSED (COMPLIANT)\033[0m"
		if !eval.Valid {
			status = "\033[1;31mREJECTED (SCHEMA VIOLATION)\033[0m"
		}

		sb.WriteString(fmt.Sprintf("  [%d] Tool: \033[1;37m%-24s\033[0m | Verdict: %s | Latency: %d µs\n",
			i+1, eval.ToolName, status, eval.DurationUs))

		if len(eval.Errors) > 0 {
			for _, err := range eval.Errors {
				sb.WriteString(fmt.Sprintf("      - \033[1;31m[%s]\033[0m Field: \033[1;33m%s\033[0m -> %s\n",
					err.Rule, err.Field, err.Description))
			}
		} else {
			sb.WriteString("      ✓ All arguments satisfied property types, constraints, and required fields\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\033[1;36m========================================================================================\033[0m\n")
	return sb.String()
}

// RenderSchemaMarkdown produces a Markdown report for schema validation audits.
func RenderSchemaMarkdown(summary SchemaSummary) string {
	sb := &strings.Builder{}

	sb.WriteString("# 📐 MCPGate Tool Schema Validation & Compliance Report\n\n")
	sb.WriteString(fmt.Sprintf("**Timestamp:** `%s`  \n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Total Calls Evaluated:** `%d`  \n", summary.TotalValidated))
	sb.WriteString(fmt.Sprintf("**Compliant:** `%d` | **Violations:** `%d`  \n", summary.ValidCount, summary.InvalidCount))
	sb.WriteString(fmt.Sprintf("**Total Duration:** `%v`  \n\n", summary.Duration))

	sb.WriteString("## Evaluation Matrix\n\n")
	sb.WriteString("| # | Tool Name | Status | Latency | Violations Count | First Violation |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")

	for i, eval := range summary.Evaluations {
		badge := "🟢 COMPLIANT"
		firstViol := "-"
		if !eval.Valid {
			badge = "🔴 REJECTED"
			if len(eval.Errors) > 0 {
				firstViol = fmt.Sprintf("`%s`: %s", eval.Errors[0].Field, eval.Errors[0].Rule)
			}
		}

		sb.WriteString(fmt.Sprintf("| %d | `%s` | %s | `%d µs` | %d | %s |\n",
			i+1, eval.ToolName, badge, eval.DurationUs, len(eval.Errors), firstViol))
	}

	sb.WriteString("\n## Detailed Violation Findings\n\n")
	for i, eval := range summary.Evaluations {
		if len(eval.Errors) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("### %d. `%s`\n", i+1, eval.ToolName))
		for _, err := range eval.Errors {
			sb.WriteString(fmt.Sprintf("- **Field:** `%s` | **Rule:** `%s`  \n  > %s\n", err.Field, err.Rule, err.Description))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// RenderSchemaMermaid generates a sequence diagram illustrating schema validation enforcement.
func RenderSchemaMermaid(evaluations []SchemaValidationResult) string {
	sb := &strings.Builder{}
	sb.WriteString("```mermaid\nsequenceDiagram\n")
	sb.WriteString("    autonumber\n")
	sb.WriteString("    participant Agent as Autonomous Agent\n")
	sb.WriteString("    participant Gate as MCPGate Pipeline\n")
	sb.WriteString("    participant Schema as Schema Validator\n")
	sb.WriteString("    participant Upstream as Target MCP Server\n\n")

	for _, eval := range evaluations {
		sb.WriteString(fmt.Sprintf("    Agent->>Gate: tools/call (%s)\n", eval.ToolName))
		sb.WriteString("    Gate->>Schema: Validate Argument Constraints & Types\n")

		if eval.Valid {
			sb.WriteString("    Schema-->>Gate: Valid (Compliant JSON Schema)\n")
			sb.WriteString("    Gate->>Upstream: Forward Verified Request\n")
			sb.WriteString("    Upstream-->>Agent: Execution Result\n")
		} else {
			sb.WriteString("    Schema-->>Gate: Invalid (Schema Constraints Violated)\n")
			sb.WriteString("    Gate-->>Agent: 400 Bad Request / Schema Rejection\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("```\n")
	return sb.String()
}
