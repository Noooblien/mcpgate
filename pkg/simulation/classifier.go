package simulation

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	// SQL classification regex patterns
	reSQLSelect   = regexp.MustCompile(`(?i)^\s*SELECT\b`)
	reSQLInsert   = regexp.MustCompile(`(?i)^\s*INSERT\b`)
	reSQLUpdate   = regexp.MustCompile(`(?i)^\s*UPDATE\b`)
	reSQLDelete   = regexp.MustCompile(`(?i)^\s*DELETE\b`)
	reSQLDrop     = regexp.MustCompile(`(?i)\b(DROP\s+TABLE|DROP\s+DATABASE|DROP\s+SCHEMA|TRUNCATE)\b`)
	reSQLWhere    = regexp.MustCompile(`(?i)\bWHERE\b`)

	// Shell destructive command patterns
	reShellCatastrophic = regexp.MustCompile(`\b(rm\s+-(?:r|f|rf|fr)\s+[/~*]|mkfs\b|dd\s+if=|:\(\)\{.*\}|>\s*/dev/sd[a-z]|shred\b)`)
	reShellDelete       = regexp.MustCompile(`\b(rm\s+|unlink\s+|rmdir\s+)`)
	reShellNetwork      = regexp.MustCompile(`\b(curl\s+|wget\s+|nc\s+|ncat\s+|ssh\s+|scp\s+|ftp\s+)`)
	reShellReadOnly     = regexp.MustCompile(`\b(ls\s*|cat\s+|grep\s+|head\s+|tail\s+|wc\s+|find\s+|stat\s+)`)

	// Financial / Egress keyword detectors
	reFinancial = regexp.MustCompile(`(?i)(charge|pay|transfer|refund|payout|invoice|billing)`)
	reEgress    = regexp.MustCompile(`(?i)(send_email|post_tweet|send_message|slack_post|webhook_post|publish_post|send_mail)`)
	reCloud     = regexp.MustCompile(`(?i)(run_instances|terminate_instances|create_cluster|delete_cluster|apply_terraform|drop_namespace)`)
)

// Classifier inspects tool names and payload parameters to determine operational category and blast radius.
type Classifier struct{}

// NewClassifier creates a static analysis tool classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// Classify evaluates the tool name and arguments.
func (c *Classifier) Classify(toolName string, rawArgs []byte) (SideEffectCategory, BlastRadiusEstimate, string) {
	normTool := strings.ToLower(strings.TrimSpace(toolName))
	argsMap := make(map[string]interface{})
	_ = json.Unmarshal(rawArgs, &argsMap)

	argsStr := string(rawArgs)

	// 1. Check for Irreversible Shell Destruction
	if reShellCatastrophic.MatchString(argsStr) || strings.Contains(normTool, "drop_database") || reSQLDrop.MatchString(argsStr) {
		return CategoryIrreversibleDestructive, BlastRadiusEstimate{
			EstimatedEntitiesAffected: 10000,
			EstimatedFinancialRiskUSD: 5000.0,
			ScopeLevel:                "infrastructure_wide",
			DestructiveRiskScore:      9.8,
			ReversibilityQuotient:     0.0,
			ReversibilityLevel:        Irreversible,
		}, "Zero automatic rollback possible. Requires full cold-storage disaster recovery restoration."
	}

	// 2. Check for SQL Operations
	if strings.Contains(normTool, "sql") || strings.Contains(normTool, "query") || strings.Contains(normTool, "db") {
		query, _ := argsMap["query"].(string)
		if query == "" {
			query = argsStr
		}

		if reSQLDrop.MatchString(query) {
			return CategoryIrreversibleDestructive, BlastRadiusEstimate{
				EstimatedEntitiesAffected: 5000,
				EstimatedFinancialRiskUSD: 1000.0,
				ScopeLevel:                "tenant_wide",
				DestructiveRiskScore:      9.5,
				ReversibilityQuotient:     0.05,
				ReversibilityLevel:        Irreversible,
			}, "Irreversible DDL operation. Requires point-in-time database snapshot restoration."
		}

		if reSQLDelete.MatchString(query) {
			hasWhere := reSQLWhere.MatchString(query)
			if !hasWhere {
				// Table-wide unconstrained delete
				return CategoryIrreversibleDestructive, BlastRadiusEstimate{
					EstimatedEntitiesAffected: 2500,
					EstimatedFinancialRiskUSD: 500.0,
					ScopeLevel:                "tenant_wide",
					DestructiveRiskScore:      8.8,
					ReversibilityQuotient:     0.15,
					ReversibilityLevel:        ReversibleWithManualEffort,
				}, "Unconstrained table-wide DELETE. Requires transaction rollback or binary log re-injection."
			}
			return CategoryReversibleMutation, BlastRadiusEstimate{
				EstimatedEntitiesAffected: 10,
				EstimatedFinancialRiskUSD: 0.0,
				ScopeLevel:                "isolated",
				DestructiveRiskScore:      5.2,
				ReversibilityQuotient:     0.70,
				ReversibilityLevel:        ReversibleFully,
			}, "Constrained DELETE with WHERE filter. Compensatable via pre-execution row snapshot."
		}

		if reSQLInsert.MatchString(query) || reSQLUpdate.MatchString(query) {
			return CategoryReversibleMutation, BlastRadiusEstimate{
				EstimatedEntitiesAffected: 5,
				EstimatedFinancialRiskUSD: 0.0,
				ScopeLevel:                "isolated",
				DestructiveRiskScore:      3.5,
				ReversibilityQuotient:     0.85,
				ReversibilityLevel:        ReversibleFully,
			}, "Compensating UPDATE/DELETE query generated from pre-state snapshot."
		}

		if reSQLSelect.MatchString(query) {
			return CategoryReadOnly, BlastRadiusEstimate{
				EstimatedEntitiesAffected: 0,
				EstimatedFinancialRiskUSD: 0.0,
				ScopeLevel:                "isolated",
				DestructiveRiskScore:      0.0,
				ReversibilityQuotient:     1.0,
				ReversibilityLevel:        ReversibleFully,
			}, "Idempotent read-only execution. No state modified."
		}
	}

	// 3. Check for Financial / Payment Operations
	if reFinancial.MatchString(normTool) || reFinancial.MatchString(argsStr) {
		amount := extractFinancialAmount(argsMap)
		return CategoryExternalEgress, BlastRadiusEstimate{
			EstimatedEntitiesAffected: 1,
			EstimatedFinancialRiskUSD: amount,
			ScopeLevel:                "isolated",
			DestructiveRiskScore:      calculateFinancialScore(amount),
			ReversibilityQuotient:     0.35, // Financial refunds take time and fee friction
			ReversibilityLevel:        ReversibleWithManualEffort,
		}, fmt.Sprintf("External financial transfer of $%.2f. Requires issuing an asynchronous refund/chargeback transaction.", amount)
	}

	// 4. Check for External Egress / Messaging
	if reEgress.MatchString(normTool) || reShellNetwork.MatchString(argsStr) {
		return CategoryExternalEgress, BlastRadiusEstimate{
			EstimatedEntitiesAffected: 1,
			EstimatedFinancialRiskUSD: 0.0,
			ScopeLevel:                "isolated",
			DestructiveRiskScore:      5.8,
			ReversibilityQuotient:     0.10, // Sent emails/messages cannot be unseen
			ReversibilityLevel:        Irreversible,
		}, "External communication sent outside trust boundary. Message cannot be un-broadcasted."
	}

	// 5. Check for Cloud / Infrastructure Resource Allocation
	if reCloud.MatchString(normTool) || reCloud.MatchString(argsStr) {
		return CategoryResourceAllocation, BlastRadiusEstimate{
			EstimatedEntitiesAffected: 20,
			EstimatedFinancialRiskUSD: 250.0,
			ScopeLevel:                "tenant_wide",
			DestructiveRiskScore:      7.5,
			ReversibilityQuotient:     0.65,
			ReversibilityLevel:        ReversibleWithManualEffort,
		}, "Cloud infrastructure modification. Compensated via Terraform destroy or VM teardown."
	}

	// 6. Check for Filesystem Writes vs Reads
	if strings.Contains(normTool, "write") || strings.Contains(normTool, "delete") || strings.Contains(normTool, "edit") || reShellDelete.MatchString(argsStr) {
		return CategoryReversibleMutation, BlastRadiusEstimate{
			EstimatedEntitiesAffected: 1,
			EstimatedFinancialRiskUSD: 0.0,
			ScopeLevel:                "isolated",
			DestructiveRiskScore:      4.2,
			ReversibilityQuotient:     0.80,
			ReversibilityLevel:        ReversibleFully,
		}, "File mutation compensatable by restoring from pre-write shadow file copy."
	}

	// 7. Default: Read-Only
	if strings.Contains(normTool, "read") || strings.Contains(normTool, "list") || strings.Contains(normTool, "get") || reShellReadOnly.MatchString(argsStr) {
		return CategoryReadOnly, BlastRadiusEstimate{
			EstimatedEntitiesAffected: 0,
			EstimatedFinancialRiskUSD: 0.0,
			ScopeLevel:                "isolated",
			DestructiveRiskScore:      0.0,
			ReversibilityQuotient:     1.0,
			ReversibilityLevel:        ReversibleFully,
		}, "Read-only idempotent operation."
	}

	// Fallback general mutation
	return CategoryReversibleMutation, BlastRadiusEstimate{
		EstimatedEntitiesAffected: 1,
		EstimatedFinancialRiskUSD: 0.0,
		ScopeLevel:                "isolated",
		DestructiveRiskScore:      3.0,
		ReversibilityQuotient:     0.70,
		ReversibilityLevel:        ReversibleFully,
	}, "Standard application side-effect."
}

func extractFinancialAmount(args map[string]interface{}) float64 {
	for k, v := range args {
		if strings.Contains(strings.ToLower(k), "amount") || strings.Contains(strings.ToLower(k), "price") || strings.Contains(strings.ToLower(k), "total") {
			switch num := v.(type) {
			case float64:
				return num
			case int:
				return float64(num)
			case int64:
				return float64(num)
			}
		}
	}
	return 25.0 // Conservative default estimate if key is missing
}

func calculateFinancialScore(amountUSD float64) float64 {
	if amountUSD <= 10.0 {
		return 3.0
	} else if amountUSD <= 100.0 {
		return 5.5
	} else if amountUSD <= 1000.0 {
		return 7.8
	}
	return 9.2
}
