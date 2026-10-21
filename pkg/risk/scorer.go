package risk

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// ToolScorer inspects tool calls and their arguments to calculate multi-dimensional risk scores.
type ToolScorer struct {
	profiles map[string]ToolRiskProfile
}

// NewToolScorer initializes a tool scorer pre-loaded with known MCP tool profiles and heuristics.
func NewToolScorer() *ToolScorer {
	scorer := &ToolScorer{
		profiles: make(map[string]ToolRiskProfile),
	}
	scorer.registerDefaultProfiles()
	return scorer
}

func (s *ToolScorer) registerDefaultProfiles() {
	defaults := []ToolRiskProfile{
		// Safe Read-only tools
		{
			ToolName:   "read_file",
			BaseScore:  5.0,
			Dimensions: DimensionBreakdown{Filesystem: 5.0},
			IsMutating: false,
		},
		{
			ToolName:   "list_files",
			BaseScore:  3.0,
			Dimensions: DimensionBreakdown{Filesystem: 3.0},
			IsMutating: false,
		},
		{
			ToolName:   "search_code",
			BaseScore:  3.0,
			Dimensions: DimensionBreakdown{Filesystem: 3.0},
			IsMutating: false,
		},
		{
			ToolName:   "get_weather",
			BaseScore:  2.0,
			Dimensions: DimensionBreakdown{Network: 2.0},
			IsMutating: false,
		},

		// Mutating Filesystem tools
		{
			ToolName:   "write_file",
			BaseScore:  25.0,
			Dimensions: DimensionBreakdown{Filesystem: 25.0},
			IsMutating: true,
		},
		{
			ToolName:       "delete_file",
			BaseScore:      45.0,
			Dimensions:     DimensionBreakdown{Filesystem: 35.0, Permanent: 10.0},
			IsMutating:     true,
			IsIrreversible: true,
		},

		// Privileged Execution tools
		{
			ToolName:       "bash_exec",
			BaseScore:      50.0,
			Dimensions:     DimensionBreakdown{Privilege: 40.0, Filesystem: 10.0},
			IsMutating:     true,
			IsIrreversible: false,
		},
		{
			ToolName:       "exec_command",
			BaseScore:      50.0,
			Dimensions:     DimensionBreakdown{Privilege: 40.0, Filesystem: 10.0},
			IsMutating:     true,
			IsIrreversible: false,
		},
		{
			ToolName:       "system_reboot",
			BaseScore:      90.0,
			Dimensions:     DimensionBreakdown{Privilege: 50.0, Permanent: 40.0},
			IsMutating:     true,
			IsIrreversible: true,
			RequiresHITL:   true,
		},

		// Network & External Egress tools
		{
			ToolName:   "fetch_url",
			BaseScore:  15.0,
			Dimensions: DimensionBreakdown{Network: 15.0},
			IsMutating: false,
		},
		{
			ToolName:   "send_webhook",
			BaseScore:  30.0,
			Dimensions: DimensionBreakdown{Network: 20.0, Exfiltration: 10.0},
			IsMutating: true,
		},
		{
			ToolName:   "send_email",
			BaseScore:  35.0,
			Dimensions: DimensionBreakdown{Network: 20.0, Exfiltration: 15.0},
			IsMutating: true,
		},

		// Financial & Payment tools
		{
			ToolName:       "transfer_funds",
			BaseScore:      75.0,
			Dimensions:     DimensionBreakdown{Financial: 60.0, Permanent: 15.0},
			IsMutating:     true,
			IsIrreversible: true,
			RequiresHITL:   true,
		},
		{
			ToolName:       "create_invoice",
			BaseScore:      30.0,
			Dimensions:     DimensionBreakdown{Financial: 30.0},
			IsMutating:     true,
		},

		// Database Mutations
		{
			ToolName:   "sql_select",
			BaseScore:  8.0,
			Dimensions: DimensionBreakdown{Exfiltration: 8.0},
			IsMutating: false,
		},
		{
			ToolName:   "sql_insert",
			BaseScore:  20.0,
			Dimensions: DimensionBreakdown{Filesystem: 20.0},
			IsMutating: true,
		},
		{
			ToolName:       "sql_drop_table",
			BaseScore:      85.0,
			Dimensions:     DimensionBreakdown{Filesystem: 40.0, Permanent: 45.0},
			IsMutating:     true,
			IsIrreversible: true,
			RequiresHITL:   true,
		},
	}

	for _, p := range defaults {
		s.profiles[p.ToolName] = p
	}
}

// RegisterProfile allows adding or overriding a tool risk profile.
func (s *ToolScorer) RegisterProfile(p ToolRiskProfile) {
	s.profiles[p.ToolName] = p
}

var (
	reDestructive = regexp.MustCompile(`(?i)(rm\s+-rf|mkfs|dd\s+if=|drop\s+table|delete\s+from|truncate\s+table|format\s+[a-z]:)`)
	reRootSystem  = regexp.MustCompile(`(?i)(^/etc|^/root|^/boot|^/var/run|^/dev|C:\\Windows|/etc/shadow|/etc/passwd)`)
	reWildcardNet = regexp.MustCompile(`(?i)(http://|https://)(\*|0\.0\.0\.0|169\.254\.169\.254|metadata\.google)`)
	reSudoPriv    = regexp.MustCompile(`(?i)(sudo\s+|chmod\s+[0-7]*777|chown\s+root|useradd|visudo)`)
)

// EvaluateToolCall computes the instantaneous score, dimension breakdown, and risk factors for a tool invocation.
func (s *ToolScorer) EvaluateToolCall(toolName string, args map[string]interface{}) (float64, DimensionBreakdown, []string, bool) {
	profile, exists := s.profiles[toolName]
	if !exists {
		// Infer risk profile for unknown tool
		profile = s.inferUnknownToolProfile(toolName)
	}

	score := profile.BaseScore
	dimensions := profile.Dimensions
	var factors []string
	requiresHITL := profile.RequiresHITL

	// Serialize args to string for heuristic inspection
	argsStr := fmt.Sprintf("%v", args)

	// Check 1: Destructive commands & irreversible drops
	if reDestructive.MatchString(argsStr) {
		score += 35.0
		dimensions.Permanent += 25.0
		dimensions.Filesystem += 10.0
		factors = append(factors, "destructive_unrecoverable_command")
		requiresHITL = true
	}

	// Check 2: Sensitive system path manipulation
	if reRootSystem.MatchString(argsStr) {
		score += 30.0
		dimensions.Privilege += 20.0
		dimensions.Filesystem += 10.0
		factors = append(factors, "sensitive_system_path_target")
	}

	// Check 3: Cloud metadata / SSRF or wildcard network targets
	if reWildcardNet.MatchString(argsStr) {
		score += 40.0
		dimensions.Network += 25.0
		dimensions.Exfiltration += 15.0
		factors = append(factors, "cloud_metadata_or_wildcard_egress")
		requiresHITL = true
	}

	// Check 4: Sudo / Privilege escalation commands
	if reSudoPriv.MatchString(argsStr) {
		score += 30.0
		dimensions.Privilege += 30.0
		factors = append(factors, "root_privilege_escalation_intent")
	}

	// Check 5: Financial volume check
	if profile.Dimensions.Financial > 0 {
		if val, found := extractNumericValue(args, "amount", "total", "price", "funds"); found {
			if val > 1000.0 {
				score += 30.0
				dimensions.Financial += 30.0
				factors = append(factors, fmt.Sprintf("high_financial_amount_gt_1000($%.2f)", val))
				requiresHITL = true
			} else if val > 100.0 {
				score += 15.0
				dimensions.Financial += 15.0
				factors = append(factors, fmt.Sprintf("moderate_financial_amount_gt_100($%.2f)", val))
			}
		}
	}

	// Check 6: Large payload exfiltration risk
	if len(argsStr) > 50000 {
		score += 15.0
		dimensions.Exfiltration += 15.0
		factors = append(factors, fmt.Sprintf("large_payload_volume(%d_bytes)", len(argsStr)))
	}

	// Cap individual score to 100.0
	score = math.Min(100.0, score)

	return score, dimensions, factors, requiresHITL
}

func (s *ToolScorer) inferUnknownToolProfile(toolName string) ToolRiskProfile {
	lower := strings.ToLower(toolName)

	if strings.Contains(lower, "exec") || strings.Contains(lower, "run") || strings.Contains(lower, "shell") || strings.Contains(lower, "command") {
		return ToolRiskProfile{
			ToolName:   toolName,
			BaseScore:  45.0,
			Dimensions: DimensionBreakdown{Privilege: 35.0, Filesystem: 10.0},
			IsMutating: true,
		}
	}
	if strings.Contains(lower, "delete") || strings.Contains(lower, "remove") || strings.Contains(lower, "drop") || strings.Contains(lower, "destroy") {
		return ToolRiskProfile{
			ToolName:       toolName,
			BaseScore:      40.0,
			Dimensions:     DimensionBreakdown{Filesystem: 25.0, Permanent: 15.0},
			IsMutating:     true,
			IsIrreversible: true,
		}
	}
	if strings.Contains(lower, "write") || strings.Contains(lower, "update") || strings.Contains(lower, "put") || strings.Contains(lower, "post") || strings.Contains(lower, "create") {
		return ToolRiskProfile{
			ToolName:   toolName,
			BaseScore:  20.0,
			Dimensions: DimensionBreakdown{Filesystem: 15.0, Network: 5.0},
			IsMutating: true,
		}
	}
	if strings.Contains(lower, "pay") || strings.Contains(lower, "transfer") || strings.Contains(lower, "fund") || strings.Contains(lower, "buy") {
		return ToolRiskProfile{
			ToolName:     toolName,
			BaseScore:    60.0,
			Dimensions:   DimensionBreakdown{Financial: 50.0, Permanent: 10.0},
			IsMutating:   true,
			RequiresHITL: true,
		}
	}

	// Fallback generic read/query tool
	return ToolRiskProfile{
		ToolName:   toolName,
		BaseScore:  5.0,
		Dimensions: DimensionBreakdown{Filesystem: 5.0},
		IsMutating: false,
	}
}

func extractNumericValue(args map[string]interface{}, keys ...string) (float64, bool) {
	for _, k := range keys {
		if raw, ok := args[k]; ok {
			switch v := raw.(type) {
			case float64:
				return v, true
			case float32:
				return float64(v), true
			case int:
				return float64(v), true
			case int64:
				return float64(v), true
			}
		}
	}
	return 0.0, false
}
