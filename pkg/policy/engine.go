package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// CompiledConstraint wraps an ArgConstraint with compiled regexes.
type CompiledConstraint struct {
	Constraint       ArgConstraint
	AllowedRegex     *regexp.Regexp
	ForbiddenRegex   *regexp.Regexp
}

// CompiledRule wraps PolicyRule with precompiled pattern matchers.
type CompiledRule struct {
	Rule             PolicyRule
	AgentRegex       *regexp.Regexp
	ToolRegex        *regexp.Regexp
	ArgConstraints   []CompiledConstraint
	Loc              *time.Location
}

// PolicyEngine provides thread-safe declarative policy evaluation.
type PolicyEngine struct {
	mu            sync.RWMutex
	manifest      *PolicyManifest
	compiledRules []*CompiledRule
}

// NewEngine initializes a PolicyEngine from a PolicyManifest.
func NewEngine(manifest *PolicyManifest) (*PolicyEngine, error) {
	if manifest == nil {
		return nil, fmt.Errorf("policy manifest cannot be nil")
	}

	compiled, err := compileManifest(manifest)
	if err != nil {
		return nil, err
	}

	return &PolicyEngine{
		manifest:      manifest,
		compiledRules: compiled,
	}, nil
}

// LoadFromJSON parses and compiles a policy manifest from JSON bytes.
func LoadFromJSON(data []byte) (*PolicyEngine, error) {
	var manifest PolicyManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy manifest: %w", err)
	}
	return NewEngine(&manifest)
}

// LoadFromFile reads and compiles a policy manifest from disk.
func LoadFromFile(filePath string) (*PolicyEngine, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	return LoadFromJSON(data)
}

// GlobToRegex converts glob wildcards (*, ?) and pipe alternation (|) into a valid regular expression.
func GlobToRegex(pattern string) (*regexp.Regexp, error) {
	if pattern == "" || pattern == "*" {
		return regexp.Compile(".*")
	}

	parts := strings.Split(pattern, "|")
	var regexParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "*" {
			regexParts = append(regexParts, ".*")
			continue
		}
		var sb strings.Builder
		for i := 0; i < len(part); i++ {
			c := part[i]
			switch c {
			case '*':
				sb.WriteString(".*")
			case '?':
				sb.WriteString(".")
			case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '\\':
				sb.WriteString("\\")
				sb.WriteByte(c)
			default:
				sb.WriteByte(c)
			}
		}
		regexParts = append(regexParts, sb.String())
	}

	fullRegex := fmt.Sprintf("^(?:%s)$", strings.Join(regexParts, "|"))
	return regexp.Compile(fullRegex)
}

func compileManifest(manifest *PolicyManifest) ([]*CompiledRule, error) {
	compiledList := make([]*CompiledRule, 0, len(manifest.Rules))

	// Sort rules by priority descending
	sortedRules := make([]PolicyRule, len(manifest.Rules))
	copy(sortedRules, manifest.Rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority > sortedRules[j].Priority
	})

	for _, rule := range sortedRules {
		agentRx, err := GlobToRegex(rule.AgentPattern)
		if err != nil {
			return nil, fmt.Errorf("rule '%s': invalid agent pattern: %w", rule.ID, err)
		}

		toolRx, err := GlobToRegex(rule.ToolPattern)
		if err != nil {
			return nil, fmt.Errorf("rule '%s': invalid tool pattern: %w", rule.ID, err)
		}

		compiledConstraints := make([]CompiledConstraint, 0, len(rule.ArgConstraints))
		for _, c := range rule.ArgConstraints {
			cc := CompiledConstraint{Constraint: c}
			if c.AllowedPattern != "" {
				rx, err := regexp.Compile(c.AllowedPattern)
				if err != nil {
					return nil, fmt.Errorf("rule '%s', field '%s': invalid allowed_pattern: %w", rule.ID, c.FieldName, err)
				}
				cc.AllowedRegex = rx
			}
			if c.ForbiddenPattern != "" {
				rx, err := regexp.Compile(c.ForbiddenPattern)
				if err != nil {
					return nil, fmt.Errorf("rule '%s', field '%s': invalid forbidden_pattern: %w", rule.ID, c.FieldName, err)
				}
				cc.ForbiddenRegex = rx
			}
			compiledConstraints = append(compiledConstraints, cc)
		}

		var loc *time.Location
		if rule.Temporal != nil && rule.Temporal.Enabled {
			tz := rule.Temporal.Timezone
			if tz == "" {
				tz = "UTC"
			}
			var tzErr error
			loc, tzErr = time.LoadLocation(tz)
			if tzErr != nil {
				loc = time.UTC
			}
		}

		compiledList = append(compiledList, &CompiledRule{
			Rule:           rule,
			AgentRegex:     agentRx,
			ToolRegex:      toolRx,
			ArgConstraints: compiledConstraints,
			Loc:            loc,
		})
	}

	return compiledList, nil
}

// UpdateManifest atomically swaps the active policy manifest and compiled rules.
func (e *PolicyEngine) UpdateManifest(manifest *PolicyManifest) error {
	compiled, err := compileManifest(manifest)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.manifest = manifest
	e.compiledRules = compiled
	return nil
}

// GetManifest returns a copy of the current policy manifest.
func (e *PolicyEngine) GetManifest() *PolicyManifest {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.manifest
}

// Evaluate tests a PolicyRequest against the compiled rules in priority order.
func (e *PolicyEngine) Evaluate(req PolicyRequest) PolicyDecision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	reqTime := req.Timestamp
	if reqTime.IsZero() {
		reqTime = time.Now()
	}

	for _, cr := range e.compiledRules {
		rule := cr.Rule

		// 1. Agent Pattern Check
		if !cr.AgentRegex.MatchString(req.AgentID) {
			continue
		}

		// 2. Role Check
		if len(rule.Roles) > 0 {
			roleMatched := false
			for _, r := range rule.Roles {
				if r == req.Role {
					roleMatched = true
					break
				}
			}
			if !roleMatched {
				continue
			}
		}

		// 3. Tool Pattern Check
		if !cr.ToolRegex.MatchString(req.ToolName) {
			continue
		}

		// 4. Temporal Check
		if rule.Temporal != nil && rule.Temporal.Enabled {
			loc := cr.Loc
			if loc == nil {
				loc = time.UTC
			}
			tLocal := reqTime.In(loc)

			// Check day of week
			if len(rule.Temporal.AllowedDays) > 0 {
				dayAllowed := false
				curDay := tLocal.Weekday()
				for _, d := range rule.Temporal.AllowedDays {
					if d == curDay {
						dayAllowed = true
						break
					}
				}
				if !dayAllowed {
					return PolicyDecision{
						Allowed:         false,
						Action:          ActionDeny,
						MatchedRuleID:   rule.ID,
						MatchedRuleName: rule.Name,
						Reason:          fmt.Sprintf("tool invocation denied by temporal constraint: %s not allowed on %s", req.ToolName, curDay),
						Violations:      []string{fmt.Sprintf("TEMPORAL_DAY_VIOLATION: %s", curDay)},
					}
				}
			}

			// Check hours
			if rule.Temporal.StartHour != 0 || rule.Temporal.EndHour != 0 {
				curHour := tLocal.Hour()
				if curHour < rule.Temporal.StartHour || curHour >= rule.Temporal.EndHour {
					return PolicyDecision{
						Allowed:         false,
						Action:          ActionDeny,
						MatchedRuleID:   rule.ID,
						MatchedRuleName: rule.Name,
						Reason:          fmt.Sprintf("tool invocation denied: %02d:00 outside operational window %02d:00-%02d:00 %s", curHour, rule.Temporal.StartHour, rule.Temporal.EndHour, loc.String()),
						Violations:      []string{"TEMPORAL_HOUR_VIOLATION"},
					}
				}
			}
		}

		// 5. Argument Constraints Check
		var violations []string
		for _, cc := range cr.ArgConstraints {
			c := cc.Constraint
			rawVal, exists := req.Args[c.FieldName]

			if c.Required && (!exists || rawVal == nil) {
				violations = append(violations, fmt.Sprintf("REQUIRED_ARG_MISSING: field '%s' is mandatory", c.FieldName))
				continue
			}

			if !exists || rawVal == nil {
				continue
			}

			valStr := fmt.Sprintf("%v", rawVal)

			if c.MaxLength > 0 && len(valStr) > c.MaxLength {
				violations = append(violations, fmt.Sprintf("ARG_MAX_LENGTH_EXCEEDED: field '%s' len %d > max %d", c.FieldName, len(valStr), c.MaxLength))
			}
			if c.MinLength > 0 && len(valStr) < c.MinLength {
				violations = append(violations, fmt.Sprintf("ARG_MIN_LENGTH_BREACHED: field '%s' len %d < min %d", c.FieldName, len(valStr), c.MinLength))
			}

			if cc.AllowedRegex != nil && !cc.AllowedRegex.MatchString(valStr) {
				violations = append(violations, fmt.Sprintf("ARG_ALLOWED_PATTERN_MISMATCH: field '%s' does not match %s", c.FieldName, c.AllowedPattern))
			}

			if cc.ForbiddenRegex != nil && cc.ForbiddenRegex.MatchString(valStr) {
				violations = append(violations, fmt.Sprintf("ARG_FORBIDDEN_PATTERN_MATCH: field '%s' matched forbidden pattern %s", c.FieldName, c.ForbiddenPattern))
			}
		}

		// For DENY rules with constraints: only trigger if a constraint violation occurred
		if rule.Action == ActionDeny && len(rule.ArgConstraints) > 0 {
			if len(violations) == 0 {
				// No forbidden patterns matched, skip this DENY rule
				continue
			}
			// Forbidden pattern matched: trigger explicit DENY
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("argument validation failed for tool '%s': %s", req.ToolName, strings.Join(violations, "; "))
			}
			return PolicyDecision{
				Allowed:         false,
				Action:          ActionDeny,
				MatchedRuleID:   rule.ID,
				MatchedRuleName: rule.Name,
				Reason:          reason,
				Violations:      violations,
			}
		}

		// For ALLOW or REQUIRE_APPROVAL rules: fail immediately if any constraint was violated
		if len(violations) > 0 {
			return PolicyDecision{
				Allowed:         false,
				Action:          ActionDeny,
				MatchedRuleID:   rule.ID,
				MatchedRuleName: rule.Name,
				Reason:          fmt.Sprintf("argument validation failed for tool '%s': %s", req.ToolName, strings.Join(violations, "; ")),
				Violations:      violations,
			}
		}

		// Rule fully matched!
		action := rule.Action
		allowed := (action == ActionAllow || action == ActionRequireApproval || action == ActionForceRedaction)
		reason := rule.Reason
		if reason == "" {
			reason = fmt.Sprintf("matched policy rule '%s' (priority %d)", rule.Name, rule.Priority)
		}

		return PolicyDecision{
			Allowed:         allowed && action != ActionDeny,
			Action:          action,
			MatchedRuleID:   rule.ID,
			MatchedRuleName: rule.Name,
			Reason:          reason,
			RequireApproval: rule.RequireApproval || action == ActionRequireApproval,
			EffectiveRPM:    rule.CustomRateLimitRPM,
		}
	}

	// Fallback to default action
	defAction := e.manifest.DefaultAction
	if defAction == "" {
		defAction = ActionDeny
	}

	return PolicyDecision{
		Allowed:       defAction == ActionAllow,
		Action:        defAction,
		MatchedRuleID: "DEFAULT_ACTION",
		Reason:        fmt.Sprintf("zero-trust default policy enforcement: %s", defAction),
	}
}

// Validate checks a PolicyManifest for common syntax and logical misconfigurations.
func Validate(m *PolicyManifest) []string {
	var errs []string
	if m.APIVersion == "" {
		errs = append(errs, "apiVersion is required (expected mcpgate.io/v1)")
	}
	if m.Kind != "SecurityPolicy" {
		errs = append(errs, "kind must be 'SecurityPolicy'")
	}
	if len(m.Rules) == 0 {
		errs = append(errs, "manifest contains zero rules")
	}

	seenIDs := make(map[string]bool)
	for i, r := range m.Rules {
		if r.ID == "" {
			errs = append(errs, fmt.Sprintf("rule[%d]: ID is required", i))
		} else if seenIDs[r.ID] {
			errs = append(errs, fmt.Sprintf("rule[%d]: duplicate ID '%s'", i, r.ID))
		}
		seenIDs[r.ID] = true

		if r.ToolPattern == "" {
			errs = append(errs, fmt.Sprintf("rule '%s': tool_pattern is required", r.ID))
		}
		if _, err := GlobToRegex(r.AgentPattern); err != nil {
			errs = append(errs, fmt.Sprintf("rule '%s': invalid agent_pattern: %v", r.ID, err))
		}
		if _, err := GlobToRegex(r.ToolPattern); err != nil {
			errs = append(errs, fmt.Sprintf("rule '%s': invalid tool_pattern: %v", r.ID, err))
		}

		for _, c := range r.ArgConstraints {
			if c.FieldName == "" {
				errs = append(errs, fmt.Sprintf("rule '%s': arg constraint missing field_name", r.ID))
			}
			if c.AllowedPattern != "" {
				if _, err := regexp.Compile(c.AllowedPattern); err != nil {
					errs = append(errs, fmt.Sprintf("rule '%s', field '%s': invalid allowed_pattern: %v", r.ID, c.FieldName, err))
				}
			}
			if c.ForbiddenPattern != "" {
				if _, err := regexp.Compile(c.ForbiddenPattern); err != nil {
					errs = append(errs, fmt.Sprintf("rule '%s', field '%s': invalid forbidden_pattern: %v", r.ID, c.FieldName, err))
				}
			}
		}
	}

	return errs
}

// DefaultZeroTrustPolicy returns an enterprise-grade out-of-the-box Zero-Trust policy manifest.
func DefaultZeroTrustPolicy() *PolicyManifest {
	return &PolicyManifest{
		APIVersion: "mcpgate.io/v1",
		Kind:       "SecurityPolicy",
		Metadata: PolicyMeta{
			Name:        "Zero-Trust Enterprise Policy",
			Version:     "1.0.0",
			Description: "Strict zero-trust least-privilege policy with SSRF, path traversal, and privileged command gates",
			Author:      "MCPGate Security Core",
			UpdatedAt:   "2026-10-18",
		},
		DefaultAction: ActionDeny,
		Rules: []PolicyRule{
			{
				ID:           "rule-global-deny-ssrf",
				Name:         "Global SSRF & Metadata Protection",
				Priority:     100,
				AgentPattern: "*",
				Roles:        []rbac.AgentRole{rbac.RoleAdmin, rbac.RoleStandard, rbac.RoleRestricted, rbac.RoleReadOnly},
				ToolPattern:  "*",
				ArgConstraints: []ArgConstraint{
					{
						FieldName:        "url",
						ForbiddenPattern: `(?i)(169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0)`,
					},
					{
						FieldName:        "host",
						ForbiddenPattern: `(?i)(169\.254\.169\.254|localhost|127\.0\.0\.1)`,
					},
				},
				Action: ActionDeny,
				Reason: "Blocked dangerous loopback or cloud metadata SSRF attempt",
			},
			{
				ID:           "rule-global-deny-traversal",
				Name:         "Global Path Traversal Defense",
				Priority:     95,
				AgentPattern: "*",
				Roles:        []rbac.AgentRole{rbac.RoleAdmin, rbac.RoleStandard, rbac.RoleRestricted, rbac.RoleReadOnly},
				ToolPattern:  "read_*|write_*|list_*|delete_*",
				ArgConstraints: []ArgConstraint{
					{
						FieldName:        "path",
						ForbiddenPattern: `(?i)(\.\./\.\.|/etc/(shadow|passwd|sudoers)|\.ssh/id_)`,
					},
				},
				Action: ActionDeny,
				Reason: "Blocked unauthorized sensitive file access or directory traversal",
			},
			{
				ID:                 "rule-require-approval-exec",
				Name:               "Human-In-The-Loop Exec Approval",
				Priority:           80,
				AgentPattern:       "*",
				Roles:              []rbac.AgentRole{rbac.RoleAdmin, rbac.RoleStandard},
				ToolPattern:        "execute_command|run_terminal|deploy_*",
				Action:             ActionRequireApproval,
				RequireApproval:    true,
				CustomRateLimitRPM: 10,
				Reason:             "Destructive command execution requires 2FA or human approval",
			},
			{
				ID:           "rule-allow-safe-reads",
				Name:         "Allow Safe Read Tools",
				Priority:     50,
				AgentPattern: "*",
				Roles:        []rbac.AgentRole{rbac.RoleAdmin, rbac.RoleStandard, rbac.RoleRestricted, rbac.RoleReadOnly},
				ToolPattern:  "read_*|list_*|search_*|get_*",
				Action:       ActionAllow,
				Reason:       "Safe read-only discovery tools authorized for all roles",
			},
			{
				ID:           "rule-allow-standard-writes",
				Name:         "Allow Standard Write Tools",
				Priority:     40,
				AgentPattern: "agent-*",
				Roles:        []rbac.AgentRole{rbac.RoleAdmin, rbac.RoleStandard},
				ToolPattern:  "write_*|create_*|update_*",
				Action:       ActionAllow,
				Reason:       "Standard mutating actions allowed for provisioned agents",
			},
		},
	}
}
