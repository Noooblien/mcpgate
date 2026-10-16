package rbac

import (
	"fmt"
	"regexp"
)

// AgentRole defines an agent's security tier.
type AgentRole string

const (
	RoleAdmin      AgentRole = "admin"
	RoleStandard   AgentRole = "standard"
	RoleRestricted AgentRole = "restricted"
	RoleReadOnly   AgentRole = "readonly"
)

// PolicyRule defines permissions for a specific tool and role.
type PolicyRule struct {
	ToolName            string   `json:"tool_name"`
	AllowedRoles        []AgentRole `json:"allowed_roles"`
	ForbiddenArgRegexes []string `json:"forbidden_arg_regexes,omitempty"`
	RequireConfirmation bool     `json:"require_confirmation"`
}

// RBACDecision represents an access control evaluation outcome.
type RBACDecision struct {
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason"`
	Role        AgentRole `json:"role"`
	ToolName    string    `json:"tool_name"`
	ViolationRule string  `json:"violation_rule,omitempty"`
}

// RBACManager manages role-based access control policies for MCP tools.
type RBACManager struct {
	policies          map[string]PolicyRule
	forbiddenRegexMap map[string][]*regexp.Regexp
	globalBannedArgs  []*regexp.Regexp
}

// NewRBACManager initializes the policy engine with standard security guardrails.
func NewRBACManager() *RBACManager {
	globalBanned := []string{
		`(?i)rm\s+(-rf|-fr|--recursive)\s+/`,
		`169\.254\.169\.254`,             // Cloud metadata IP / SSRF
		`(?i)/etc/(shadow|passwd|sudoers)`,
		`(?i)\b(drop\s+database|truncate\s+table)\b`,
		`\.\./\.\./`,                      // Path traversal
	}

	compiledBanned := make([]*regexp.Regexp, 0, len(globalBanned))
	for _, b := range globalBanned {
		compiledBanned = append(compiledBanned, regexp.MustCompile(b))
	}

	mgr := &RBACManager{
		policies:          make(map[string]PolicyRule),
		forbiddenRegexMap: make(map[string][]*regexp.Regexp),
		globalBannedArgs:  compiledBanned,
	}

	// Register default standard policies
	mgr.RegisterPolicy(PolicyRule{
		ToolName:     "read_file",
		AllowedRoles: []AgentRole{RoleAdmin, RoleStandard, RoleRestricted, RoleReadOnly},
	})
	mgr.RegisterPolicy(PolicyRule{
		ToolName:     "list_dir",
		AllowedRoles: []AgentRole{RoleAdmin, RoleStandard, RoleRestricted, RoleReadOnly},
	})
	mgr.RegisterPolicy(PolicyRule{
		ToolName:     "web_search",
		AllowedRoles: []AgentRole{RoleAdmin, RoleStandard, RoleRestricted, RoleReadOnly},
	})
	mgr.RegisterPolicy(PolicyRule{
		ToolName:     "write_file",
		AllowedRoles: []AgentRole{RoleAdmin, RoleStandard},
	})
	mgr.RegisterPolicy(PolicyRule{
		ToolName:     "execute_command",
		AllowedRoles: []AgentRole{RoleAdmin},
	})

	return mgr
}

// RegisterPolicy adds or overrides a tool permission policy.
func (m *RBACManager) RegisterPolicy(rule PolicyRule) {
	m.policies[rule.ToolName] = rule
	compiled := make([]*regexp.Regexp, 0, len(rule.ForbiddenArgRegexes))
	for _, r := range rule.ForbiddenArgRegexes {
		compiled = append(compiled, regexp.MustCompile(r))
	}
	m.forbiddenRegexMap[rule.ToolName] = compiled
}

// Authorize validates whether the given agent role is authorized to invoke a tool with the provided arguments.
func (m *RBACManager) Authorize(role AgentRole, toolName string, args map[string]interface{}) RBACDecision {
	rule, exists := m.policies[toolName]
	if !exists {
		// Default closed: if tool not registered, deny for restricted/readonly, allow for admin
		if role == RoleAdmin {
			return RBACDecision{Allowed: true, Reason: "unregistered tool allowed for admin", Role: role, ToolName: toolName}
		}
		return RBACDecision{
			Allowed:       false,
			Reason:        fmt.Sprintf("tool '%s' is not in the authorized policy registry", toolName),
			Role:          role,
			ToolName:      toolName,
			ViolationRule: "DEFAULT_DENY_UNREGISTERED",
		}
	}

	// Verify role membership
	roleAllowed := false
	for _, r := range rule.AllowedRoles {
		if r == role {
			roleAllowed = true
			break
		}
	}

	if !roleAllowed {
		return RBACDecision{
			Allowed:       false,
			Reason:        fmt.Sprintf("role '%s' is not authorized to invoke tool '%s'", role, toolName),
			Role:          role,
			ToolName:      toolName,
			ViolationRule: "ROLE_UNAUTHORIZED",
		}
	}

	// Scan arguments against global banned patterns and tool-specific forbidden patterns
	for k, v := range args {
		valStr := fmt.Sprintf("%v", v)

		// Check global banned patterns (SSRF, rm -rf /, etc.)
		for _, reg := range m.globalBannedArgs {
			if reg.MatchString(valStr) {
				return RBACDecision{
					Allowed:       false,
					Reason:        fmt.Sprintf("argument '%s' violates global critical safety policy: matched pattern %s", k, reg.String()),
					Role:          role,
					ToolName:      toolName,
					ViolationRule: "GLOBAL_SAFETY_GUARDRAIL",
				}
			}
		}

		// Check tool-specific forbidden patterns
		if compiledRules, ok := m.forbiddenRegexMap[toolName]; ok {
			for _, reg := range compiledRules {
				if reg.MatchString(valStr) {
					return RBACDecision{
						Allowed:       false,
						Reason:        fmt.Sprintf("argument '%s' contains forbidden pattern %s for tool %s", k, reg.String(), toolName),
						Role:          role,
						ToolName:      toolName,
						ViolationRule: "TOOL_ARG_CONSTRAINT",
					}
				}
			}
		}
	}

	return RBACDecision{
		Allowed:  true,
		Reason:   "policy authorization granted",
		Role:     role,
		ToolName: toolName,
	}
}
