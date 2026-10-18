package redact

import (
	"fmt"
	"strings"
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// DLPAction specifies the enforcement action taken upon detecting sensitive data.
type DLPAction string

const (
	DLPActionMask      DLPAction = "MASK"      // One-way static redaction: [REDACTED_...]
	DLPActionVault     DLPAction = "VAULT"     // Reversible ephemeral tokenization: [[VAULT:...]]
	DLPActionBlock     DLPAction = "BLOCK"     // Refuse execution and throw security policy violation
	DLPActionAllow     DLPAction = "ALLOW"     // Permit through with audit flag
)

// DLPConfig configures the behavior of the Data Loss Prevention engine.
type DLPConfig struct {
	DefaultAction     DLPAction                     `json:"default_action"`
	CategoryActions   map[SecretCategory]DLPAction  `json:"category_actions"`
	RoleOverrides     map[rbac.AgentRole]DLPAction  `json:"role_overrides"`
	ScanEntropy       bool                          `json:"scan_entropy"`
	EntropyThreshold  float64                       `json:"entropy_threshold"`
	VaultTTL          time.Duration                 `json:"vault_ttl"`
	HMACSeed          string                        `json:"-"`
}

// DefaultDLPConfig provides production zero-trust defaults.
func DefaultDLPConfig() DLPConfig {
	return DLPConfig{
		DefaultAction: DLPActionVault,
		CategoryActions: map[SecretCategory]DLPAction{
			CategoryAPIKey:     DLPActionVault,
			CategoryPrivateKey: DLPActionBlock, // Never allow raw private key blocks
			CategoryJWT:        DLPActionVault,
			CategoryCreditCard: DLPActionMask,  // Luhn-verified credit cards strictly masked
			CategoryEmail:      DLPActionVault,
			CategorySSN:        DLPActionMask,  // SSNs strictly masked
		},
		RoleOverrides: map[rbac.AgentRole]DLPAction{
			rbac.RoleAdmin:      DLPActionVault,
			rbac.RoleRestricted: DLPActionMask,
			rbac.RoleReadOnly:   DLPActionBlock,
		},
		ScanEntropy:      true,
		EntropyThreshold: 4.3,
		VaultTTL:         30 * time.Minute,
		HMACSeed:         "mcpgate-dlp-seed-2026",
	}
}

// DLPResult encapsulates the outcome of a DLP inspection.
type DLPResult struct {
	OriginalText       string             `json:"-"`
	SanitizedText      string             `json:"sanitized_text"`
	Allowed            bool               `json:"allowed"`
	BlockReason        string             `json:"block_reason,omitempty"`
	Occurrences        []RedactOccurrence `json:"occurrences"`
	HighEntropySecrets []EntropyResult    `json:"high_entropy_secrets,omitempty"`
	TokensCreated      []string           `json:"tokens_created,omitempty"`
}

// DLPController coordinates regex-based masking, entropy analysis, and the reversible secret vault.
type DLPController struct {
	config   DLPConfig
	redactor *Redactor
	vault    *SecretVault
}

// NewDLPController creates a new DLP Controller.
func NewDLPController(cfg DLPConfig) *DLPController {
	if cfg.EntropyThreshold <= 0 {
		cfg.EntropyThreshold = 4.3
	}
	if cfg.VaultTTL <= 0 {
		cfg.VaultTTL = 30 * time.Minute
	}

	red := NewRedactor(cfg.HMACSeed)
	v := NewSecretVault(cfg.HMACSeed, cfg.VaultTTL)

	return &DLPController{
		config:   cfg,
		redactor: red,
		vault:    v,
	}
}

// InspectAndSanitize evaluates text, applying role-based DLP policies and vaulting.
func (c *DLPController) InspectAndSanitize(text string, agentID string, role rbac.AgentRole) *DLPResult {
	res := &DLPResult{
		OriginalText:  text,
		SanitizedText: text,
		Allowed:       true,
		Occurrences:   make([]RedactOccurrence, 0),
		TokensCreated: make([]string, 0),
	}

	// Determine base action from role override or default
	effectiveAction := c.config.DefaultAction
	if override, ok := c.config.RoleOverrides[role]; ok {
		effectiveAction = override
	}

	// 1. Scan for known regular expression rules
	sanitized := text
	for _, rule := range c.redactor.rules {
		indices := rule.Regex.FindAllStringIndex(sanitized, -1)
		if len(indices) == 0 {
			continue
		}

		// Check category-specific action unless role override takes precedence
		action := effectiveAction
		if _, hasRoleOverride := c.config.RoleOverrides[role]; !hasRoleOverride {
			if catAction, ok := c.config.CategoryActions[rule.Category]; ok {
				action = catAction
			}
		} else {
			// If role is restricted or readonly, prevent privilege escalation to VAULT
			if catAction, ok := c.config.CategoryActions[rule.Category]; ok {
				if catAction == DLPActionBlock {
					action = DLPActionBlock
				}
			}
		}

		// If BLOCK action triggered, halt immediately
		if action == DLPActionBlock {
			res.Allowed = false
			res.BlockReason = fmt.Sprintf("DLP Policy Block: Sensitive secret matched rule '%s' (%s)", rule.Name, rule.Category)
			return res
		}

		// Process backwards for offset stability
		for i := len(indices) - 1; i >= 0; i-- {
			start, end := indices[i][0], indices[i][1]
			matched := sanitized[start:end]

			if rule.ValidateFn != nil && !rule.ValidateFn(matched) {
				continue
			}

			var replacement string
			switch action {
			case DLPActionVault:
				tok := c.vault.Tokenize(matched, rule.Category, agentID)
				replacement = tok
				res.TokensCreated = append(res.TokensCreated, tok)
			case DLPActionMask:
				replacement = rule.MaskFormat
			case DLPActionAllow:
				replacement = matched
			default:
				replacement = rule.MaskFormat
			}

			sanitized = sanitized[:start] + replacement + sanitized[end:]

			res.Occurrences = append(res.Occurrences, RedactOccurrence{
				RuleID:   rule.ID,
				Category: rule.Category,
				Masked:   replacement,
				StartPos: start,
				EndPos:   end,
			})
		}
	}

	// 2. High-Entropy Scanner
	if c.config.ScanEntropy {
		entropyHits := ScanHighEntropySecrets(sanitized, c.config.EntropyThreshold, 16)
		if len(entropyHits) > 0 {
			res.HighEntropySecrets = entropyHits
			// Mask or vault high-entropy strings
			for _, hit := range entropyHits {
				if effectiveAction == DLPActionBlock {
					res.Allowed = false
					res.BlockReason = fmt.Sprintf("DLP Policy Block: Unstructured high-entropy secret detected (H=%.2f bits)", hit.Entropy)
					return res
				}

				var repl string
				if effectiveAction == DLPActionVault {
					tok := c.vault.Tokenize(hit.Token, CategoryAPIKey, agentID)
					repl = tok
					res.TokensCreated = append(res.TokensCreated, tok)
				} else {
					repl = "[REDACTED_HIGH_ENTROPY_SECRET]"
				}
				sanitized = strings.ReplaceAll(sanitized, hit.Token, repl)
			}
		}
	}

	res.SanitizedText = sanitized
	return res
}

// DetokenizeEgress restores vaulted pseudonyms to plaintext secrets prior to upstream dispatch.
func (c *DLPController) DetokenizeEgress(text string, agentID string) (string, int) {
	return c.vault.Detokenize(text, agentID)
}

// GetVault returns the underlying secret vault for lifecycle checks and metrics.
func (c *DLPController) GetVault() *SecretVault {
	return c.vault
}
