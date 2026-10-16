package firewall

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

// ThreatLevel categorizes the severity of an injection attack.
type ThreatLevel string

const (
	ThreatLow      ThreatLevel = "LOW"
	ThreatMedium   ThreatLevel = "MEDIUM"
	ThreatHigh     ThreatLevel = "HIGH"
	ThreatCritical ThreatLevel = "CRITICAL"
)

// ThreatFinding records a specific injection pattern matched in the payload.
type ThreatFinding struct {
	RuleID      string      `json:"rule_id"`
	PatternName string      `json:"pattern_name"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	MatchedText string      `json:"matched_text"`
	Description string      `json:"description"`
}

// FirewallResult encapsulates the firewall verdict on a payload.
type FirewallResult struct {
	Allowed      bool            `json:"allowed"`
	ThreatScore  float64         `json:"threat_score"` // 0.0 (safe) to 1.0 (malicious)
	Findings     []ThreatFinding `json:"findings"`
	CleanedText  string          `json:"cleaned_text"`
	IsJailbreak  bool            `json:"is_jailbreak"`
	HasInvisible bool            `json:"has_invisible_unicode"`
}

// FirewallEngine evaluates prompt injection and jailbreak threats in tool arguments.
type FirewallEngine struct {
	jailbreakPatterns []*regexp.Regexp
	overridePatterns  []*regexp.Regexp
	canaryTokens      []string
}

// NewFirewallEngine initializes the prompt injection firewall.
func NewFirewallEngine(canaries ...string) *FirewallEngine {
	jPatterns := []string{
		`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules)`,
		`(?i)disregard\s+(all\s+)?(previous|prior|system)\s+(instructions|prompts)`,
		`(?i)you\s+are\s+now\s+(in\s+developer\s+mode|dan|an\s+unfiltered|an\s+unrestricted)`,
		`(?i)do\s+anything\s+now`,
		`(?i)jailbreak`,
		`(?i)override\s+(system|safety|security)\s+(filters|protocol|guardrails)`,
		`(?i)<\s*(system|admin|developer|instructions)\s*>`,
		`(?i)---+\s*(end\s+system\s+prompt|new\s+system\s+directive)\s*---+`,
	}

	oPatterns := []string{
		`(?i)(system|root)\s*:\s*execute`,
		`(?i)print\s+(all\s+)?(initial|hidden|system)\s+(prompt|instructions)`,
		`(?i)reveal\s+(your\s+)?(secret|api\s+key|password|bearer|auth)`,
		`(?i)cat\s+/etc/(passwd|shadow)`,
		`(?i)base64\s+-d`,
	}

	compiledJ := make([]*regexp.Regexp, 0, len(jPatterns))
	for _, p := range jPatterns {
		compiledJ = append(compiledJ, regexp.MustCompile(p))
	}

	compiledO := make([]*regexp.Regexp, 0, len(oPatterns))
	for _, p := range oPatterns {
		compiledO = append(compiledO, regexp.MustCompile(p))
	}

	return &FirewallEngine{
		jailbreakPatterns: compiledJ,
		overridePatterns:  compiledO,
		canaryTokens:      canaries,
	}
}

// ScanText inspects a string payload for injection attacks, hidden characters, and canary leaks.
func (f *FirewallEngine) ScanText(text string) FirewallResult {
	findings := make([]ThreatFinding, 0)
	score := 0.0
	isJailbreak := false
	hasInvisible := false

	// Check 1: Invisible Unicode characters (zero-width spaces, joiners, directional overrides)
	cleanRunes := make([]rune, 0, len(text))
	for _, r := range text {
		// Zero-width characters and format controls
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' || (r >= '\u202A' && r <= '\u202E') {
			hasInvisible = true
			continue
		}
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			hasInvisible = true
			continue
		}
		cleanRunes = append(cleanRunes, r)
	}

	if hasInvisible {
		findings = append(findings, ThreatFinding{
			RuleID:      "INVIS-001",
			PatternName: "Zero-Width Obfuscation",
			ThreatLevel: ThreatHigh,
			MatchedText: "[invisible Unicode bytes detected]",
			Description: "Payload contains zero-width or directional control characters used to bypass text filters",
		})
		score += 0.40
	}

	cleaned := string(cleanRunes)

	// Check 2: Canary token leak detection
	for _, canary := range f.canaryTokens {
		if canary != "" && strings.Contains(cleaned, canary) {
			findings = append(findings, ThreatFinding{
				RuleID:      "CANARY-001",
				PatternName: "Honeytoken / Canary Leakage",
				ThreatLevel: ThreatCritical,
				MatchedText: canary,
				Description: "Payload references or leaks an internal system canary token",
			})
			score += 0.80
		}
	}

	// Check 3: Jailbreak & Prompt Override patterns
	for _, reg := range f.jailbreakPatterns {
		if loc := reg.FindString(cleaned); loc != "" {
			isJailbreak = true
			findings = append(findings, ThreatFinding{
				RuleID:      "JAIL-001",
				PatternName: "Direct Instruction Override / Jailbreak",
				ThreatLevel: ThreatCritical,
				MatchedText: loc,
				Description: "Payload attempts to override LLM system guardrails or previous instructions",
			})
			score += 0.60
		}
	}

	for _, reg := range f.overridePatterns {
		if loc := reg.FindString(cleaned); loc != "" {
			findings = append(findings, ThreatFinding{
				RuleID:      "OVERRIDE-002",
				PatternName: "Confidentiality Exfiltration Probe",
				ThreatLevel: ThreatHigh,
				MatchedText: loc,
				Description: "Payload attempts to extract system prompts, secrets, or internal files",
			})
			score += 0.40
		}
	}

	// Check 4: Base64 obfuscated payload inspection
	b64Regex := regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)
	matches := b64Regex.FindAllString(cleaned, 5)
	for _, m := range matches {
		if decoded, err := base64.StdEncoding.DecodeString(m); err == nil && len(decoded) > 16 {
			decStr := string(decoded)
			for _, reg := range f.jailbreakPatterns {
				if reg.MatchString(decStr) {
					findings = append(findings, ThreatFinding{
						RuleID:      "OBFUS-B64-001",
						PatternName: "Base64 Encoded Injection",
						ThreatLevel: ThreatCritical,
						MatchedText: m,
						Description: "Base64 encoded block unpacks to an active prompt injection",
					})
					score += 0.70
				}
			}
		}
	}

	if score > 1.0 {
		score = 1.0
	}

	allowed := score < 0.50

	return FirewallResult{
		Allowed:      allowed,
		ThreatScore:  score,
		Findings:     findings,
		CleanedText:  cleaned,
		IsJailbreak:  isJailbreak,
		HasInvisible: hasInvisible,
	}
}
