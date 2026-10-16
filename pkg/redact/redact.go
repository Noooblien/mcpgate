package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
)

// SecretCategory classifies detected sensitive data.
type SecretCategory string

const (
	CategoryAPIKey     SecretCategory = "API_KEY"
	CategoryPrivateKey SecretCategory = "PRIVATE_KEY"
	CategoryJWT        SecretCategory = "JWT_TOKEN"
	CategoryCreditCard SecretCategory = "CREDIT_CARD"
	CategoryEmail      SecretCategory = "EMAIL"
	CategorySSN        SecretCategory = "SSN"
)

// RedactRule defines a regular expression pattern for matching secrets.
type RedactRule struct {
	ID          string
	Name        string
	Category    SecretCategory
	Regex       *regexp.Regexp
	MaskFormat  string
	ValidateFn  func(match string) bool
}

// RedactOccurrence records a specific matched secret.
type RedactOccurrence struct {
	RuleID    string         `json:"rule_id"`
	Category  SecretCategory `json:"category"`
	Masked    string         `json:"masked"`
	StartPos  int            `json:"start_pos"`
	EndPos    int            `json:"end_pos"`
}

// RedactResult contains the sanitized text and audit metadata.
type RedactResult struct {
	SanitizedText string             `json:"sanitized_text"`
	TotalRedacted int                `json:"total_redacted"`
	Occurrences   []RedactOccurrence `json:"occurrences"`
}

// Redactor handles sensitive data token masking and secret scrubbing.
type Redactor struct {
	rules   []RedactRule
	hmacKey []byte
}

// NewRedactor initializes the default comprehensive secret redactor.
func NewRedactor(secretKey string) *Redactor {
	if secretKey == "" {
		secretKey = "mcpgate-default-pseudonymization-seed"
	}

	rules := []RedactRule{
		{
			ID:         "SEC-OPENAI",
			Name:       "OpenAI API Key",
			Category:   CategoryAPIKey,
			Regex:      regexp.MustCompile(`\bsk-[A-Za-z0-9]{32,}\b`),
			MaskFormat: "[REDACTED_OPENAI_KEY]",
		},
		{
			ID:         "SEC-ANTHROPIC",
			Name:       "Anthropic API Key",
			Category:   CategoryAPIKey,
			Regex:      regexp.MustCompile(`\bsk-ant-[A-Za-z0-9-_]{32,}\b`),
			MaskFormat: "[REDACTED_ANTHROPIC_KEY]",
		},
		{
			ID:         "SEC-AWS-KEY",
			Name:       "AWS Access Key ID",
			Category:   CategoryAPIKey,
			Regex:      regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			MaskFormat: "[REDACTED_AWS_ACCESS_KEY]",
		},
		{
			ID:         "SEC-GITHUB-PAT",
			Name:       "GitHub Personal Access Token",
			Category:   CategoryAPIKey,
			Regex:      regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
			MaskFormat: "[REDACTED_GITHUB_TOKEN]",
		},
		{
			ID:         "SEC-PRIV-KEY",
			Name:       "Private Cryptographic Key",
			Category:   CategoryPrivateKey,
			Regex:      regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[a-zA-Z0-9\s+/=]+-----END [A-Z ]+PRIVATE KEY-----`),
			MaskFormat: "[REDACTED_PRIVATE_KEY_BLOCK]",
		},
		{
			ID:         "SEC-JWT",
			Name:       "JSON Web Token (JWT)",
			Category:   CategoryJWT,
			Regex:      regexp.MustCompile(`\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b`),
			MaskFormat: "[REDACTED_JWT_TOKEN]",
		},
		{
			ID:         "PII-EMAIL",
			Name:       "Email Address",
			Category:   CategoryEmail,
			Regex:      regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
			MaskFormat: "[REDACTED_EMAIL]",
		},
		{
			ID:         "PII-SSN",
			Name:       "Social Security Number (SSN)",
			Category:   CategorySSN,
			Regex:      regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			MaskFormat: "[REDACTED_SSN]",
		},
		{
			ID:         "PII-CREDIT-CARD",
			Name:       "Credit Card Number (Luhn verified)",
			Category:   CategoryCreditCard,
			Regex:      regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`),
			MaskFormat: "[REDACTED_CREDIT_CARD]",
			ValidateFn: validateLuhn,
		},
	}

	return &Redactor{
		rules:   rules,
		hmacKey: []byte(secretKey),
	}
}

// Redact scrubs text and replaces secrets with pseudonymized or placeholder tokens.
func (r *Redactor) Redact(text string) RedactResult {
	sanitized := text
	occurrences := make([]RedactOccurrence, 0)

	for _, rule := range r.rules {
		indices := rule.Regex.FindAllStringIndex(sanitized, -1)
		if len(indices) == 0 {
			continue
		}

		// Process backwards so offsets remain valid during replacements
		for i := len(indices) - 1; i >= 0; i-- {
			start, end := indices[i][0], indices[i][1]
			matched := sanitized[start:end]

			if rule.ValidateFn != nil && !rule.ValidateFn(matched) {
				continue
			}

			// Generate deterministic pseudonym hash
			h := hmac.New(sha256.New, r.hmacKey)
			h.Write([]byte(matched))
			pseudonym := hex.EncodeToString(h.Sum(nil))[:6]
			replacement := fmt.Sprintf("%s:%s", rule.MaskFormat, pseudonym)

			sanitized = sanitized[:start] + replacement + sanitized[end:]

			occurrences = append(occurrences, RedactOccurrence{
				RuleID:   rule.ID,
				Category: rule.Category,
				Masked:   replacement,
				StartPos: start,
				EndPos:   end,
			})
		}
	}

	return RedactResult{
		SanitizedText: sanitized,
		TotalRedacted: len(occurrences),
		Occurrences:   occurrences,
	}
}

// validateLuhn confirms valid credit card checksums.
func validateLuhn(cc string) bool {
	digits := make([]int, 0, len(cc))
	for _, ch := range cc {
		if ch >= '0' && ch <= '9' {
			d, _ := strconv.Atoi(string(ch))
			digits = append(digits, d)
		}
	}

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}

	return sum%10 == 0
}
