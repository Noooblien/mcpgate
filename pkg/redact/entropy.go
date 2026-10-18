package redact

import (
	"math"
	"regexp"
	"strings"
)

var (
	// wordCandidateRegex matches potential secret candidates (16 to 128 characters without delimiters)
	wordCandidateRegex = regexp.MustCompile(`[^\s"';,()<>{}\[\]]{16,128}`)
)

// EntropyResult details an identified high-entropy secret.
type EntropyResult struct {
	Token        string  `json:"token"`
	Entropy      float64 `json:"entropy"`
	Length       int     `json:"length"`
	IsSuspicious bool    `json:"is_suspicious"`
	CharacterMix string  `json:"character_mix"`
}

// CalculateShannonEntropy computes the bit entropy of a string: H(X) = -sum(P(x) * log2(P(x))).
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	total := float64(len(s))
	for _, ch := range s {
		freq[ch]++
	}

	var entropy float64
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// ScanHighEntropySecrets finds words exceeding the entropy threshold.
// Standard threshold for passwords/API tokens is typically 4.2 - 4.5 bits/char.
func ScanHighEntropySecrets(text string, threshold float64, minLen int) []EntropyResult {
	if threshold <= 0 {
		threshold = 4.3
	}
	if minLen <= 0 {
		minLen = 16
	}

	matches := wordCandidateRegex.FindAllString(text, -1)
	results := make([]EntropyResult, 0)
	seen := make(map[string]bool)

	for _, token := range matches {
		if len(token) < minLen || seen[token] {
			continue
		}
		seen[token] = true

		// Skip common non-secret patterns (e.g. pure hex hashes, UUIDs, or existing vault tokens)
		if strings.Contains(token, "VAULT:") || strings.Contains(token, "REDACTED") || isCommonBenign(token) {
			continue
		}

		ent := CalculateShannonEntropy(token)
		if ent >= threshold {
			results = append(results, EntropyResult{
				Token:        token,
				Entropy:      ent,
				Length:       len(token),
				IsSuspicious: true,
				CharacterMix: analyzeCharMix(token),
			})
		}
	}

	return results
}

func analyzeCharMix(s string) string {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	var parts []string
	if hasUpper {
		parts = append(parts, "upper")
	}
	if hasLower {
		parts = append(parts, "lower")
	}
	if hasDigit {
		parts = append(parts, "digits")
	}
	if hasSpecial {
		parts = append(parts, "symbols")
	}
	return strings.Join(parts, "+")
}

func isCommonBenign(s string) bool {
	// Exclude UUIDs
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	// Exclude all digits
	allDigits := true
	for _, r := range s {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}
	return false
}
