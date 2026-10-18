package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

var (
	// VaultTokenRegex matches structured ephemeral vault tokens: [[VAULT:<CATEGORY>:<HEX>]]
	VaultTokenRegex = regexp.MustCompile(`\[\[VAULT:([A-Z_]+):([a-f0-9]{8,16})\]\]`)
)

// VaultEntry stores the bidirectional mapping and lease metadata for a tokenized secret.
type VaultEntry struct {
	Token        string         `json:"token"`
	Category     SecretCategory `json:"category"`
	Plaintext    string         `json:"-"` // Never serialized in logs or API responses
	AgentID      string         `json:"agent_id"`
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    time.Time      `json:"expires_at"`
	AccessCount  int            `json:"access_count"`
	LastAccessAt time.Time      `json:"last_access_at"`
}

// SecretVault manages in-memory, auto-expiring ephemeral tokens with zero disk persistence.
type SecretVault struct {
	mu           sync.RWMutex
	secretToTok  map[string]*VaultEntry // agentID + ":" + Plaintext -> VaultEntry
	tokToEntry   map[string]*VaultEntry // Token -> VaultEntry
	hmacKey      []byte
	defaultTTL   time.Duration
	stats        VaultStats
}

// VaultStats tracks throughput and security telemetry for the ephemeral vault.
type VaultStats struct {
	ActiveTokens      int   `json:"active_tokens"`
	TotalTokenized    int64 `json:"total_tokenized"`
	TotalDetokenized  int64 `json:"total_detokenized"`
	TotalExpired      int64 `json:"total_expired"`
	CrossAgentBlocked int64 `json:"cross_agent_blocked"`
}

// NewSecretVault initializes a secure ephemeral token vault.
func NewSecretVault(hmacSeed string, defaultTTL time.Duration) *SecretVault {
	if hmacSeed == "" {
		hmacSeed = "mcpgate-vault-seed-default-7319"
	}
	if defaultTTL <= 0 {
		defaultTTL = 30 * time.Minute
	}

	return &SecretVault{
		secretToTok: make(map[string]*VaultEntry),
		tokToEntry:  make(map[string]*VaultEntry),
		hmacKey:     []byte(hmacSeed),
		defaultTTL:  defaultTTL,
	}
}

// Tokenize converts a plaintext secret into a reversible scoped pseudonym token.
func (v *SecretVault) Tokenize(plaintext string, category SecretCategory, agentID string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	lookupKey := agentID + ":" + plaintext
	now := time.Now().UTC()

	// Check existing unexpired lease
	if entry, exists := v.secretToTok[lookupKey]; exists {
		if now.Before(entry.ExpiresAt) {
			entry.AccessCount++
			entry.LastAccessAt = now
			return entry.Token
		}
		// Expired entry - remove stale
		delete(v.tokToEntry, entry.Token)
		delete(v.secretToTok, lookupKey)
		v.stats.TotalExpired++
	}

	// Generate deterministic token hash from plaintext + agentID + secretKey
	h := hmac.New(sha256.New, v.hmacKey)
	h.Write([]byte(plaintext))
	h.Write([]byte("::"))
	h.Write([]byte(agentID))
	tokenHash := hex.EncodeToString(h.Sum(nil))[:10]

	token := fmt.Sprintf("[[VAULT:%s:%s]]", category, tokenHash)

	entry := &VaultEntry{
		Token:        token,
		Category:     category,
		Plaintext:    plaintext,
		AgentID:      agentID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(v.defaultTTL),
		AccessCount:  1,
		LastAccessAt: now,
	}

	v.secretToTok[lookupKey] = entry
	v.tokToEntry[token] = entry
	v.stats.TotalTokenized++
	v.stats.ActiveTokens = len(v.tokToEntry)

	return token
}

// Detokenize swaps all pseudonym tokens in tokenizedText back to plaintext secrets.
// Enforces tenant isolation: tokens created by agent A cannot be detokenized by agent B.
func (v *SecretVault) Detokenize(tokenizedText string, agentID string) (string, int) {
	v.mu.Lock()
	defer v.mu.Unlock()

	detokenizedCount := 0
	now := time.Now().UTC()

	result := VaultTokenRegex.ReplaceAllStringFunc(tokenizedText, func(match string) string {
		entry, exists := v.tokToEntry[match]
		if !exists {
			return match // Unknown token; leave untouched
		}

		// Verify TTL
		if now.After(entry.ExpiresAt) {
			delete(v.tokToEntry, match)
			delete(v.secretToTok, entry.AgentID+":"+entry.Plaintext)
			v.stats.TotalExpired++
			v.stats.ActiveTokens = len(v.tokToEntry)
			return match
		}

		// Verify Agent Tenant Isolation
		if entry.AgentID != "" && agentID != "" && entry.AgentID != agentID {
			v.stats.CrossAgentBlocked++
			return match // Block cross-agent detokenization attempt
		}

		entry.AccessCount++
		entry.LastAccessAt = now
		detokenizedCount++
		v.stats.TotalDetokenized++
		return entry.Plaintext
	})

	return result, detokenizedCount
}

// PurgeExpired evicts expired vault entries to prevent memory growth.
func (v *SecretVault) PurgeExpired() int {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now().UTC()
	purged := 0

	for tok, entry := range v.tokToEntry {
		if now.After(entry.ExpiresAt) {
			delete(v.tokToEntry, tok)
			delete(v.secretToTok, entry.AgentID+":"+entry.Plaintext)
			purged++
			v.stats.TotalExpired++
		}
	}

	v.stats.ActiveTokens = len(v.tokToEntry)
	return purged
}

// GetEntry retrieves public metadata for an active token (omitting plaintext).
func (v *SecretVault) GetEntry(token string) (*VaultEntry, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, ok := v.tokToEntry[token]
	if !ok || time.Now().UTC().After(entry.ExpiresAt) {
		return nil, false
	}
	// Return shallow copy
	cp := *entry
	cp.Plaintext = "" // Ensure plaintext is hidden
	return &cp, true
}

// GetStats returns telemetry metrics for the secret vault.
func (v *SecretVault) GetStats() VaultStats {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.stats
}

// ContainsTokens checks if text contains any structured vault tokens.
func ContainsTokens(s string) bool {
	return VaultTokenRegex.MatchString(s)
}
