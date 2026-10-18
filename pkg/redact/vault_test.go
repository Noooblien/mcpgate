package redact

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

func TestVault_TokenizeAndDetokenize(t *testing.T) {
	vault := NewSecretVault("test-seed", 10*time.Minute)
	agentID := "agent-test-01"
	rawSecret := "sk-ant-api03-abcdef1234567890abcdef1234567890"

	tok := vault.Tokenize(rawSecret, CategoryAPIKey, agentID)
	if !strings.HasPrefix(tok, "[[VAULT:API_KEY:") {
		t.Fatalf("expected vault token format, got: %s", tok)
	}

	payload := "Tool input with secret: " + tok
	restored, count := vault.Detokenize(payload, agentID)

	if count != 1 {
		t.Fatalf("expected 1 detokenized secret, got %d", count)
	}
	if !strings.Contains(restored, rawSecret) {
		t.Fatalf("detokenized payload does not match original secret: %s", restored)
	}
}

func TestVault_TTL_Expiration(t *testing.T) {
	// Vault with ultra-short TTL of 10ms
	vault := NewSecretVault("test-seed-exp", 10*time.Millisecond)
	agentID := "agent-test-exp"
	rawSecret := "AKIAIOSFODNN7EXAMPLE"

	tok := vault.Tokenize(rawSecret, CategoryAPIKey, agentID)

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	payload := "Request with: " + tok
	restored, count := vault.Detokenize(payload, agentID)

	if count != 0 {
		t.Fatalf("expected 0 detokenizations after TTL expiration, got %d", count)
	}
	if strings.Contains(restored, rawSecret) {
		t.Fatalf("expired secret should not be detokenized: %s", restored)
	}
}

func TestVault_TenantIsolation(t *testing.T) {
	vault := NewSecretVault("test-seed-tenant", 10*time.Minute)
	tok := vault.Tokenize("ghp_99887766554433221100aabbccddeeff", CategoryAPIKey, "agent-alice")

	payload := "Call with: " + tok

	// Agent Bob attempts to detokenize Alice's token
	restored, count := vault.Detokenize(payload, "agent-bob")
	if count != 0 {
		t.Fatalf("expected cross-agent detokenization to be blocked, count=%d", count)
	}
	if strings.Contains(restored, "ghp_") {
		t.Fatalf("agent-bob accessed agent-alice's secret!")
	}

	stats := vault.GetStats()
	if stats.CrossAgentBlocked != 1 {
		t.Fatalf("expected 1 cross-agent blocked event, got %d", stats.CrossAgentBlocked)
	}

	// Agent Alice detokenizes her own token
	restoredAlice, countAlice := vault.Detokenize(payload, "agent-alice")
	if countAlice != 1 || !strings.Contains(restoredAlice, "ghp_") {
		t.Fatalf("alice failed to detokenize her own secret")
	}
}

func TestEntropy_CalculationAndDetection(t *testing.T) {
	// Low entropy English text
	lowEntropy := "this_is_a_very_normal_string_with_no_randomness"
	hLow := CalculateShannonEntropy(lowEntropy)
	if hLow > 4.0 {
		t.Fatalf("expected low entropy string to be < 4.0, got %f", hLow)
	}

	// High entropy cryptographic token
	highEntropy := "zK9#vL2$pQ8*wN4!mX7"
	hHigh := CalculateShannonEntropy(highEntropy)
	if hHigh < 4.1 {
		t.Fatalf("expected high entropy token to be > 4.1, got %f", hHigh)
	}

	text := "Database password is: zK9#vL2$pQ8*wN4!mX7 and standard text"
	hits := ScanHighEntropySecrets(text, 4.0, 16)
	if len(hits) == 0 {
		t.Fatalf("expected at least 1 high-entropy secret detected")
	}
	if hits[0].Token != "zK9#vL2$pQ8*wN4!mX7" {
		t.Fatalf("unexpected token detected: %s", hits[0].Token)
	}
}

func TestDLP_RoleBasedPolicies(t *testing.T) {
	dlp := NewDLPController(DefaultDLPConfig())

	sampleText := "Deploy with sk-proj99887766554433221100aabbccddeeff and email dev@example.com"

	// 1. Admin / Standard Role: Should VAULT into reversible tokens
	resAdmin := dlp.InspectAndSanitize(sampleText, "agent-admin", rbac.RoleAdmin)
	if !resAdmin.Allowed {
		t.Fatalf("expected admin to be allowed")
	}
	if !strings.Contains(resAdmin.SanitizedText, "[[VAULT:API_KEY:") {
		t.Fatalf("expected API key to be vaulted for admin, got: %s", resAdmin.SanitizedText)
	}

	// Invert / Detokenize admin payload
	detok, cnt := dlp.DetokenizeEgress(resAdmin.SanitizedText, "agent-admin")
	if cnt < 1 || !strings.Contains(detok, "sk-proj") {
		t.Fatalf("failed to detokenize admin egress: %s", detok)
	}

	// 2. Restricted Role: Should irreversibly MASK
	resRestricted := dlp.InspectAndSanitize(sampleText, "agent-restricted", rbac.RoleRestricted)
	if !resRestricted.Allowed {
		t.Fatalf("expected restricted role to be allowed with masking")
	}
	if strings.Contains(resRestricted.SanitizedText, "[[VAULT:") {
		t.Fatalf("restricted role should not receive reversible vault tokens: %s", resRestricted.SanitizedText)
	}
	if !strings.Contains(resRestricted.SanitizedText, "[REDACTED_OPENAI_KEY]") {
		t.Fatalf("expected masked token [REDACTED_OPENAI_KEY], got: %s", resRestricted.SanitizedText)
	}

	// 3. Raw Private Key: Should BLOCK
	privateKeyText := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y9x6e...\n-----END RSA PRIVATE KEY-----"
	resBlock := dlp.InspectAndSanitize(privateKeyText, "agent-user", rbac.RoleStandard)
	if resBlock.Allowed {
		t.Fatalf("expected raw private key to trigger DLP BLOCK")
	}
}

func TestDLP_ScorecardAndMermaid(t *testing.T) {
	dlp := NewDLPController(DefaultDLPConfig())
	scenarios := DefaultDemoScenarios()

	res := dlp.InspectAndSanitize(scenarios[0].Payload, scenarios[0].AgentID, scenarios[0].Role)
	scorecard := RenderDLPScorecard(res, scenarios[0].AgentID, DLPActionVault)

	if !strings.Contains(scorecard, "MCPGATE // DATA LOSS PREVENTION") {
		t.Fatalf("missing header in scorecard: %s", scorecard)
	}

	mermaid := RenderDLPMermaid()
	if !strings.Contains(mermaid, "flowchart LR") || !strings.Contains(mermaid, "Secret Vault") {
		t.Fatalf("invalid mermaid diagram: %s", mermaid)
	}

	md := RenderMarkdownReport([]*DLPResult{res})
	if !strings.Contains(md, "MCPGate Data Loss Prevention") {
		t.Fatalf("invalid markdown report: %s", md)
	}
}

// Silence math import unused warning if any
var _ = math.Max
