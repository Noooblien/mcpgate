package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
	"github.com/Noooblien/mcpgate/pkg/redact"
)

func TestVault_EndToEndWorkflow(t *testing.T) {
	dlp := redact.NewDLPController(redact.DefaultDLPConfig())
	agentID := "agent-e2e-workflow"
	role := rbac.RoleStandard

	rawSecret := "sk-ant-api03-abcdef1234567890abcdef1234567890"
	customerEmail := "alice.engineer@techcorp.io"

	originalPayload := `{"tool": "fetch_customer_data", "api_key": "` + rawSecret + `", "email": "` + customerEmail + `"}`

	// 1. Ingress Sanitization: Raw secrets are replaced with scoped reversible vault tokens
	ingressRes := dlp.InspectAndSanitize(originalPayload, agentID, role)
	if !ingressRes.Allowed {
		t.Fatalf("ingress inspection should be allowed")
	}

	sanitized := ingressRes.SanitizedText
	if strings.Contains(sanitized, rawSecret) {
		t.Fatalf("sanitized payload still contains raw plaintext API key: %s", sanitized)
	}
	if strings.Contains(sanitized, customerEmail) {
		t.Fatalf("sanitized payload still contains raw email: %s", sanitized)
	}
	if !strings.Contains(sanitized, "[[VAULT:API_KEY:") {
		t.Fatalf("sanitized payload missing vault token for API key: %s", sanitized)
	}
	if !strings.Contains(sanitized, "[[VAULT:EMAIL:") {
		t.Fatalf("sanitized payload missing vault token for email: %s", sanitized)
	}

	// 2. Egress Detokenization: Right before upstream dispatch, gateway restores exact plaintext
	upstreamPayload, restoredCount := dlp.DetokenizeEgress(sanitized, agentID)
	if restoredCount != 2 {
		t.Fatalf("expected 2 detokenized secrets, got %d", restoredCount)
	}
	if !strings.Contains(upstreamPayload, rawSecret) {
		t.Fatalf("restored upstream payload missing original API key")
	}
	if !strings.Contains(upstreamPayload, customerEmail) {
		t.Fatalf("restored upstream payload missing original email")
	}
}

func TestVault_CrossAgentIsolation(t *testing.T) {
	dlp := redact.NewDLPController(redact.DefaultDLPConfig())

	secret := "ghp_11223344556677889900aabbccddeeff1122"
	resAlice := dlp.InspectAndSanitize("Secret is "+secret, "agent-alice", rbac.RoleAdmin)
	tokenAlice := resAlice.TokensCreated[0]

	// Malicious or confused agent-bob tries to pass Alice's token to detokenize
	payloadBob := "Executing tool with token: " + tokenAlice
	detokBob, countBob := dlp.DetokenizeEgress(payloadBob, "agent-bob")

	if countBob != 0 {
		t.Fatalf("cross-tenant detokenization must be blocked! count=%d", countBob)
	}
	if strings.Contains(detokBob, secret) {
		t.Fatalf("agent-bob exfiltrated agent-alice's secret: %s", detokBob)
	}

	// Alice can detokenize successfully
	detokAlice, countAlice := dlp.DetokenizeEgress(payloadBob, "agent-alice")
	if countAlice != 1 || !strings.Contains(detokAlice, secret) {
		t.Fatalf("alice failed to detokenize her own secret")
	}
}

func TestVault_DLPScenarios(t *testing.T) {
	dlp := redact.NewDLPController(redact.DefaultDLPConfig())
	scenarios := redact.DefaultDemoScenarios()

	for i, sc := range scenarios {
		res := dlp.InspectAndSanitize(sc.Payload, sc.AgentID, sc.Role)

		switch sc.Role {
		case rbac.RoleReadOnly:
			if res.Allowed {
				t.Fatalf("scenario %d (%s) expected to be BLOCKED for read-only role", i+1, sc.Name)
			}
		case rbac.RoleRestricted:
			if !res.Allowed {
				t.Fatalf("scenario %d (%s) expected to be ALLOWED with MASK for restricted role", i+1, sc.Name)
			}
			if len(res.TokensCreated) > 0 {
				t.Fatalf("scenario %d restricted role should not create reversible vault tokens", i+1)
			}
		default:
			if !res.Allowed {
				t.Fatalf("scenario %d (%s) should be ALLOWED", i+1, sc.Name)
			}
		}

		scorecard := redact.RenderDLPScorecard(res, sc.AgentID, redact.DLPActionVault)
		if len(scorecard) == 0 {
			t.Fatalf("scorecard rendering returned empty string")
		}
	}
}

func TestVault_TTL_Purge(t *testing.T) {
	cfg := redact.DefaultDLPConfig()
	cfg.VaultTTL = 15 * time.Millisecond
	dlp := redact.NewDLPController(cfg)

	_ = dlp.InspectAndSanitize("API Key sk-ant-1122334455667788990011223344556677", "agent-purge", rbac.RoleStandard)

	vault := dlp.GetVault()
	if vault.GetStats().ActiveTokens != 1 {
		t.Fatalf("expected 1 active token in vault")
	}

	// Wait for expiration
	time.Sleep(25 * time.Millisecond)

	purged := vault.PurgeExpired()
	if purged != 1 {
		t.Fatalf("expected 1 purged token, got %d", purged)
	}
	if vault.GetStats().ActiveTokens != 0 {
		t.Fatalf("expected 0 active tokens after purge")
	}
}
