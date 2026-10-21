package honeypot

import (
	"strings"
	"sync"
	"testing"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

func TestInjectToolsList(t *testing.T) {
	cfg := HoneypotConfig{Enabled: true}
	engine := NewEngine(cfg)

	realTools := []map[string]interface{}{
		{"name": "read_file", "description": "Reads a file"},
		{"name": "write_file", "description": "Writes a file"},
	}

	injected := engine.InjectToolsList(realTools)
	if len(injected) <= len(realTools) {
		t.Fatalf("expected injected tools list to be larger than real tools, got %d", len(injected))
	}

	foundVault := false
	for _, tool := range injected {
		if tool["name"] == "admin_export_vault_credentials" {
			foundVault = true
			break
		}
	}
	if !foundVault {
		t.Errorf("expected canary tool 'admin_export_vault_credentials' in injected tools")
	}
}

func TestDecoyToolHoneyedPayload(t *testing.T) {
	cfg := HoneypotConfig{
		Enabled:               true,
		AutoQuarantineSession: true,
	}
	engine := NewEngine(cfg)

	sessionID := "sess-test-01"
	agentID := "agent-attacker"
	verdict := engine.InterceptToolCall(sessionID, agentID, rbac.RoleStandard, "admin_export_vault_credentials", map[string]interface{}{
		"vault_path": "secret/prod",
	})

	if verdict.Allowed {
		t.Errorf("expected honeypot decoy call to NOT be allowed")
	}
	if !verdict.IsHoneypotHit {
		t.Errorf("expected IsHoneypotHit to be true")
	}
	if !verdict.SessionLocked {
		t.Errorf("expected SessionLocked to be true")
	}
	if verdict.DeceptionMode != ModeHoneyedPayload {
		t.Errorf("expected DeceptionMode HoneyedPayload, got %v", verdict.DeceptionMode)
	}
	if !strings.Contains(verdict.SpoofedPayload, "AKIA_DECOY_CANARY_PROD") {
		t.Errorf("expected spoofed payload to contain canary credentials, got %s", verdict.SpoofedPayload)
	}

	// Verify session is quarantined on subsequent benign call
	followUp := engine.InterceptToolCall(sessionID, agentID, rbac.RoleStandard, "read_file", map[string]interface{}{
		"path": "test.txt",
	})
	if followUp.Allowed {
		t.Errorf("expected subsequent call in quarantined session to be blocked")
	}
	if !followUp.SessionLocked {
		t.Errorf("expected follow-up to indicate SessionLocked")
	}
}

func TestDecoyToolSyntheticError(t *testing.T) {
	cfg := HoneypotConfig{
		Enabled:               true,
		AutoQuarantineSession: false,
	}
	engine := NewEngine(cfg)

	verdict := engine.InterceptToolCall("sess-02", "agent-probe", rbac.RoleStandard, "system_debug_eval_raw", map[string]interface{}{
		"command": "whoami",
	})

	if verdict.Allowed {
		t.Errorf("expected decoy tool call to be blocked")
	}
	if verdict.DeceptionMode != ModeSyntheticError {
		t.Errorf("expected ModeSyntheticError, got %v", verdict.DeceptionMode)
	}
	if !strings.Contains(verdict.SpoofedError, "DEBUG_DAEMON_ERROR") {
		t.Errorf("expected synthetic error message, got %s", verdict.SpoofedError)
	}
}

func TestCanaryTokenDetectionInNestedArgs(t *testing.T) {
	cfg := HoneypotConfig{
		Enabled:               true,
		AutoQuarantineSession: true,
		CanaryTokens:          []string{"custom_canary_leak_token_123"},
	}
	engine := NewEngine(cfg)

	nestedArgs := map[string]interface{}{
		"options": map[string]interface{}{
			"headers": []interface{}{
				"Authorization: Bearer custom_canary_leak_token_123",
			},
		},
	}

	verdict := engine.InterceptToolCall("sess-nested", "agent-exfil", rbac.RoleStandard, "http_request", nestedArgs)
	if verdict.Allowed {
		t.Errorf("expected tool call with canary token to be blocked")
	}
	if !verdict.IsHoneypotHit {
		t.Errorf("expected IsHoneypotHit to be true")
	}
	if verdict.TrapEvent == nil || verdict.TrapEvent.TrapType != "CANARY_TOKEN" {
		t.Errorf("expected TrapType CANARY_TOKEN, got %v", verdict.TrapEvent)
	}
}

func TestQuarantineRelease(t *testing.T) {
	cfg := HoneypotConfig{
		Enabled:               true,
		AutoQuarantineSession: true,
	}
	engine := NewEngine(cfg)

	sessionID := "sess-release-test"
	_ = engine.InterceptToolCall(sessionID, "agent-1", rbac.RoleStandard, "admin_export_vault_credentials", nil)

	if !engine.IsSessionQuarantined(sessionID) {
		t.Fatalf("expected session to be quarantined")
	}

	engine.ReleaseSession(sessionID)
	if engine.IsSessionQuarantined(sessionID) {
		t.Fatalf("expected session to be released from quarantine")
	}

	cleanVerdict := engine.InterceptToolCall(sessionID, "agent-1", rbac.RoleStandard, "read_file", map[string]interface{}{
		"path": "main.go",
	})
	if !cleanVerdict.Allowed {
		t.Errorf("expected clean tool call to be allowed after release")
	}
}

func TestConcurrency(t *testing.T) {
	cfg := HoneypotConfig{
		Enabled:               true,
		AutoQuarantineSession: true,
	}
	engine := NewEngine(cfg)

	var wg sync.WaitGroup
	workers := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sessID := "sess-concurrent"
			if id%2 == 0 {
				_ = engine.InterceptToolCall(sessID, "agent-worker", rbac.RoleStandard, "read_file", map[string]interface{}{"path": "file.txt"})
			} else {
				_ = engine.InterceptToolCall(sessID, "agent-worker", rbac.RoleStandard, "admin_export_vault_credentials", map[string]interface{}{"vault_path": "prod"})
			}
		}(i)
	}

	wg.Wait()
}

func TestDemoSuiteExecution(t *testing.T) {
	summary, verdicts, err := RunDemoSuite()
	if err != nil {
		t.Fatalf("RunDemoSuite failed: %v", err)
	}

	if summary.TotalEvaluated != len(GetDemoScenarios()) {
		t.Errorf("expected %d evaluated, got %d", len(GetDemoScenarios()), summary.TotalEvaluated)
	}
	if summary.TrapsTriggered != 3 {
		t.Errorf("expected 3 traps triggered, got %d", summary.TrapsTriggered)
	}
	if summary.CleanPassed != 1 {
		t.Errorf("expected 1 clean passed, got %d", summary.CleanPassed)
	}
	if len(verdicts) != len(GetDemoScenarios()) {
		t.Errorf("expected %d verdicts, got %d", len(GetDemoScenarios()), len(verdicts))
	}

	// Verify reports render without panic
	sc := RenderHoneypotScorecard(verdicts[0], "sess-adv-01", "agent-compromised-red", "admin_export_vault_credentials")
	if !strings.Contains(sc, "MCPGATE HONEYPOT") {
		t.Errorf("expected scorecard to contain title")
	}

	mermaid := RenderHoneypotMermaid(verdicts[0].TrapEvent)
	if !strings.Contains(mermaid, "sequenceDiagram") {
		t.Errorf("expected mermaid diagram to contain sequenceDiagram")
	}

	md := RenderMarkdownReport(summary)
	if !strings.Contains(md, "Honeypot & Adversarial Deception Report") {
		t.Errorf("expected markdown report to contain header")
	}

	jsonStr, err := summary.RenderJSON()
	if err != nil || !strings.Contains(jsonStr, "total_evaluated") {
		t.Errorf("expected valid JSON string, got err: %v", err)
	}
}
