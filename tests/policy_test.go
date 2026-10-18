package tests

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/policy"
	"github.com/Noooblien/mcpgate/pkg/rbac"
	"github.com/Noooblien/mcpgate/pkg/spec"
)

func TestPolicy_DefaultZeroTrust_AllowSafeReads(t *testing.T) {
	manifest := policy.DefaultZeroTrustPolicy()
	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	req := policy.PolicyRequest{
		AgentID:  "agent-reader-01",
		Role:     rbac.RoleStandard,
		ToolName: "read_file",
		Args: map[string]interface{}{
			"path": "pkg/policy/engine.go",
		},
	}

	dec := engine.Evaluate(req)
	if !dec.Allowed {
		t.Fatalf("expected read_file to be allowed, got: %+v", dec)
	}
	if dec.Action != policy.ActionAllow {
		t.Fatalf("expected ActionAllow, got %s", dec.Action)
	}
	if dec.MatchedRuleID != "rule-allow-safe-reads" {
		t.Fatalf("expected matched rule 'rule-allow-safe-reads', got %s", dec.MatchedRuleID)
	}
}

func TestPolicy_DefaultZeroTrust_BlockSSRF(t *testing.T) {
	manifest := policy.DefaultZeroTrustPolicy()
	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	ssrfTargets := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:8080/admin",
		"http://127.0.0.1:9090/metrics",
	}

	for _, url := range ssrfTargets {
		req := policy.PolicyRequest{
			AgentID:  "agent-crawler",
			Role:     rbac.RoleAdmin, // Even admin should be blocked by global SSRF rule
			ToolName: "fetch_url",
			Args: map[string]interface{}{
				"url": url,
			},
		}

		dec := engine.Evaluate(req)
		if dec.Allowed {
			t.Fatalf("expected SSRF url '%s' to be blocked, got allowed: %+v", url, dec)
		}
		if dec.Action != policy.ActionDeny {
			t.Fatalf("expected ActionDeny, got %s", dec.Action)
		}
		if dec.MatchedRuleID != "rule-global-deny-ssrf" {
			t.Fatalf("expected rule-global-deny-ssrf, got %s", dec.MatchedRuleID)
		}
	}
}

func TestPolicy_DefaultZeroTrust_BlockPathTraversal(t *testing.T) {
	manifest := policy.DefaultZeroTrustPolicy()
	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	maliciousPaths := []string{
		"../../etc/shadow",
		"/etc/passwd",
		"~/.ssh/id_rsa",
	}

	for _, path := range maliciousPaths {
		req := policy.PolicyRequest{
			AgentID:  "agent-file-scanner",
			Role:     rbac.RoleAdmin,
			ToolName: "read_file",
			Args: map[string]interface{}{
				"path": path,
			},
		}

		dec := engine.Evaluate(req)
		if dec.Allowed {
			t.Fatalf("expected path '%s' to be blocked, got allowed: %+v", path, dec)
		}
		if dec.MatchedRuleID != "rule-global-deny-traversal" {
			t.Fatalf("expected rule-global-deny-traversal, got %s", dec.MatchedRuleID)
		}
	}
}

func TestPolicy_DefaultZeroTrust_RequireApprovalForExec(t *testing.T) {
	manifest := policy.DefaultZeroTrustPolicy()
	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	req := policy.PolicyRequest{
		AgentID:  "agent-devops",
		Role:     rbac.RoleAdmin,
		ToolName: "execute_command",
		Args: map[string]interface{}{
			"command": "apt-get update && apt-get upgrade",
		},
	}

	dec := engine.Evaluate(req)
	if !dec.RequireApproval {
		t.Fatalf("expected RequireApproval true, got false")
	}
	if dec.Action != policy.ActionRequireApproval {
		t.Fatalf("expected ActionRequireApproval, got %s", dec.Action)
	}
	if dec.EffectiveRPM != 10 {
		t.Fatalf("expected custom RPM 10, got %d", dec.EffectiveRPM)
	}
}

func TestPolicy_DefaultZeroTrust_FallbackDefaultDeny(t *testing.T) {
	manifest := policy.DefaultZeroTrustPolicy()
	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	req := policy.PolicyRequest{
		AgentID:  "agent-untrusted",
		Role:     rbac.RoleRestricted,
		ToolName: "raw_kernel_ioctl",
		Args:     map[string]interface{}{},
	}

	dec := engine.Evaluate(req)
	if dec.Allowed {
		t.Fatalf("expected unregistered tool to be denied by zero-trust fallback, got allowed: %+v", dec)
	}
	if dec.MatchedRuleID != "DEFAULT_ACTION" {
		t.Fatalf("expected DEFAULT_ACTION, got %s", dec.MatchedRuleID)
	}
}

func TestPolicy_TemporalWindow(t *testing.T) {
	manifest := &policy.PolicyManifest{
		APIVersion:    "mcpgate.io/v1",
		Kind:          "SecurityPolicy",
		DefaultAction: policy.ActionDeny,
		Rules: []policy.PolicyRule{
			{
				ID:           "temporal-business-hours-only",
				Name:         "Business Hours Only",
				Priority:     10,
				AgentPattern: "*",
				Roles:        []rbac.AgentRole{rbac.RoleStandard},
				ToolPattern:  "send_payment",
				Temporal: &policy.TemporalWindow{
					Enabled:   true,
					StartHour: 9,
					EndHour:   17,
					Timezone:  "UTC",
				},
				Action: policy.ActionAllow,
			},
		},
	}

	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	// Case 1: Inside business hours (14:00 UTC)
	validTime := time.Date(2026, 10, 19, 14, 0, 0, 0, time.UTC) // Monday
	reqValid := policy.PolicyRequest{
		AgentID:   "finance-agent",
		Role:      rbac.RoleStandard,
		ToolName:  "send_payment",
		Timestamp: validTime,
	}
	decValid := engine.Evaluate(reqValid)
	if !decValid.Allowed {
		t.Fatalf("expected inside business hours to be allowed, got denied: %+v", decValid)
	}

	// Case 2: Outside business hours (22:00 UTC)
	invalidTime := time.Date(2026, 10, 19, 22, 0, 0, 0, time.UTC)
	reqInvalid := policy.PolicyRequest{
		AgentID:   "finance-agent",
		Role:      rbac.RoleStandard,
		ToolName:  "send_payment",
		Timestamp: invalidTime,
	}
	decInvalid := engine.Evaluate(reqInvalid)
	if decInvalid.Allowed {
		t.Fatalf("expected 22:00 UTC to be denied, got allowed: %+v", decInvalid)
	}
	if len(decInvalid.Violations) == 0 || decInvalid.Violations[0] != "TEMPORAL_HOUR_VIOLATION" {
		t.Fatalf("expected TEMPORAL_HOUR_VIOLATION, got: %v", decInvalid.Violations)
	}
}

func TestPolicy_HotReload(t *testing.T) {
	manifest := &policy.PolicyManifest{
		APIVersion:    "mcpgate.io/v1",
		Kind:          "SecurityPolicy",
		DefaultAction: policy.ActionDeny,
		Rules: []policy.PolicyRule{
			{
				ID:           "rule-init-deny",
				Name:         "Initial Deny",
				Priority:     1,
				AgentPattern: "*",
				ToolPattern:  "custom_tool",
				Action:       policy.ActionDeny,
			},
		},
	}

	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	req := policy.PolicyRequest{
		AgentID:  "agent-1",
		Role:     rbac.RoleStandard,
		ToolName: "custom_tool",
	}

	if engine.Evaluate(req).Allowed {
		t.Fatalf("expected initial rule to deny")
	}

	// Hot reload with updated manifest allowing custom_tool
	updatedManifest := &policy.PolicyManifest{
		APIVersion:    "mcpgate.io/v1",
		Kind:          "SecurityPolicy",
		DefaultAction: policy.ActionDeny,
		Rules: []policy.PolicyRule{
			{
				ID:           "rule-allow-custom",
				Name:         "Allow Custom",
				Priority:     10,
				AgentPattern: "*",
				ToolPattern:  "custom_tool",
				Action:       policy.ActionAllow,
			},
		},
	}

	if err := engine.UpdateManifest(updatedManifest); err != nil {
		t.Fatalf("failed to update manifest: %v", err)
	}

	if !engine.Evaluate(req).Allowed {
		t.Fatalf("expected hot-reloaded policy to allow custom_tool")
	}
}

func TestPolicy_LinterAndValidation(t *testing.T) {
	// Valid manifest
	validManifest := policy.DefaultZeroTrustPolicy()
	errs := policy.Validate(validManifest)
	if len(errs) > 0 {
		t.Fatalf("expected zero validation errors for default policy, got: %v", errs)
	}

	// Broken manifest
	brokenManifest := &policy.PolicyManifest{
		APIVersion: "wrong-api-version",
		Kind:       "WrongKind",
		Rules: []policy.PolicyRule{
			{
				ID:           "",
				ToolPattern:  "",
				AgentPattern: "[invalid-regex(",
				ArgConstraints: []policy.ArgConstraint{
					{
						FieldName:        "",
						ForbiddenPattern: "(unclosed-regex",
					},
				},
			},
		},
	}

	brokenErrs := policy.Validate(brokenManifest)
	if len(brokenErrs) < 5 {
		t.Fatalf("expected multiple validation errors, got %d: %v", len(brokenErrs), brokenErrs)
	}
}

func TestPolicy_GatewayIntegration(t *testing.T) {
	manifest := policy.DefaultZeroTrustPolicy()
	pe, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init policy engine: %v", err)
	}

	gate, err := gateway.NewMCPGate(gateway.GatewayConfig{
		HMACSeed:     "test-seed",
		MaxRPM:       100,
		BurstSize:    20,
		AuditLogPath: t.TempDir() + "/audit.jsonl",
		PolicyEngine: pe,
	})
	if err != nil {
		t.Fatalf("failed to create MCPGate: %v", err)
	}

	// 1. Allowed request
	v1 := gate.InterceptToolCall("agent-1", rbac.RoleStandard, "read_file", map[string]interface{}{
		"path": "pkg/policy/types.go",
	})
	if !v1.Allowed {
		t.Fatalf("expected allowed tool call, got blocked: %s", v1.BlockReason)
	}
	if v1.PolicyDecision == nil || v1.PolicyDecision.MatchedRuleID != "rule-allow-safe-reads" {
		t.Fatalf("expected policy decision rule-allow-safe-reads, got %+v", v1.PolicyDecision)
	}

	// 2. Blocked SSRF request
	v2 := gate.InterceptToolCall("agent-1", rbac.RoleAdmin, "fetch_url", map[string]interface{}{
		"url": "http://169.254.169.254/latest/meta-data/",
	})
	if v2.Allowed {
		t.Fatalf("expected SSRF tool call to be blocked, got allowed")
	}
	if v2.Verdict != spec.VerdictBlock {
		t.Fatalf("expected VerdictBlock, got %s", v2.Verdict)
	}

	// 3. Approval Gated Request
	v3 := gate.InterceptToolCall("agent-1", rbac.RoleStandard, "execute_command", map[string]interface{}{
		"command": "reboot",
	})
	if v3.Allowed {
		t.Fatalf("expected execute_command to be gated for approval, got allowed")
	}
	if v3.Verdict != spec.VerdictAudit {
		t.Fatalf("expected VerdictAudit for approval gate, got %s", v3.Verdict)
	}
}

func TestPolicy_ScorecardAndMermaid(t *testing.T) {
	manifest := policy.DefaultZeroTrustPolicy()
	engine, err := policy.NewEngine(manifest)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	req := policy.PolicyRequest{
		AgentID:  "agent-demo",
		Role:     rbac.RoleStandard,
		ToolName: "read_file",
		Args: map[string]interface{}{
			"path": "main.go",
		},
	}
	dec := engine.Evaluate(req)

	scorecard := policy.RenderPolicyScorecard(dec, req)
	if !strings.Contains(scorecard, "MCPGate Declarative Security Policy Evaluation") {
		t.Fatalf("scorecard missing header: %s", scorecard)
	}
	if !strings.Contains(scorecard, "[ALLOWED]") {
		t.Fatalf("scorecard missing allowed badge: %s", scorecard)
	}

	mermaid := policy.RenderPolicyMermaid(manifest)
	if !strings.Contains(mermaid, "flowchart TD") {
		t.Fatalf("mermaid missing flowchart TD header: %s", mermaid)
	}
	if !strings.Contains(mermaid, "DEFAULT ACTION: DENY") {
		t.Fatalf("mermaid missing default action node: %s", mermaid)
	}

	// JSON unmarshal check on DefaultZeroTrustPolicy
	b, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal policy to JSON: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("empty json bytes")
	}
}
