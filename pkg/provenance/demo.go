package provenance

import (
	"crypto/ed25519"
	"time"
)

// DemoScenario represents a realistic multi-agent execution scenario for provenance auditing.
type DemoScenario struct {
	Name            string
	AgentID         string
	ToolName        string
	ArgumentsJSON   string
	ResponseJSON    string
	Verdict         string
	Duration        time.Duration
	TamperPayload   bool
	TamperSignature bool
	ReplayNonce     bool
	TamperSchema    bool
}

// GetDemoScenarios returns four battle-tested production scenarios for provenance evaluation.
func GetDemoScenarios() []DemoScenario {
	return []DemoScenario{
		{
			Name:          "Legitimate Authorized Tool Call (Zero-Trust Compliant)",
			AgentID:       "agent-analyst-alpha",
			ToolName:      "query_database",
			ArgumentsJSON: `{"query": "SELECT count(*) FROM transactions WHERE status='settled'", "limit": 100}`,
			ResponseJSON:  `{"result": [{"count": 482910}], "status": "success"}`,
			Verdict:       "ALLOWED",
			Duration:      12 * time.Millisecond,
		},
		{
			Name:          "Man-in-the-Middle Payload Tampering Attack",
			AgentID:       "agent-devops-worker",
			ToolName:      "deploy_container",
			ArgumentsJSON: `{"cluster": "prod-us-east", "image": "registry.corp.internal/app:v2.4.1"}`,
			ResponseJSON:  `{"error": "security_block", "reason": "payload_tampered"}`,
			Verdict:       "BLOCKED_SECURITY_GATEWAY",
			Duration:      3 * time.Millisecond,
			TamperPayload: true,
		},
		{
			Name:          "Cryptographic Replay Attack (Nonce Duplication)",
			AgentID:       "agent-analyst-alpha",
			ToolName:      "query_database",
			ArgumentsJSON: `{"query": "SELECT count(*) FROM transactions WHERE status='settled'", "limit": 100}`,
			ResponseJSON:  `{"error": "replay_attack", "reason": "nonce_already_used"}`,
			Verdict:       "BLOCKED_REPLAY_DETECTION",
			Duration:      2 * time.Millisecond,
			ReplayNonce:   true,
		},
		{
			Name:          "Upstream Tool Manifest Schema Poisoning (Trojan Injection)",
			AgentID:       "agent-qa-tester",
			ToolName:      "execute_sandbox",
			ArgumentsJSON: `{"command": "pytest -v tests/"}`,
			ResponseJSON:  `{"error": "upstream_compromise", "reason": "schema_tampered"}`,
			Verdict:       "BLOCKED_MANIFEST_VERIFICATION",
			Duration:      4 * time.Millisecond,
			TamperSchema:  true,
		},
	}
}

// SetupDemoEnvironment initializes a key registry and provenance engine primed with demo agent keys.
func SetupDemoEnvironment() (*ProvenanceEngine, map[string]ed25519.PrivateKey, error) {
	registry := NewKeyRegistry()
	agentPrivs := make(map[string]ed25519.PrivateKey)

	agents := []string{"agent-analyst-alpha", "agent-devops-worker", "agent-qa-tester"}
	for _, a := range agents {
		pub, priv, err := GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		registry.RegisterAgentKey(a, pub)
		agentPrivs[a] = priv
	}

	// Register upstream server
	serverPub, serverPriv, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	registry.RegisterServerKey("mcp-upstream-corp", serverPub)
	agentPrivs["mcp-upstream-corp"] = serverPriv

	pe, err := NewProvenanceEngine(DefaultProvenanceConfig(), registry, nil)
	if err != nil {
		return nil, nil, err
	}

	return pe, agentPrivs, nil
}
