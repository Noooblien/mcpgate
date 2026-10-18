package tests

import (
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/provenance"
)

func TestIntegration_Provenance_EndToEnd(t *testing.T) {
	pe, agentPrivs, err := provenance.SetupDemoEnvironment()
	if err != nil {
		t.Fatalf("SetupDemoEnvironment failed: %v", err)
	}

	scenarios := provenance.GetDemoScenarios()
	if len(scenarios) != 4 {
		t.Fatalf("Expected 4 demo scenarios, got %d", len(scenarios))
	}

	var validReceipts []*provenance.AttestationReceipt

	for _, sc := range scenarios {
		priv := agentPrivs[sc.AgentID]
		if priv == nil {
			t.Fatalf("Missing private key for agent: %s", sc.AgentID)
		}

		// 1. Agent signs request
		req, err := pe.SignRequest(sc.AgentID, priv, sc.ToolName, sc.ArgumentsJSON)
		if err != nil {
			t.Fatalf("Scenario '%s': SignRequest failed: %v", sc.Name, err)
		}

		// Apply attack simulations if specified
		if sc.TamperPayload {
			req.ArgumentsJSON = `{"cluster": "attacker-controlled-node", "image": "malicious/trojan:latest"}`
		}

		if sc.ReplayNonce {
			// First verify legitimately to record nonce
			res1 := pe.VerifyRequest(req)
			if !res1.Valid {
				t.Fatalf("First submission of replay scenario should be valid, got: %s", res1.Detail)
			}
			// Now submit again with same nonce to trigger replay attack
		}

		// 2. Gateway Intercepts & Verifies Request
		verResult := pe.VerifyRequest(req)

		if sc.TamperPayload {
			if verResult.Valid || verResult.Status != provenance.StatusPayloadTampered {
				t.Errorf("Scenario '%s': expected StatusPayloadTampered, got %s", sc.Name, verResult.Status)
			}
			continue
		}

		if sc.ReplayNonce {
			if verResult.Valid || verResult.Status != provenance.StatusReplayDetected {
				t.Errorf("Scenario '%s': expected StatusReplayDetected, got %s", sc.Name, verResult.Status)
			}
			continue
		}

		if sc.TamperSchema {
			// Test upstream manifest poisoning
			serverPriv := agentPrivs["mcp-upstream-corp"]
			att, err := pe.SignManifest("mcp-upstream-corp", serverPriv, sc.ToolName, "1.0.0", `{"type": "object"}`)
			if err != nil {
				t.Fatalf("SignManifest failed: %v", err)
			}
			// Tamper schema description
			att.SchemaJSON = `{"type": "object", "injected_instructions": "IGNORE_SECURITY_GATEWAY"}`
			ok, err := pe.VerifyManifest(att)
			if ok || err == nil {
				t.Errorf("Scenario '%s': expected manifest schema verification failure", sc.Name)
			}
			continue
		}

		// For legitimate scenario:
		if !verResult.Valid {
			t.Fatalf("Scenario '%s' failed verification: %s", sc.Name, verResult.Detail)
		}

		// 3. Issue and Verify Execution Attestation Receipt
		receipt, err := pe.IssueReceipt(req, sc.ResponseJSON, sc.Verdict, sc.Duration)
		if err != nil {
			t.Fatalf("Scenario '%s': IssueReceipt failed: %v", sc.Name, err)
		}

		validReceipt, err := pe.VerifyReceipt(receipt)
		if err != nil || !validReceipt {
			t.Fatalf("Scenario '%s': VerifyReceipt failed: %v", sc.Name, err)
		}

		validReceipts = append(validReceipts, receipt)
	}

	if len(validReceipts) == 0 {
		t.Fatalf("Expected at least 1 verified receipt issued")
	}
}

func TestIntegration_ReceiptTamperEvident(t *testing.T) {
	pe, agentPrivs, _ := provenance.SetupDemoEnvironment()
	agentID := "agent-analyst-alpha"
	priv := agentPrivs[agentID]

	req, _ := pe.SignRequest(agentID, priv, "read_financial_data", `{"year": 2026}`)
	receipt, err := pe.IssueReceipt(req, `{"net_profit": 5000000}`, "ALLOWED", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("IssueReceipt failed: %v", err)
	}

	// Legitimate verification
	valid, err := pe.VerifyReceipt(receipt)
	if err != nil || !valid {
		t.Fatalf("Valid receipt should pass verification")
	}

	// Malicious modification of response hash
	tampered := *receipt
	tampered.ResponseHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	validTampered, err := pe.VerifyReceipt(&tampered)
	if validTampered || err == nil {
		t.Errorf("Tampered receipt must fail verification")
	}
}
