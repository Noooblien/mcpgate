package provenance

import (
	"strings"
	"testing"
	"time"
)

func TestKeyPairGenerationAndRegistry(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(pub) != 32 || len(priv) != 64 {
		t.Errorf("Invalid key sizes: pub=%d, priv=%d", len(pub), len(priv))
	}

	pubHex, privHex, err := GenerateKeyPairHex()
	if err != nil {
		t.Fatalf("GenerateKeyPairHex failed: %v", err)
	}

	reg := NewKeyRegistry()
	if err := reg.RegisterAgentKeyHex("agent-1", pubHex); err != nil {
		t.Fatalf("RegisterAgentKeyHex failed: %v", err)
	}

	retrieved, exists := reg.GetAgentKey("agent-1")
	if !exists || len(retrieved) != 32 {
		t.Fatalf("Failed to retrieve registered key for agent-1")
	}

	// Revocation
	reg.RevokeKey("agent-1")
	_, existsAfterRevocation := reg.GetAgentKey("agent-1")
	if existsAfterRevocation {
		t.Errorf("Expected agent-1 to be revoked")
	}
	_ = privHex
}

func TestRequestSigningAndVerification(t *testing.T) {
	pe, agentPrivs, err := SetupDemoEnvironment()
	if err != nil {
		t.Fatalf("SetupDemoEnvironment failed: %v", err)
	}

	agentID := "agent-analyst-alpha"
	priv := agentPrivs[agentID]

	// 1. Valid signature and verification
	req, err := pe.SignRequest(agentID, priv, "query_db", `{"limit": 50}`)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	res := pe.VerifyRequest(req)
	if !res.Valid || res.Status != StatusVerified {
		t.Fatalf("Expected valid verification, got %s: %s", res.Status, res.Detail)
	}
	if !res.ArgumentsVerified || !res.SignatureVerified {
		t.Errorf("Expected both arguments and signature to be verified")
	}

	// 2. Tampered Payload detection
	reqTampered, err := pe.SignRequest(agentID, priv, "query_db", `{"limit": 50}`)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}
	reqTampered.ArgumentsJSON = `{"limit": 999999}` // Modified arguments in-transit

	resTampered := pe.VerifyRequest(reqTampered)
	if resTampered.Valid || resTampered.Status != StatusPayloadTampered {
		t.Errorf("Expected StatusPayloadTampered, got %s", resTampered.Status)
	}

	// 3. Replay Attack detection
	resReplay := pe.VerifyRequest(req) // Submit identical req again with same nonce
	if resReplay.Valid || resReplay.Status != StatusReplayDetected {
		t.Errorf("Expected StatusReplayDetected, got %s", resReplay.Status)
	}

	// 4. Clock Skew Exceeded
	reqExpired, err := pe.SignRequest(agentID, priv, "query_db", `{"limit": 10}`)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}
	reqExpired.Timestamp = time.Now().UTC().Add(-2 * time.Hour) // 2 hours in the past
	resExpired := pe.VerifyRequest(reqExpired)
	if resExpired.Valid || resExpired.Status != StatusClockSkewExceeded {
		t.Errorf("Expected StatusClockSkewExceeded, got %s", resExpired.Status)
	}

	// 5. Unknown Agent Key
	_, unknownPriv, _ := GenerateKeyPair()
	reqUnknown, err := pe.SignRequest("agent-unknown-rogue", unknownPriv, "query_db", `{"limit": 10}`)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}
	resUnknown := pe.VerifyRequest(reqUnknown)
	if resUnknown.Valid || resUnknown.Status != StatusUnknownAgentKey {
		t.Errorf("Expected StatusUnknownAgentKey, got %s", resUnknown.Status)
	}
}

func TestManifestSigningAndVerification(t *testing.T) {
	pe, agentPrivs, err := SetupDemoEnvironment()
	if err != nil {
		t.Fatalf("SetupDemoEnvironment failed: %v", err)
	}

	serverID := "mcp-upstream-corp"
	priv := agentPrivs[serverID]

	// 1. Valid manifest
	manifest, err := pe.SignManifest(serverID, priv, "search_docs", "1.0.0", `{"type": "object", "properties": {"q": {"type": "string"}}}`)
	if err != nil {
		t.Fatalf("SignManifest failed: %v", err)
	}

	ok, err := pe.VerifyManifest(manifest)
	if err != nil || !ok {
		t.Fatalf("Expected valid manifest verification, got %v (err: %v)", ok, err)
	}

	// 2. Tampered schema
	manifestTampered := *manifest
	manifestTampered.SchemaJSON = `{"type": "object", "properties": {"poisoned_instruction": {"type": "string"}}}`
	okTampered, err := pe.VerifyManifest(&manifestTampered)
	if okTampered || err == nil {
		t.Errorf("Expected failure for tampered schema manifest")
	}
}

func TestGatewayReceiptIssuanceAndVerification(t *testing.T) {
	pe, agentPrivs, err := SetupDemoEnvironment()
	if err != nil {
		t.Fatalf("SetupDemoEnvironment failed: %v", err)
	}

	agentID := "agent-analyst-alpha"
	priv := agentPrivs[agentID]

	req, _ := pe.SignRequest(agentID, priv, "exec_query", `{"limit": 25}`)
	receipt, err := pe.IssueReceipt(req, `{"rows": 25}`, "ALLOWED", 1500*time.Microsecond)
	if err != nil {
		t.Fatalf("IssueReceipt failed: %v", err)
	}

	valid, err := pe.VerifyReceipt(receipt)
	if err != nil || !valid {
		t.Fatalf("VerifyReceipt failed: %v (valid=%v)", err, valid)
	}

	// Tampered receipt detection
	receiptTampered := *receipt
	receiptTampered.Verdict = "TAMPERED_VERDICT"
	validTampered, err := pe.VerifyReceipt(&receiptTampered)
	if validTampered || err == nil {
		t.Errorf("Expected verification failure on tampered receipt")
	}
}

func TestScorecardsAndRenderers(t *testing.T) {
	pe, agentPrivs, err := SetupDemoEnvironment()
	if err != nil {
		t.Fatalf("SetupDemoEnvironment failed: %v", err)
	}

	agentID := "agent-analyst-alpha"
	priv := agentPrivs[agentID]

	req, _ := pe.SignRequest(agentID, priv, "run_task", `{"task": "audit"}`)
	res := pe.VerifyRequest(req)
	rec, _ := pe.IssueReceipt(req, `{"status": "ok"}`, "ALLOWED", 2*time.Millisecond)

	scorecard := RenderProvenanceScorecard(res, rec)
	if !strings.Contains(scorecard, "CRYPTOGRAPHIC TOOL PROVENANCE") {
		t.Errorf("Scorecard missing header")
	}

	mermaid := RenderProvenanceMermaid(rec)
	if !strings.Contains(mermaid, "sequenceDiagram") {
		t.Errorf("Mermaid missing sequenceDiagram")
	}

	proof := &AuditProof{
		Receipt:      rec,
		Request:      req,
		Verification: res,
	}

	jsonStr, err := proof.ToJSON()
	if err != nil || !strings.Contains(jsonStr, "receipt_id") {
		t.Errorf("ToJSON failed: %v", err)
	}

	md := RenderMarkdownReport([]*AuditProof{proof})
	if !strings.Contains(md, "Executive Summary") {
		t.Errorf("Markdown report missing Executive Summary")
	}
}
