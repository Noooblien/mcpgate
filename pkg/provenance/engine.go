package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

// ProvenanceEngine coordinates cryptographic verification, non-repudiation, and receipt issuance.
type ProvenanceEngine struct {
	Config     ProvenanceConfig
	Registry   *KeyRegistry
	gatewayPub ed25519.PublicKey
	gatewayPriv ed25519.PrivateKey
	seenNonces map[string]time.Time
	mu         sync.RWMutex
}

// NewProvenanceEngine initializes the provenance and attestation engine.
func NewProvenanceEngine(cfg ProvenanceConfig, registry *KeyRegistry, gatewayPriv ed25519.PrivateKey) (*ProvenanceEngine, error) {
	if registry == nil {
		registry = NewKeyRegistry()
	}

	var gatewayPub ed25519.PublicKey
	if gatewayPriv != nil {
		gatewayPub = gatewayPriv.Public().(ed25519.PublicKey)
	} else {
		// Generate an ephemeral keypair for the gateway if not provided
		pub, priv, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		gatewayPub = pub
		gatewayPriv = priv
	}

	return &ProvenanceEngine{
		Config:      cfg,
		Registry:    registry,
		gatewayPub:  gatewayPub,
		gatewayPriv: gatewayPriv,
		seenNonces:  make(map[string]time.Time),
	}, nil
}

// GetGatewayPublicKeyHex returns the hex-encoded public key of the gateway.
func (pe *ProvenanceEngine) GetGatewayPublicKeyHex() string {
	return hex.EncodeToString(pe.gatewayPub)
}

// ComputeHash returns the lowercase hex-encoded SHA-256 digest of input bytes.
func ComputeHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// CanonicalizeJSON formats a JSON string into a deterministic canonical representation.
func CanonicalizeJSON(rawJSON string) (string, error) {
	var val interface{}
	if err := json.Unmarshal([]byte(rawJSON), &val); err != nil {
		return "", fmt.Errorf("invalid json: %w", err)
	}
	canonicalBytes, err := json.Marshal(val)
	if err != nil {
		return "", err
	}
	return string(canonicalBytes), nil
}

// CanonicalRequestString builds the deterministic signing string for a tool request.
func CanonicalRequestString(req *SignedToolRequest) string {
	return fmt.Sprintf("v1:agent_req:%s:%s:%s:%d:%s:%s",
		req.AgentID,
		req.RequestID,
		req.ToolName,
		req.Timestamp.Unix(),
		req.Nonce,
		req.ArgumentsHash,
	)
}

// CanonicalManifestString builds the deterministic signing string for a tool schema manifest.
func CanonicalManifestString(att *ToolManifestAttestation) string {
	return fmt.Sprintf("v1:tool_manifest:%s:%s:%s:%d:%s",
		att.ServerID,
		att.ToolName,
		att.Version,
		att.Timestamp.Unix(),
		att.SchemaDigest,
	)
}

// CanonicalReceiptString builds the deterministic signing string for an execution receipt.
func CanonicalReceiptString(rec *AttestationReceipt) string {
	return fmt.Sprintf("v1:gw_receipt:%s:%s:%s:%s:%s:%s:%s:%s:%s:%d:%s",
		rec.ReceiptID,
		rec.RequestID,
		rec.GatewayID,
		rec.AgentID,
		rec.ToolName,
		rec.ArgumentsHash,
		rec.ResponseHash,
		rec.Verdict,
		rec.Status,
		rec.Timestamp.Unix(),
		rec.Nonce,
	)
}

// SignRequest allows an agent to cryptographically sign a tool call invocation.
func (pe *ProvenanceEngine) SignRequest(agentID string, privKey ed25519.PrivateKey, toolName string, argumentsJSON string) (*SignedToolRequest, error) {
	canonicalArgs, err := CanonicalizeJSON(argumentsJSON)
	if err != nil {
		canonicalArgs = argumentsJSON
	}

	argsHash := ComputeHash([]byte(canonicalArgs))
	nonce := generateNonce()
	reqID := fmt.Sprintf("req_%s", nonce[:12])
	now := time.Now().UTC()

	req := &SignedToolRequest{
		RequestID:     reqID,
		AgentID:       agentID,
		ToolName:      toolName,
		Timestamp:     now,
		Nonce:         nonce,
		ArgumentsJSON: argumentsJSON,
		ArgumentsHash: argsHash,
	}

	canonicalStr := CanonicalRequestString(req)
	sig := ed25519.Sign(privKey, []byte(canonicalStr))
	req.SignatureHex = hex.EncodeToString(sig)

	return req, nil
}

// VerifyRequest authenticates an incoming signed tool request against registered agent public keys.
func (pe *ProvenanceEngine) VerifyRequest(req *SignedToolRequest) *VerificationResult {
	res := &VerificationResult{
		AgentID:  req.AgentID,
		ToolName: req.ToolName,
	}

	now := time.Now().UTC()
	drift := now.Sub(req.Timestamp)
	res.TimestampDrift = drift

	// 1. Clock skew check
	if math.Abs(drift.Seconds()) > pe.Config.MaxClockSkew.Seconds() {
		res.Valid = false
		res.Status = StatusClockSkewExceeded
		res.Detail = fmt.Sprintf("Timestamp drift %.1fs exceeds tolerance of %.1fs",
			drift.Seconds(), pe.Config.MaxClockSkew.Seconds())
		return res
	}

	// 2. Replay attack check
	pe.mu.Lock()
	pe.cleanupNonces(now)
	if _, exists := pe.seenNonces[req.Nonce]; exists {
		pe.mu.Unlock()
		res.Valid = false
		res.Status = StatusReplayDetected
		res.Detail = fmt.Sprintf("Cryptographic nonce '%s' has already been processed", req.Nonce)
		return res
	}
	pe.seenNonces[req.Nonce] = now
	pe.mu.Unlock()

	// 3. Arguments payload hash check
	canonicalArgs, err := CanonicalizeJSON(req.ArgumentsJSON)
	if err != nil {
		canonicalArgs = req.ArgumentsJSON
	}
	computedHash := ComputeHash([]byte(canonicalArgs))
	if computedHash != req.ArgumentsHash {
		res.Valid = false
		res.Status = StatusPayloadTampered
		res.Detail = fmt.Sprintf("Computed hash (%s) does not match declared hash (%s)",
			computedHash, req.ArgumentsHash)
		return res
	}
	res.ArgumentsVerified = true

	// 4. Agent Public Key Lookup
	pubKey, exists := pe.Registry.GetAgentKey(req.AgentID)
	if !exists {
		res.Valid = false
		res.Status = StatusUnknownAgentKey
		res.Detail = fmt.Sprintf("Agent ID '%s' has no valid registered Ed25519 public key", req.AgentID)
		return res
	}

	// 5. Ed25519 Signature Verification
	sigBytes, err := hex.DecodeString(req.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		res.Valid = false
		res.Status = StatusInvalidSignature
		res.Detail = "Signature is malformed or invalid size"
		return res
	}

	canonicalStr := CanonicalRequestString(req)
	if !ed25519.Verify(pubKey, []byte(canonicalStr), sigBytes) {
		res.Valid = false
		res.Status = StatusInvalidSignature
		res.Detail = "Cryptographic signature verification failed; request content was modified or forged"
		return res
	}

	res.SignatureVerified = true
	res.Valid = true
	res.Status = StatusVerified
	res.Detail = "Cryptographic signature and payload integrity verified successfully"

	return res
}

// SignManifest creates an attestation token for an upstream MCP tool schema.
func (pe *ProvenanceEngine) SignManifest(serverID string, privKey ed25519.PrivateKey, toolName string, version string, schemaJSON string) (*ToolManifestAttestation, error) {
	canonicalSchema, err := CanonicalizeJSON(schemaJSON)
	if err != nil {
		canonicalSchema = schemaJSON
	}

	digest := ComputeHash([]byte(canonicalSchema))
	att := &ToolManifestAttestation{
		ServerID:     serverID,
		ToolName:     toolName,
		Version:      version,
		SchemaJSON:   schemaJSON,
		SchemaDigest: digest,
		Timestamp:    time.Now().UTC(),
	}

	canonicalStr := CanonicalManifestString(att)
	sig := ed25519.Sign(privKey, []byte(canonicalStr))
	att.SignatureHex = hex.EncodeToString(sig)

	return att, nil
}

// VerifyManifest checks an upstream MCP server's schema attestation signature.
func (pe *ProvenanceEngine) VerifyManifest(att *ToolManifestAttestation) (bool, error) {
	pubKey, exists := pe.Registry.GetServerKey(att.ServerID)
	if !exists {
		return false, fmt.Errorf("unknown server key for server ID '%s'", att.ServerID)
	}

	canonicalSchema, err := CanonicalizeJSON(att.SchemaJSON)
	if err != nil {
		canonicalSchema = att.SchemaJSON
	}
	digest := ComputeHash([]byte(canonicalSchema))
	if digest != att.SchemaDigest {
		return false, fmt.Errorf("schema digest mismatch: computed %s, declared %s", digest, att.SchemaDigest)
	}

	sigBytes, err := hex.DecodeString(att.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid manifest signature bytes")
	}

	canonicalStr := CanonicalManifestString(att)
	if !ed25519.Verify(pubKey, []byte(canonicalStr), sigBytes) {
		return false, fmt.Errorf("upstream manifest signature invalid")
	}

	return true, nil
}

// IssueReceipt mints an Ed25519-signed Execution Attestation Receipt for non-repudiation.
func (pe *ProvenanceEngine) IssueReceipt(req *SignedToolRequest, responseJSON string, verdict string, duration time.Duration) (*AttestationReceipt, error) {
	respHash := ComputeHash([]byte(responseJSON))
	receiptID := fmt.Sprintf("rcpt_%s", generateNonce()[:14])
	now := time.Now().UTC()

	rec := &AttestationReceipt{
		ReceiptID:       receiptID,
		RequestID:       req.RequestID,
		GatewayID:       pe.Config.GatewayID,
		AgentID:         req.AgentID,
		ToolName:        req.ToolName,
		ArgumentsHash:   req.ArgumentsHash,
		ResponseHash:    respHash,
		Verdict:         verdict,
		Status:          StatusVerified,
		Timestamp:       now,
		DurationUs:      duration.Microseconds(),
		Nonce:           generateNonce(),
		SignerPublicKey: hex.EncodeToString(pe.gatewayPub),
	}

	canonicalStr := CanonicalReceiptString(rec)
	sig := ed25519.Sign(pe.gatewayPriv, []byte(canonicalStr))
	rec.GatewaySignature = hex.EncodeToString(sig)

	return rec, nil
}

// VerifyReceipt cryptographically verifies a gateway-issued execution receipt.
func (pe *ProvenanceEngine) VerifyReceipt(receipt *AttestationReceipt) (bool, error) {
	pubKeyBytes, err := hex.DecodeString(receipt.SignerPublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid signer public key in receipt: %w", err)
	}

	sigBytes, err := hex.DecodeString(receipt.GatewaySignature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid gateway signature in receipt: %w", err)
	}

	canonicalStr := CanonicalReceiptString(receipt)
	valid := ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(canonicalStr), sigBytes)
	if !valid {
		return false, fmt.Errorf("receipt signature verification failed")
	}

	return true, nil
}

func (pe *ProvenanceEngine) cleanupNonces(now time.Time) {
	cutoff := now.Add(-pe.Config.NonceTTL)
	for nonce, ts := range pe.seenNonces {
		if ts.Before(cutoff) {
			delete(pe.seenNonces, nonce)
		}
	}
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
