package provenance

import (
	"time"
)

// VerificationStatus represents the cryptographic verification result.
type VerificationStatus string

const (
	StatusVerified            VerificationStatus = "VERIFIED"
	StatusInvalidSignature    VerificationStatus = "INVALID_SIGNATURE"
	StatusReplayDetected      VerificationStatus = "REPLAY_ATTACK_DETECTED"
	StatusClockSkewExceeded   VerificationStatus = "CLOCK_SKEW_EXCEEDED"
	StatusUnknownAgentKey     VerificationStatus = "UNKNOWN_AGENT_KEY"
	StatusSchemaTampered      VerificationStatus = "SCHEMA_TAMPERED"
	StatusPayloadTampered     VerificationStatus = "PAYLOAD_TAMPERED"
)

// ProvenanceConfig configures cryptographic verification tolerances and keys.
type ProvenanceConfig struct {
	GatewayID             string        `json:"gateway_id"`
	MaxClockSkew          time.Duration `json:"max_clock_skew"`          // Default: 30s
	NonceTTL              time.Duration `json:"nonce_ttl"`                // Default: 5m
	EnforceRequestSigning bool          `json:"enforce_request_signing"`  // Require Ed25519 signatures
	EnforceManifestVerify bool          `json:"enforce_manifest_verify"`  // Require upstream schema proof
}

// DefaultProvenanceConfig returns production defaults for zero-trust provenance.
func DefaultProvenanceConfig() ProvenanceConfig {
	return ProvenanceConfig{
		GatewayID:             "mcpgate-primary-gw-01",
		MaxClockSkew:          30 * time.Second,
		NonceTTL:              5 * time.Minute,
		EnforceRequestSigning: true,
		EnforceManifestVerify: true,
	}
}

// SignedToolRequest represents an agent tool call signed with Ed25519.
type SignedToolRequest struct {
	RequestID     string    `json:"request_id"`
	AgentID       string    `json:"agent_id"`
	ToolName      string    `json:"tool_name"`
	Timestamp     time.Time `json:"timestamp"`
	Nonce         string    `json:"nonce"`
	ArgumentsJSON string    `json:"arguments_json"`
	ArgumentsHash string    `json:"arguments_hash"` // SHA-256 of canonical arguments JSON
	SignatureHex  string    `json:"signature_hex"`  // Ed25519 signature in hex
}

// ToolManifestAttestation certifies the authenticity and schema integrity of an upstream MCP tool.
type ToolManifestAttestation struct {
	ServerID      string    `json:"server_id"`
	ToolName      string    `json:"tool_name"`
	Version       string    `json:"version"`
	SchemaJSON    string    `json:"schema_json"`
	SchemaDigest  string    `json:"schema_digest"`  // SHA-256 of canonical tool JSON schema
	Timestamp     time.Time `json:"timestamp"`
	SignatureHex  string    `json:"signature_hex"`  // Upstream Ed25519 signature
}

// AttestationReceipt is a tamper-proof cryptographic audit token issued by the Gateway.
type AttestationReceipt struct {
	ReceiptID         string             `json:"receipt_id"`
	RequestID         string             `json:"request_id"`
	GatewayID         string             `json:"gateway_id"`
	AgentID           string             `json:"agent_id"`
	ToolName          string             `json:"tool_name"`
	ArgumentsHash     string             `json:"arguments_hash"`
	ResponseHash      string             `json:"response_hash"`
	Verdict           string             `json:"verdict"`           // ALLOWED, BLOCKED_FIREWALL, etc.
	Status            VerificationStatus `json:"status"`            // VERIFIED or reason for rejection
	Timestamp         time.Time          `json:"timestamp"`
	DurationUs        int64              `json:"duration_us"`
	Nonce             string             `json:"nonce"`
	GatewaySignature  string             `json:"gateway_signature"` // Ed25519 signature by Gateway
	SignerPublicKey   string             `json:"signer_public_key"`
}

// VerificationResult details the granular checks performed during tool call interception.
type VerificationResult struct {
	Valid              bool               `json:"valid"`
	Status             VerificationStatus `json:"status"`
	Detail             string             `json:"detail"`
	AgentID            string             `json:"agent_id"`
	ToolName           string             `json:"tool_name"`
	ArgumentsVerified  bool               `json:"arguments_verified"`
	SignatureVerified  bool               `json:"signature_verified"`
	TimestampDrift     time.Duration      `json:"timestamp_drift"`
	Receipt            *AttestationReceipt`json:"receipt,omitempty"`
}
