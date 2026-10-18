package provenance

import (
	"encoding/json"
	"fmt"
)

// AuditProof bundles the entire cryptographic lifecycle of a tool invocation for compliance audits.
type AuditProof struct {
	Receipt      *AttestationReceipt      `json:"receipt"`
	Request      *SignedToolRequest       `json:"request"`
	Verification *VerificationResult      `json:"verification"`
	Manifest     *ToolManifestAttestation `json:"manifest,omitempty"`
}

// ToJSON serializes the audit proof to indented JSON.
func (ap *AuditProof) ToJSON() (string, error) {
	b, err := json.MarshalIndent(ap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal audit proof: %w", err)
	}
	return string(b), nil
}

// ParseReceiptFromJSON parses an AttestationReceipt from raw JSON bytes.
func ParseReceiptFromJSON(rawJSON []byte) (*AttestationReceipt, error) {
	var rec AttestationReceipt
	if err := json.Unmarshal(rawJSON, &rec); err != nil {
		return nil, fmt.Errorf("invalid receipt json: %w", err)
	}
	return &rec, nil
}
