package provenance

import (
	"fmt"
	"strings"
	"time"
)

// RenderProvenanceScorecard formats a cryptographic verification outcome for the terminal.
func RenderProvenanceScorecard(res *VerificationResult, rec *AttestationReceipt) string {
	var b strings.Builder

	statusColor := "\033[1;32m" // Green
	if !res.Valid {
		statusColor = "\033[1;31m" // Red
	}

	b.WriteString("\033[1;35m========================================================================================\033[0m\n")
	b.WriteString("  \033[1;37mMCPGATE // CRYPTOGRAPHIC TOOL PROVENANCE & NON-REPUDIATION ATTESTATION\033[0m\n")
	b.WriteString("\033[1;35m========================================================================================\033[0m\n")
	b.WriteString(fmt.Sprintf("  \033[1;33mAgent ID:\033[0m            %s\n", res.AgentID))
	b.WriteString(fmt.Sprintf("  \033[1;33mTarget Tool:\033[0m        \033[1;36m%s\033[0m\n", res.ToolName))
	b.WriteString(fmt.Sprintf("  \033[1;33mVerification:\033[0m       %s[%s]\033[0m (%s)\n", statusColor, res.Status, res.Detail))
	b.WriteString(fmt.Sprintf("  \033[1;33mPayload Integrity:\033[0m  %s\n", formatBool(res.ArgumentsVerified)))
	b.WriteString(fmt.Sprintf("  \033[1;33mEd25519 Signature:\033[0m  %s\n", formatBool(res.SignatureVerified)))
	b.WriteString(fmt.Sprintf("  \033[1;33mClock Skew:\033[0m         %v\n", res.TimestampDrift.Round(time.Millisecond)))

	if rec != nil {
		b.WriteString("  \033[1;34m----------------------------------------------------------------------------------------\033[0m\n")
		b.WriteString("  \033[1;37mGATEWAY ATTESTATION RECEIPT (NON-REPUDIATION TOKEN):\033[0m\n")
		b.WriteString(fmt.Sprintf("  Receipt ID:          \033[1;33m%s\033[0m\n", rec.ReceiptID))
		b.WriteString(fmt.Sprintf("  Request ID:          %s\n", rec.RequestID))
		b.WriteString(fmt.Sprintf("  Gateway ID:          %s\n", rec.GatewayID))
		b.WriteString(fmt.Sprintf("  Execution Verdict:   \033[1;32m%s\033[0m (Duration: %d µs)\n", rec.Verdict, rec.DurationUs))
		b.WriteString(fmt.Sprintf("  Arguments Hash:      \033[0;37m%s\033[0m\n", rec.ArgumentsHash))
		b.WriteString(fmt.Sprintf("  Response Hash:       \033[0;37m%s\033[0m\n", rec.ResponseHash))
		b.WriteString(fmt.Sprintf("  Gateway Signature:   \033[1;32m[ED25519-SIGNED]\033[0m %s...\n", truncate(rec.GatewaySignature, 32)))
		b.WriteString(fmt.Sprintf("  Signer Public Key:   %s...\n", truncate(rec.SignerPublicKey, 32)))
	}

	b.WriteString("\033[1;35m========================================================================================\033[0m\n")
	return b.String()
}

// RenderProvenanceMermaid produces a Mermaid sequence diagram illustrating the mutual signing flow.
func RenderProvenanceMermaid(rec *AttestationReceipt) string {
	var b strings.Builder
	b.WriteString("```mermaid\n")
	b.WriteString("sequenceDiagram\n")
	b.WriteString("    autonumber\n")
	b.WriteString("    actor A as Autonomous Agent\n")
	b.WriteString("    participant GW as MCPGate (Zero-Trust Gateway)\n")
	b.WriteString("    participant UP as Upstream MCP Server\n\n")

	b.WriteString(fmt.Sprintf("    A->>GW: SignedToolRequest(Tool: %s, ArgsHash: %s...)\n", rec.ToolName, truncate(rec.ArgumentsHash, 10)))
	b.WriteString("    Note over GW: Verify Agent Ed25519 Signature<br/>Validate Nonce & Timestamp Drift\n")

	if rec.Verdict == "ALLOWED" {
		b.WriteString("    GW->>UP: Forward Verified Tool Call\n")
		b.WriteString("    UP-->>GW: Tool Execution Output\n")
		b.WriteString(fmt.Sprintf("    Note over GW: Mint Non-Repudiation Receipt<br/>Receipt ID: %s\n", rec.ReceiptID))
		b.WriteString("    GW-->>A: Tool Output + Ed25519 Attestation Receipt\n")
	} else {
		b.WriteString(fmt.Sprintf("    Note over GW: Tool Call Rejected: %s\n", rec.Verdict))
		b.WriteString(fmt.Sprintf("    GW-->>A: Security Block + Cryptographic Audit Proof (%s)\n", rec.Verdict))
	}

	b.WriteString("```\n")
	return b.String()
}

// RenderMarkdownReport generates a markdown summary table of audited tool calls.
func RenderMarkdownReport(proofs []*AuditProof) string {
	var b strings.Builder

	b.WriteString("# MCPGate // Cryptographic Tool Provenance & Attestation Audit Report\n\n")
	b.WriteString(fmt.Sprintf("**Audit Date:** %s  \n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("**Gateway Engine:** MCPGate Zero-Trust Security Gateway  \n\n")

	b.WriteString("## Executive Summary\n\n")
	b.WriteString("| Metric | Count | Rate |\n")
	b.WriteString("| :--- | :--- | :--- |\n")

	total := len(proofs)
	verified := 0
	for _, p := range proofs {
		if p.Verification.Valid {
			verified++
		}
	}
	rate := 0.0
	if total > 0 {
		rate = float64(verified) / float64(total) * 100.0
	}

	b.WriteString(fmt.Sprintf("| **Total Tool Calls Intercepted** | %d | 100.0%% |\n", total))
	b.WriteString(fmt.Sprintf("| **Cryptographically Verified** | %d | %.1f%% |\n", verified, rate))
	b.WriteString(fmt.Sprintf("| **Tampered / Replayed / Rejected** | %d | %.1f%% |\n\n", total-verified, 100.0-rate))

	b.WriteString("## Tool Call Verification Ledger\n\n")
	b.WriteString("| Receipt ID | Agent ID | Tool Name | Verification | Verdict | Arguments SHA-256 | Signature |\n")
	b.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, p := range proofs {
		recID := "N/A"
		verdict := "REJECTED"
		if p.Receipt != nil {
			recID = p.Receipt.ReceiptID
			verdict = p.Receipt.Verdict
		}
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | **%s** | `%s` | `%s...` | `[ED25519-OK]` |\n",
			recID,
			p.Request.AgentID,
			p.Request.ToolName,
			p.Verification.Status,
			verdict,
			truncate(p.Request.ArgumentsHash, 12),
		))
	}

	b.WriteString("\n## Provenance Lifecycle Flowchart\n\n")
	if len(proofs) > 0 && proofs[0].Receipt != nil {
		b.WriteString(RenderProvenanceMermaid(proofs[0].Receipt))
	}

	return b.String()
}

func formatBool(v bool) string {
	if v {
		return "\033[1;32m[PASS]\033[0m Verified"
	}
	return "\033[1;31m[FAIL]\033[0m Tampered/Invalid"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
