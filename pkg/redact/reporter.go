package redact

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderDLPScorecard generates an ANSI terminal dashboard of the DLP evaluation.
func RenderDLPScorecard(res *DLPResult, agentID string, action DLPAction) string {
	var b strings.Builder

	statusColor := "\033[1;32m" // Green
	statusText := "[PASS / SANITIZED]"
	if !res.Allowed {
		statusColor = "\033[1;31m" // Red
		statusText = "[BLOCKED BY DLP]"
	}

	b.WriteString("\033[1;36m========================================================================================\033[0m\n")
	b.WriteString("  \033[1;37mMCPGATE // DATA LOSS PREVENTION (DLP) & EPHEMERAL SECRET VAULT\033[0m\n")
	b.WriteString("\033[1;36m========================================================================================\033[0m\n")
	b.WriteString(fmt.Sprintf("  \033[1;33mAgent ID:\033[0m            %s\n", agentID))
	b.WriteString(fmt.Sprintf("  \033[1;33mDLP Enforcement:\033[0m     %s\n", action))
	b.WriteString(fmt.Sprintf("  \033[1;33mAudit Verdict:\033[0m       %s%s\033[0m\n", statusColor, statusText))
	b.WriteString(fmt.Sprintf("  \033[1;33mTotal Redacted:\033[0m      %d secrets scrubbed\n", len(res.Occurrences)+len(res.HighEntropySecrets)))
	b.WriteString(fmt.Sprintf("  \033[1;33mVault Tokens Made:\033[0m   %d active reversible pseudonyms\n", len(res.TokensCreated)))

	if !res.Allowed {
		b.WriteString(fmt.Sprintf("  \033[1;31mBlock Reason:\033[0m        %s\n", res.BlockReason))
	}

	if len(res.Occurrences) > 0 {
		b.WriteString("  \033[1;34m----------------------------------------------------------------------------------------\033[0m\n")
		b.WriteString("  \033[1;37mDETECTED SECRET PATTERNS (REGEX / LUHN AUDITED):\033[0m\n")
		b.WriteString("  #   Rule ID        Category          Replacement Mask\n")
		b.WriteString("  ----------------------------------------------------------------------------------------\n")
		for i, occ := range res.Occurrences {
			b.WriteString(fmt.Sprintf("  [%d] %-14s %-16s  %s\n", i+1, occ.RuleID, occ.Category, occ.Masked))
		}
	}

	if len(res.HighEntropySecrets) > 0 {
		b.WriteString("  \033[1;34m----------------------------------------------------------------------------------------\033[0m\n")
		b.WriteString("  \033[1;37mDETECTED UNSTRUCTURED HIGH-ENTROPY SECRETS:\033[0m\n")
		b.WriteString("  #   Entropy (bits)  Length  Complexity       Candidate Preview\n")
		b.WriteString("  ----------------------------------------------------------------------------------------\n")
		for i, h := range res.HighEntropySecrets {
			preview := h.Token
			if len(preview) > 20 {
				preview = preview[:17] + "..."
			}
			b.WriteString(fmt.Sprintf("  [%d] %5.2f bits      %-7d %-16s %s\n", i+1, h.Entropy, h.Length, h.CharacterMix, preview))
		}
	}

	b.WriteString("  \033[1;34m----------------------------------------------------------------------------------------\033[0m\n")
	b.WriteString("  \033[1;37mSANITIZED PAYLOAD PREVIEW:\033[0m\n")
	preview := res.SanitizedText
	if len(preview) > 300 {
		preview = preview[:297] + "..."
	}
	b.WriteString(fmt.Sprintf("  %s\n", strings.ReplaceAll(preview, "\n", "\n  ")))
	b.WriteString("\033[1;36m========================================================================================\033[0m\n")

	return b.String()
}

// RenderDLPMermaid generates a Mermaid flowchart demonstrating bi-directional secret vaulting.
func RenderDLPMermaid() string {
	var b strings.Builder
	b.WriteString("```mermaid\nflowchart LR\n")
	b.WriteString("  subgraph Agent Context [Autonomous Agent / LLM]\n")
	b.WriteString("    A[Agent Reasoning Loop] -->|Submits Tool Args| G[MCPGate Gateway]\n")
	b.WriteString("    G -->|Returns Sanitized Result with Pseudonyms| A\n")
	b.WriteString("  end\n\n")
	b.WriteString("  subgraph Zero-Trust Gateway [MCPGate DLP & Vault]\n")
	b.WriteString("    G -->|Ingress Inspection| DLP[DLP Policy Engine]\n")
	b.WriteString("    DLP -->|Entropy Scanner| H[Shannon Entropy H > 4.3]\n")
	b.WriteString("    DLP -->|Known Rules| R[API Keys, JWT, PII]\n")
	b.WriteString("    R -->|Action: VAULT| V[(In-Memory Secret Vault)]\n")
	b.WriteString("    V -->|Generate Token| T[Token: [[VAULT:CAT:hash]]]\n")
	b.WriteString("    T -->|Forward Plaintext to Upstream| UP[Upstream MCP Tool Execution]\n")
	b.WriteString("  end\n")
	b.WriteString("```\n")
	return b.String()
}

// RenderMarkdownReport produces GitHub flavored markdown for CI/CD audit logs.
func RenderMarkdownReport(results []*DLPResult) string {
	var b strings.Builder
	b.WriteString("### MCPGate Data Loss Prevention & Secret Vault Audit\n\n")
	b.WriteString("| # | Status | Scrubbed Secrets | High-Entropy Hits | Vault Tokens Created | Action |\n")
	b.WriteString("| :-: | :---: | :---: | :---: | :---: | :---: |\n")

	for i, r := range results {
		status := "✅ ALLOWED"
		if !r.Allowed {
			status = "❌ BLOCKED"
		}
		b.WriteString(fmt.Sprintf("| %d | **%s** | %d | %d | %d | `%s` |\n",
			i+1, status, len(r.Occurrences), len(r.HighEntropySecrets), len(r.TokensCreated), "VAULT/MASK"))
	}

	b.WriteString("\n*Zero-trust DLP tokenization guaranteed by MCPGate ephemeral vault.*\n")
	return b.String()
}

// RenderJSON formats the DLP result into standard JSON.
func (res *DLPResult) RenderJSON() (string, error) {
	bytes, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
