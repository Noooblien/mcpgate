package redact

import (
	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// DLPDemoScenario represents a realistic agent payload containing sensitive data.
type DLPDemoScenario struct {
	Name        string
	Description string
	AgentID     string
	Role        rbac.AgentRole
	Payload     string
}

// DefaultDemoScenarios returns realistic test cases for DLP and secret vaulting.
func DefaultDemoScenarios() []DLPDemoScenario {
	return []DLPDemoScenario{
		{
			Name:        "Multi-Provider API Keys in Tool Parameters",
			Description: "Agent receives OpenAI, Anthropic, and AWS access keys in tool call arguments",
			AgentID:     "agent-dev-01",
			Role:        rbac.RoleStandard,
			Payload:     `{"target": "deploy_cluster", "openai_key": "sk-proj99887766554433221100aabbccddeeff", "anthropic_key": "sk-ant-api03-abcdef1234567890abcdef1234567890", "aws_id": "AKIAIOSFODNN7EXAMPLE"}`,
		},
		{
			Name:        "PII & Financial Information (Luhn Credit Card & SSN)",
			Description: "Billing workflow with customer SSN, Luhn-valid Visa card, and email address",
			AgentID:     "agent-billing-02",
			Role:        rbac.RoleRestricted,
			Payload:     `Customer contact: jane.doe@enterprise-corp.com (SSN: 987-65-4321), Charged card: 4532-0150-1234-5678 for order #99214`,
		},
		{
			Name:        "Unstructured High-Entropy Secrets & Passwords",
			Description: "Internal database connection URI containing high-entropy password",
			AgentID:     "agent-db-admin",
			Role:        rbac.RoleStandard,
			Payload:     `postgresql://admin:zK9#vL2$pQ8*wN4!mX7@internal-cluster.us-east-1.rds.amazonaws.com:5432/production_ledger`,
		},
		{
			Name:        "Restricted Agent Blocked on Raw RSA Private Key Block",
			Description: "Attempt to pass raw PEM private key through a read-only or restricted agent",
			AgentID:     "agent-readonly-03",
			Role:        rbac.RoleReadOnly,
			Payload:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y9x6e...\n-----END RSA PRIVATE KEY-----",
		},
	}
}
