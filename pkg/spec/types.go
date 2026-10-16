package spec

import (
	"encoding/json"
	"time"
)

// JSON-RPC 2.0 primitives
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP Specific Payloads
type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type ContentItem struct {
	Type string `json:"type"` // "text", "image", "resource"
	Text string `json:"text,omitempty"`
	Data string `json:"data,omitempty"`
}

type CallToolResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// GateVerdict represents the security gateway evaluation decision.
type GateVerdict string

const (
	VerdictAllow    GateVerdict = "ALLOW"
	VerdictBlock    GateVerdict = "BLOCK"
	VerdictRedacted GateVerdict = "REDACTED"
)

// InterceptEvent details an audited security decision by the gateway.
type InterceptEvent struct {
	EventID        string      `json:"event_id"`
	AgentID        string      `json:"agent_id"`
	Role           string      `json:"role"`
	Method         string      `json:"method"`
	ToolName       string      `json:"tool_name,omitempty"`
	Verdict        GateVerdict `json:"verdict"`
	BlockReason    string      `json:"block_reason,omitempty"`
	RedactionsMade int         `json:"redactions_made"`
	LatencyMs      int64       `json:"latency_ms"`
	Timestamp      time.Time   `json:"timestamp"`
	PayloadDigest  string      `json:"payload_digest"`
}
