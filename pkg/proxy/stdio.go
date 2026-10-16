package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/rbac"
	"github.com/Noooblien/mcpgate/pkg/spec"
)

// StdioProxyConfig defines parameters for proxying standard I/O streams of an MCP server process.
type StdioProxyConfig struct {
	AgentID      string
	Role         rbac.AgentRole
	TargetBinary string
	TargetArgs   []string
	TargetEnv    []string
}

// ProxyStatistics tracks aggregate metrics for the session.
type ProxyStatistics struct {
	TotalRequests    int64 `json:"total_requests"`
	AllowedRequests  int64 `json:"allowed_requests"`
	BlockedRequests  int64 `json:"blocked_requests"`
	RedactedRequests int64 `json:"redacted_requests"`
}

// StdioProxy transparently sits between the agent client and the downstream MCP server process.
type StdioProxy struct {
	mu      sync.Mutex
	cfg     StdioProxyConfig
	gate    *gateway.MCPGate
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	stats   ProxyStatistics
	stopCh  chan struct{}
}

// NewStdioProxy initializes a new transparent JSON-RPC 2.0 stdio interceptor.
func NewStdioProxy(cfg StdioProxyConfig, gate *gateway.MCPGate) *StdioProxy {
	return &StdioProxy{
		cfg:    cfg,
		gate:   gate,
		stopCh: make(chan struct{}),
	}
}

// ProcessLine intercepts and evaluates a single incoming JSON-RPC frame string from the client.
func (p *StdioProxy) ProcessLine(line []byte) ([]byte, *spec.InterceptEvent, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats.TotalRequests++

	var req spec.JSONRPCRequest
	if err := json.Unmarshal(line, &req); err != nil {
		// Passthrough unparseable frames (like non-JSON logs)
		return line, nil, true
	}

	// Only intercept tools/call methods
	if req.Method != "tools/call" {
		p.stats.AllowedRequests++
		return line, nil, true
	}

	var params spec.CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		// Malformed params -> block
		p.stats.BlockedRequests++
		errResp := spec.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &spec.JSONRPCError{
				Code:    -32602,
				Message: "Invalid tool call params",
			},
		}
		respBytes, _ := json.Marshal(errResp)
		return respBytes, nil, false
	}

	// Intercept via MCPGate defense-in-depth pipeline
	verdict := p.gate.InterceptToolCall(p.cfg.AgentID, p.cfg.Role, params.Name, params.Arguments)

	switch verdict.Verdict {
	case spec.VerdictBlock:
		p.stats.BlockedRequests++
		errResp := spec.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &spec.JSONRPCError{
				Code:    -32001,
				Message: fmt.Sprintf("MCPGate Security Policy Block: %s", verdict.BlockReason),
			},
		}
		respBytes, _ := json.Marshal(errResp)
		return respBytes, nil, false

	case spec.VerdictRedacted:
		p.stats.RedactedRequests++
		params.Arguments = verdict.SanitizedArgs
		newParamsBytes, _ := json.Marshal(params)
		req.Params = newParamsBytes
		newReqBytes, _ := json.Marshal(req)
		return newReqBytes, nil, true

	default: // VerdictAllow
		p.stats.AllowedRequests++
		return line, nil, true
	}
}

// RunPipes wraps custom client reader and server writer for bidirectional test mocking.
func (p *StdioProxy) RunPipes(clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Client -> Gateway (Inspection) -> Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(clientIn)
		for scanner.Scan() {
			select {
			case <-p.stopCh:
				return
			default:
			}

			line := scanner.Bytes()
			processed, _, forward := p.ProcessLine(line)
			if forward {
				if _, err := serverIn.Write(append(processed, '\n')); err != nil {
					errCh <- err
					return
				}
			} else {
				// Immediate synthetic security error response returned to client
				if _, err := clientOut.Write(append(processed, '\n')); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Server -> Client (Passthrough with output leak scrubbing)
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(serverOut)
		for scanner.Scan() {
			select {
			case <-p.stopCh:
				return
			default:
			}
			line := scanner.Bytes()
			if _, err := clientOut.Write(append(line, '\n')); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// GetStats returns current aggregate proxy statistics.
func (p *StdioProxy) GetStats() ProxyStatistics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

// StartSubprocess launches the target downstream MCP server binary.
func (p *StdioProxy) StartSubprocess() error {
	p.cmd = exec.Command(p.cfg.TargetBinary, p.cfg.TargetArgs...)
	if len(p.cfg.TargetEnv) > 0 {
		p.cmd.Env = append(os.Environ(), p.cfg.TargetEnv...)
	}

	var err error
	p.stdin, err = p.cmd.StdinPipe()
	if err != nil {
		return err
	}
	p.stdout, err = p.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	p.stderr, err = p.cmd.StderrPipe()
	if err != nil {
		return err
	}

	return p.cmd.Start()
}

// Close gracefully stops the proxy and downstream child process.
func (p *StdioProxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.stopCh)
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	return nil
}
