package httpproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/rbac"
	"github.com/Noooblien/mcpgate/pkg/spec"
)

// HTTPProxyServer provides an inline zero-trust reverse-proxy for HTTP/SSE MCP endpoints.
type HTTPProxyServer struct {
	config      HTTPProxyConfig
	gateway     *gateway.MCPGate
	metrics     *ProxyMetrics
	reverse     *httputil.ReverseProxy
	upstreamURL *url.URL
	httpClient  *http.Client
}

// NewHTTPProxyServer instantiates the HTTP/SSE security proxy.
func NewHTTPProxyServer(cfg HTTPProxyConfig) (*HTTPProxyServer, error) {
	if cfg.Gateway == nil {
		return nil, fmt.Errorf("gateway instance cannot be nil")
	}

	if cfg.AgentIDHeader == "" {
		cfg.AgentIDHeader = "X-Agent-ID"
	}
	if cfg.RoleHeader == "" {
		cfg.RoleHeader = "X-Agent-Role"
	}
	if cfg.DefaultAgentID == "" {
		cfg.DefaultAgentID = "agent-http-client"
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = rbac.RoleStandard
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}

	var parsedUpstream *url.URL
	var revProxy *httputil.ReverseProxy
	if cfg.UpstreamURL != "" {
		u, err := url.Parse(cfg.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL: %w", err)
		}
		parsedUpstream = u
		revProxy = httputil.NewSingleHostReverseProxy(u)
	}

	return &HTTPProxyServer{
		config:      cfg,
		gateway:     cfg.Gateway,
		metrics:     &ProxyMetrics{},
		reverse:     revProxy,
		upstreamURL: parsedUpstream,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

// Handler returns the http.Handler for the proxy server.
func (p *HTTPProxyServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", p.handleHealth)
	mux.HandleFunc("/metrics", p.handleMetrics)
	mux.HandleFunc("/", p.handleDispatch)
	return mux
}

// handleHealth outputs operational health and uptime.
func (p *HTTPProxyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "healthy",
		"service":  "mcpgate",
		"version":  "1.0.0",
		"upstream": p.config.UpstreamURL,
	})
}

// handleMetrics returns a real-time snapshot of security counters.
func (p *HTTPProxyServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(p.metrics.Snapshot())
}

// handleDispatch coordinates SSE streaming vs. JSON-RPC tool-call inspection.
func (p *HTTPProxyServer) handleDispatch(w http.ResponseWriter, r *http.Request) {
	// Identify agent and role from incoming headers
	agentID := r.Header.Get(p.config.AgentIDHeader)
	if agentID == "" {
		agentID = p.config.DefaultAgentID
	}
	roleStr := r.Header.Get(p.config.RoleHeader)
	role := p.config.DefaultRole
	if roleStr != "" {
		role = rbac.AgentRole(strings.ToLower(roleStr))
	}

	// 1. SSE Connection Stream
	if r.Method == http.MethodGet && (r.Header.Get("Accept") == "text/event-stream" || strings.HasSuffix(r.URL.Path, "/sse")) {
		p.handleSSE(w, r, agentID, role)
		return
	}

	// 2. JSON-RPC POST request
	if r.Method == http.MethodPost {
		p.handleJSONRPC(w, r, agentID, role)
		return
	}

	// Fallback to reverse proxy or 404
	if p.reverse != nil {
		p.reverse.ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}

// handleJSONRPC intercepts, evaluates, redacts, and proxies MCP JSON-RPC 2.0 payloads.
func (p *HTTPProxyServer) handleJSONRPC(w http.ResponseWriter, r *http.Request, agentID string, role rbac.AgentRole) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	var req spec.JSONRPCRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		// Passthrough non-JSON-RPC frames
		if p.reverse != nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			p.reverse.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Invalid JSON-RPC 2.0 request payload", http.StatusBadRequest)
		return
	}

	// If not a tools/call request, pass through
	if req.Method != "tools/call" {
		p.forwardOrEcho(w, r, bodyBytes)
		return
	}

	// Parse tools/call parameters
	var toolCallParams spec.CallToolParams
	if err := json.Unmarshal(req.Params, &toolCallParams); err != nil {
		p.sendJSONRPCError(w, req.ID, -32602, "Invalid params for tools/call")
		return
	}

	// Intercept and evaluate with MCPGate security pipeline
	verdict := p.gateway.InterceptToolCall(agentID, role, toolCallParams.Name, toolCallParams.Arguments)

	if !verdict.Allowed {
		isRateLimit := strings.Contains(verdict.BlockReason, "Rate limit")
		p.metrics.IncrementBlocked(isRateLimit)
		p.sendJSONRPCError(w, req.ID, -32001, fmt.Sprintf("MCPGate Security Policy Block: %s", verdict.BlockReason))
		return
	}

	// Apply redaction if arguments were sanitized
	if verdict.Verdict == spec.VerdictRedacted {
		redactions := 0
		if verdict.RedactResult != nil {
			redactions = verdict.RedactResult.TotalRedacted
		}
		p.metrics.IncrementRedacted(uint64(redactions))
		toolCallParams.Arguments = verdict.SanitizedArgs
		newParams, _ := json.Marshal(toolCallParams)
		req.Params = newParams
		bodyBytes, _ = json.Marshal(req)
	}

	p.metrics.IncrementAllowed(uint64(len(bodyBytes)))

	// If upstream MCP server is configured, forward sanitized request
	if p.upstreamURL != nil {
		targetURL := *p.upstreamURL
		targetURL.Path = r.URL.Path
		targetURL.RawQuery = r.URL.RawQuery

		proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			p.sendJSONRPCError(w, req.ID, -32603, "Internal proxy dispatch failure")
			return
		}

		for k, vv := range r.Header {
			for _, v := range vv {
				proxyReq.Header.Add(k, v)
			}
		}

		resp, err := p.httpClient.Do(proxyReq)
		if err != nil {
			p.sendJSONRPCError(w, req.ID, -32002, fmt.Sprintf("Upstream MCP server unreachable: %v", err))
			return
		}
		defer resp.Body.Close()

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			p.sendJSONRPCError(w, req.ID, -32603, "Failed to read upstream response")
			return
		}

		// Perform egress secret redaction on tool response output
		sanitizedResp := p.sanitizeEgressResponse(respBytes)

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(sanitizedResp)
		return
	}

	// Standalone echo / mock response for testing and standalone mode
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	contentBytes, _ := json.Marshal(map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("[MCPGate Verified] Tool '%s' executed successfully under role '%s'", toolCallParams.Name, role),
			},
		},
	})
	resp := spec.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  contentBytes,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// sanitizeEgressResponse intercepts upstream response text and redacts leaked credentials.
func (p *HTTPProxyServer) sanitizeEgressResponse(respBytes []byte) []byte {
	var respObj map[string]interface{}
	if err := json.Unmarshal(respBytes, &respObj); err != nil {
		return respBytes
	}

	// Redact secrets in response object
	sanitizedObj, count := p.gateway.RedactObject(respObj)
	if count > 0 {
		p.metrics.IncrementRedacted(uint64(count))
		cleanedBytes, err := json.Marshal(sanitizedObj)
		if err == nil {
			return cleanedBytes
		}
	}

	return respBytes
}

func (p *HTTPProxyServer) handleSSE(w http.ResponseWriter, r *http.Request, agentID string, role rbac.AgentRole) {
	if p.reverse != nil {
		p.reverse.ServeHTTP(w, r)
		return
	}

	// Standalone mock SSE endpoint
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=%s\n\n", agentID)
	flusher.Flush()
}

func (p *HTTPProxyServer) forwardOrEcho(w http.ResponseWriter, r *http.Request, body []byte) {
	if p.reverse != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		p.reverse.ServeHTTP(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"status":"ok"}}`))
}

func (p *HTTPProxyServer) sendJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	errResp := spec.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &spec.JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
	_ = json.NewEncoder(w).Encode(errResp)
}

// Metrics returns the active ProxyMetrics instance.
func (p *HTTPProxyServer) Metrics() *ProxyMetrics {
	return p.metrics
}
