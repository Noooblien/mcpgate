package httpproxy

import (
	"sync"
	"time"

	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// HTTPProxyConfig holds configuration parameters for the HTTP/SSE reverse-proxy server.
type HTTPProxyConfig struct {
	ListenAddr      string            `json:"listen_addr"`
	UpstreamURL     string            `json:"upstream_url"`
	AgentIDHeader   string            `json:"agent_id_header"` // Header key for agent identity (default: X-Agent-ID)
	RoleHeader      string            `json:"role_header"`     // Header key for agent role (default: X-Agent-Role)
	DefaultAgentID  string            `json:"default_agent_id"`
	DefaultRole     rbac.AgentRole    `json:"default_role"`
	ReadTimeout     time.Duration     `json:"read_timeout"`
	WriteTimeout    time.Duration     `json:"write_timeout"`
	Gateway         *gateway.MCPGate  `json:"-"`
}

// ProxyMetrics tracks real-time traffic statistics and security enforcement counters.
type ProxyMetrics struct {
	mu                 sync.RWMutex
	RequestsTotal      uint64    `json:"requests_total"`
	RequestsAllowed    uint64    `json:"requests_allowed"`
	RequestsBlocked    uint64    `json:"requests_blocked"`
	SecretsRedacted    uint64    `json:"secrets_redacted"`
	RateLimitsExceeded uint64    `json:"rate_limits_exceeded"`
	BytesTransferred   uint64    `json:"bytes_transferred"`
	ActiveConnections  int64     `json:"active_connections"`
	LastEventAt        time.Time `json:"last_event_at"`
}

// IncrementAllowed increments the allowed requests counter.
func (m *ProxyMetrics) IncrementAllowed(bytesCount uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestsTotal++
	m.RequestsAllowed++
	m.BytesTransferred += bytesCount
	m.LastEventAt = time.Now().UTC()
}

// IncrementBlocked increments the blocked requests counter.
func (m *ProxyMetrics) IncrementBlocked(isRateLimit bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestsTotal++
	m.RequestsBlocked++
	if isRateLimit {
		m.RateLimitsExceeded++
	}
	m.LastEventAt = time.Now().UTC()
}

// IncrementRedacted adds to the redacted secrets counter.
func (m *ProxyMetrics) IncrementRedacted(count uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SecretsRedacted += count
}

// Snapshot returns a point-in-time copy of the metrics.
func (m *ProxyMetrics) Snapshot() ProxyMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ProxyMetrics{
		RequestsTotal:      m.RequestsTotal,
		RequestsAllowed:    m.RequestsAllowed,
		RequestsBlocked:    m.RequestsBlocked,
		SecretsRedacted:    m.SecretsRedacted,
		RateLimitsExceeded: m.RateLimitsExceeded,
		BytesTransferred:   m.BytesTransferred,
		ActiveConnections:  m.ActiveConnections,
		LastEventAt:        m.LastEventAt,
	}
}
