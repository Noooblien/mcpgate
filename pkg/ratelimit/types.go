package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// LimitStatus indicates the outcome of a rate limiting decision.
type LimitStatus string

const (
	StatusAllowed      LimitStatus = "ALLOWED"
	StatusRateLimited  LimitStatus = "RATE_LIMITED"
	StatusConcurrentEx LimitStatus = "CONCURRENCY_EXCEEDED"
	StatusCircuitOpen  LimitStatus = "CIRCUIT_BREAKER_OPEN"
)

// RateLimiterConfig specifies capacity and replenishment rate.
type RateLimiterConfig struct {
	MaxRPM              int                     `json:"max_rpm"`               // Global/default requests per minute
	Burst               int                     `json:"burst"`                 // Global/default maximum burst capacity
	MaxConcurrency      int                     `json:"max_concurrency"`       // Max in-flight concurrent requests per client (0 = unlimited)
	MaxToolConcurrency  map[string]int          `json:"max_tool_concurrency"`  // Tool-specific max in-flight requests
	ToolLimits          map[string]ToolLimit    `json:"tool_limits"`           // Tool-specific RPM and burst overrides
	RunawayLoopWindow   time.Duration           `json:"runaway_loop_window"`   // Time window to detect rapid loops (e.g. 100ms)
	RunawayLoopCeiling  int                     `json:"runaway_loop_ceiling"`  // Max requests in window before circuit trip
	CircuitCooloff      time.Duration           `json:"circuit_cooloff"`       // How long circuit breaker isolates a rogue agent
}

// ToolLimit defines specialized rate ceilings for specific MCP tools.
type ToolLimit struct {
	MaxRPM int `json:"max_rpm"`
	Burst  int `json:"burst"`
}

// LimitDecision provides comprehensive decision metadata adhering to RFC 6585.
type LimitDecision struct {
	Allowed        bool          `json:"allowed"`
	Status         LimitStatus   `json:"status"`
	ClientID       string        `json:"client_id"`
	ToolName       string        `json:"tool_name,omitempty"`
	TokensRequested float64      `json:"tokens_requested"`
	TokensRemaining float64      `json:"tokens_remaining"`
	Capacity       float64       `json:"capacity"`
	RefillRatePerSec float64     `json:"refill_rate_per_sec"`
	RetryAfter     time.Duration `json:"retry_after"`
	ResetTime      time.Time     `json:"reset_time"`
	ActiveConcurrency int        `json:"active_concurrency"`
	MaxConcurrency int           `json:"max_concurrency"`
	Reason         string        `json:"reason,omitempty"`
}

// RFC6585Headers returns standard HTTP 429 rate limiting headers.
func (d LimitDecision) RFC6585Headers() map[string]string {
	headers := make(map[string]string)
	headers["X-RateLimit-Limit"] = fmt.Sprintf("%.0f", d.Capacity)
	headers["X-RateLimit-Remaining"] = fmt.Sprintf("%.0f", d.TokensRemaining)
	headers["X-RateLimit-Reset"] = fmt.Sprintf("%d", d.ResetTime.Unix())
	if !d.Allowed && d.RetryAfter > 0 {
		headers["Retry-After"] = fmt.Sprintf("%d", int(d.RetryAfter.Seconds()+0.999))
	}
	return headers
}

// ConcurrencyLease represents an active in-flight execution slot.
type ConcurrencyLease struct {
	ID        string
	ClientID  string
	ToolName  string
	AcquiredAt time.Time
	released  bool
	mu        sync.Mutex
	releaseFn func()
}

// Release yields the active concurrency slot back to the pool.
func (l *ConcurrencyLease) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.released {
		l.released = true
		if l.releaseFn != nil {
			l.releaseFn()
		}
	}
}

// GovernorMetrics tracks telemetry across rate limiting and concurrency subsystems.
type GovernorMetrics struct {
	TotalRequests        int64         `json:"total_requests"`
	AllowedRequests      int64         `json:"allowed_requests"`
	ThrottledRateLimit   int64         `json:"throttled_rate_limit"`
	ThrottledConcurrency int64         `json:"throttled_concurrency"`
	ThrottledRunawayLoop int64         `json:"throttled_runaway_loop"`
	ActiveLeases         int           `json:"active_leases"`
	UniqueClientsTracked int           `json:"unique_clients_tracked"`
	P50LatencyNanos      int64         `json:"p50_latency_nanos"`
	P99LatencyNanos      int64         `json:"p99_latency_nanos"`
}

// SimulationScenario defines a synthetic workload for governor validation.
type SimulationScenario struct {
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	AgentID        string        `json:"agent_id"`
	ToolName       string        `json:"tool_name"`
	TotalRequests  int           `json:"total_requests"`
	Concurrency    int           `json:"concurrency"`
	Interval       time.Duration `json:"interval"`
	SimulatedWork  time.Duration `json:"simulated_work"`
	CostPerRequest float64       `json:"cost_per_request"`
}

// AgentSimulationResult summarizes simulated agent execution.
type AgentSimulationResult struct {
	ScenarioName      string        `json:"scenario_name"`
	AgentID           string        `json:"agent_id"`
	TotalDispatched   int           `json:"total_dispatched"`
	Allowed           int           `json:"allowed"`
	RateLimited       int           `json:"rate_limited"`
	ConcurrencyGated  int           `json:"concurrency_gated"`
	CircuitBroken     int           `json:"circuit_broken"`
	AvgLatencyMicros  float64       `json:"avg_latency_micros"`
	P99LatencyMicros  float64       `json:"p99_latency_micros"`
	Duration          time.Duration `json:"duration"`
}

// SimulationSummary aggregates all agent simulation results.
type SimulationSummary struct {
	Timestamp          time.Time                `json:"timestamp"`
	TotalDispatched    int                      `json:"total_dispatched"`
	TotalAllowed       int                      `json:"total_allowed"`
	TotalThrottled     int                      `json:"total_throttled"`
	BurstContainmentPct float64                 `json:"burst_containment_pct"`
	GovernorOverheadMicros float64              `json:"governor_overhead_micros"`
	AgentResults       []AgentSimulationResult  `json:"agent_results"`
}
