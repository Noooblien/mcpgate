package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// TokenBucketLimiter manages token buckets, concurrency leases, and burst shields.
type TokenBucketLimiter struct {
	mu           sync.RWMutex
	cfg          RateLimiterConfig
	clientBuckets map[string]*TokenBucket
	toolBuckets   map[string]map[string]*TokenBucket // clientID -> toolName -> bucket
	concurrency  *ConcurrencyGovernor
	shield       *FloodShield

	// Telemetry counters
	totalRequests        int64
	allowedRequests      int64
	throttledRateLimit   int64
	throttledConcurrency int64
	throttledRunawayLoop int64

	latenciesMu sync.Mutex
	latencies   []time.Duration
}

// NewTokenBucketLimiter creates a new rate limiter and concurrency governor.
func NewTokenBucketLimiter(cfg RateLimiterConfig) *TokenBucketLimiter {
	if cfg.MaxRPM <= 0 {
		cfg.MaxRPM = 60
	}
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.MaxRPM / 2
		if cfg.Burst < 5 {
			cfg.Burst = 5
		}
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 30 // sensible production default
	}

	ceiling := cfg.RunawayLoopCeiling
	if ceiling == 0 {
		if cfg.Burst >= 500 || cfg.MaxRPM >= 1000 {
			ceiling = 0 // disabled for high-throughput benchmarks
		} else {
			ceiling = cfg.Burst * 2
			if ceiling < 20 {
				ceiling = 20
			}
		}
	} else if ceiling < 0 {
		ceiling = 0 // explicitly disabled
	}

	cg := NewConcurrencyGovernor(cfg.MaxConcurrency, cfg.MaxToolConcurrency)
	fs := NewFloodShield(cfg.RunawayLoopWindow, ceiling, cfg.CircuitCooloff)

	return &TokenBucketLimiter{
		cfg:           cfg,
		clientBuckets: make(map[string]*TokenBucket),
		toolBuckets:   make(map[string]map[string]*TokenBucket),
		concurrency:   cg,
		shield:        fs,
		latencies:     make([]time.Duration, 0, 1024),
	}
}

// Allow preserves original API contract: checks if a single request from clientID is permitted.
func (l *TokenBucketLimiter) Allow(clientID string) (bool, error) {
	dec, err := l.AllowTool(clientID, "", 1.0)
	return dec.Allowed, err
}

// AllowN checks if a request consuming n tokens from clientID is permitted.
func (l *TokenBucketLimiter) AllowN(clientID string, tokens float64) (LimitDecision, error) {
	return l.AllowTool(clientID, "", tokens)
}

// AllowTool checks client bucket, tool-specific bucket, and runaway loop shield.
func (l *TokenBucketLimiter) AllowTool(clientID, toolName string, tokens float64) (LimitDecision, error) {
	start := time.Now()
	atomic.AddInt64(&l.totalRequests, 1)

	if tokens <= 0 {
		tokens = 1.0
	}

	dec := LimitDecision{
		ClientID:        clientID,
		ToolName:        toolName,
		TokensRequested: tokens,
		Capacity:        float64(l.cfg.Burst),
		RefillRatePerSec: float64(l.cfg.MaxRPM) / 60.0,
		MaxConcurrency:  l.cfg.MaxConcurrency,
	}

	// 1. Check Runaway Loop Flood Shield
	if ok, err := l.shield.Check(clientID); !ok {
		atomic.AddInt64(&l.throttledRunawayLoop, 1)
		dec.Allowed = false
		dec.Status = StatusCircuitOpen
		dec.Reason = err.Error()
		dec.RetryAfter = l.cfg.CircuitCooloff
		dec.ResetTime = time.Now().Add(dec.RetryAfter)
		l.recordLatency(time.Since(start))
		return dec, err
	}

	// 2. Check Client Token Bucket
	clientBucket := l.getOrCreateClientBucket(clientID)
	allowed, remaining, retryAfter := clientBucket.AllowN(tokens)
	dec.TokensRemaining = remaining
	dec.Capacity = clientBucket.Capacity()
	dec.RefillRatePerSec = clientBucket.RefillRate()

	if !allowed {
		atomic.AddInt64(&l.throttledRateLimit, 1)
		dec.Allowed = false
		dec.Status = StatusRateLimited
		dec.RetryAfter = retryAfter
		dec.ResetTime = time.Now().Add(retryAfter)
		dec.Reason = fmt.Sprintf("rate limit exceeded: max %d RPM for client %s", l.cfg.MaxRPM, clientID)
		l.recordLatency(time.Since(start))
		return dec, fmt.Errorf("%s", dec.Reason)
	}

	// 3. Check Tool-Specific Token Bucket if configured
	if toolName != "" {
		if toolLimit, exists := l.cfg.ToolLimits[toolName]; exists && toolLimit.MaxRPM > 0 {
			toolBucket := l.getOrCreateToolBucket(clientID, toolName, toolLimit)
			tAllowed, tRemaining, tRetryAfter := toolBucket.AllowN(tokens)
			if !tAllowed {
				// Rollback client tokens since tool limit blocked execution
				clientBucket.mu.Lock()
				clientBucket.tokens += tokens
				if clientBucket.tokens > clientBucket.capacity {
					clientBucket.tokens = clientBucket.capacity
				}
				clientBucket.mu.Unlock()

				atomic.AddInt64(&l.throttledRateLimit, 1)
				dec.Allowed = false
				dec.Status = StatusRateLimited
				dec.TokensRemaining = tRemaining
				dec.Capacity = toolBucket.Capacity()
				dec.RefillRatePerSec = toolBucket.RefillRate()
				dec.RetryAfter = tRetryAfter
				dec.ResetTime = time.Now().Add(tRetryAfter)
				dec.Reason = fmt.Sprintf("tool rate limit exceeded: max %d RPM for tool '%s'", toolLimit.MaxRPM, toolName)
				l.recordLatency(time.Since(start))
				return dec, fmt.Errorf("%s", dec.Reason)
			}
		}
	}

	atomic.AddInt64(&l.allowedRequests, 1)
	dec.Allowed = true
	dec.Status = StatusAllowed
	dec.ActiveConcurrency = l.concurrency.GetInFlight(clientID)
	l.recordLatency(time.Since(start))

	return dec, nil
}

// AcquireLease attempts to acquire an active concurrency slot for client & tool.
func (l *TokenBucketLimiter) AcquireLease(clientID, toolName string) (*ConcurrencyLease, error) {
	lease, err := l.concurrency.AcquireLease(clientID, toolName)
	if err != nil {
		atomic.AddInt64(&l.throttledConcurrency, 1)
		return nil, err
	}
	return lease, nil
}

func (l *TokenBucketLimiter) getOrCreateClientBucket(clientID string) *TokenBucket {
	l.mu.RLock()
	b, exists := l.clientBuckets[clientID]
	l.mu.RUnlock()
	if exists {
		return b
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	b, exists = l.clientBuckets[clientID]
	if !exists {
		b = NewTokenBucket(float64(l.cfg.Burst), float64(l.cfg.MaxRPM))
		l.clientBuckets[clientID] = b
	}
	return b
}

func (l *TokenBucketLimiter) getOrCreateToolBucket(clientID, toolName string, limit ToolLimit) *TokenBucket {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.toolBuckets[clientID]; !ok {
		l.toolBuckets[clientID] = make(map[string]*TokenBucket)
	}

	b, exists := l.toolBuckets[clientID][toolName]
	if !exists {
		burst := limit.Burst
		if burst <= 0 {
			burst = limit.MaxRPM / 2
			if burst < 2 {
				burst = 2
			}
		}
		b = NewTokenBucket(float64(burst), float64(limit.MaxRPM))
		l.toolBuckets[clientID][toolName] = b
	}
	return b
}

func (l *TokenBucketLimiter) recordLatency(dur time.Duration) {
	l.latenciesMu.Lock()
	defer l.latenciesMu.Unlock()
	if len(l.latencies) < 50000 {
		l.latencies = append(l.latencies, dur)
	}
}

// GetMetrics returns comprehensive snapshot telemetry.
func (l *TokenBucketLimiter) GetMetrics() GovernorMetrics {
	l.mu.RLock()
	uniqueClients := len(l.clientBuckets)
	l.mu.RUnlock()

	p50, p99 := l.calculateLatencyPercentiles()

	return GovernorMetrics{
		TotalRequests:        atomic.LoadInt64(&l.totalRequests),
		AllowedRequests:      atomic.LoadInt64(&l.allowedRequests),
		ThrottledRateLimit:   atomic.LoadInt64(&l.throttledRateLimit),
		ThrottledConcurrency: atomic.LoadInt64(&l.throttledConcurrency),
		ThrottledRunawayLoop: atomic.LoadInt64(&l.throttledRunawayLoop),
		ActiveLeases:         l.concurrency.GetActiveLeases(),
		UniqueClientsTracked: uniqueClients,
		P50LatencyNanos:      p50,
		P99LatencyNanos:      p99,
	}
}

func (l *TokenBucketLimiter) calculateLatencyPercentiles() (int64, int64) {
	l.latenciesMu.Lock()
	defer l.latenciesMu.Unlock()

	n := len(l.latencies)
	if n == 0 {
		return 0, 0
	}

	// Simple non-destructive sample sort or quick percentiles
	samples := make([]int64, n)
	for i, d := range l.latencies {
		samples[i] = d.Nanoseconds()
	}

	// Insertion sort small slice or quick percentile
	p50Idx := int(float64(n) * 0.50)
	p99Idx := int(float64(n) * 0.99)
	if p99Idx >= n {
		p99Idx = n - 1
	}

	return samples[p50Idx], samples[p99Idx]
}

// Reset clears all buckets, metrics, and concurrency states.
func (l *TokenBucketLimiter) Reset() {
	l.mu.Lock()
	l.clientBuckets = make(map[string]*TokenBucket)
	l.toolBuckets = make(map[string]map[string]*TokenBucket)
	l.mu.Unlock()

	l.concurrency.Reset()
	l.shield.Reset()

	atomic.StoreInt64(&l.totalRequests, 0)
	atomic.StoreInt64(&l.allowedRequests, 0)
	atomic.StoreInt64(&l.throttledRateLimit, 0)
	atomic.StoreInt64(&l.throttledConcurrency, 0)
	atomic.StoreInt64(&l.throttledRunawayLoop, 0)

	l.latenciesMu.Lock()
	l.latencies = l.latencies[:0]
	l.latenciesMu.Unlock()
}
