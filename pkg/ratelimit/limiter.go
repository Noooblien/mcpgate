package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// RateLimiterConfig specifies capacity and replenishment rate.
type RateLimiterConfig struct {
	MaxRPM int // Requests per minute
	Burst  int // Maximum burst size
}

type clientBucket struct {
	tokens     float64
	lastRefill time.Time
}

// TokenBucketLimiter manages rate limits per agent/client ID.
type TokenBucketLimiter struct {
	mu      sync.Mutex
	cfg     RateLimiterConfig
	buckets map[string]*clientBucket
}

// NewTokenBucketLimiter creates a new rate limiter.
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

	return &TokenBucketLimiter{
		cfg:     cfg,
		buckets: make(map[string]*clientBucket),
	}
}

// Allow checks if a request from the given client ID is permitted under current rate limits.
func (l *TokenBucketLimiter) Allow(clientID string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[clientID]
	if !exists {
		b = &clientBucket{
			tokens:     float64(l.cfg.Burst),
			lastRefill: now,
		}
		l.buckets[clientID] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	refillRate := float64(l.cfg.MaxRPM) / 60.0 // tokens per second
	b.tokens += elapsed * refillRate
	if b.tokens > float64(l.cfg.Burst) {
		b.tokens = float64(l.cfg.Burst)
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true, nil
	}

	return false, fmt.Errorf("rate limit exceeded: max %d RPM for client %s", l.cfg.MaxRPM, clientID)
}
