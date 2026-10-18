package ratelimit

import (
	"math"
	"sync"
	"time"
)

// TokenBucket provides a thread-safe token bucket with fractional replenishment.
type TokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// NewTokenBucket creates a new token bucket with given capacity and refill rate per minute.
func NewTokenBucket(capacity float64, rpm float64) *TokenBucket {
	if capacity <= 0 {
		capacity = 10
	}
	if rpm <= 0 {
		rpm = 60
	}
	ratePerSec := rpm / 60.0

	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: ratePerSec,
		lastRefill: time.Now(),
	}
}

// Allow attempts to consume 1 token.
func (b *TokenBucket) Allow() (bool, float64, time.Duration) {
	return b.AllowN(1.0)
}

// AllowN attempts to consume n tokens. Returns:
// - allowed: true if enough tokens were available
// - remaining: current token balance after attempt
// - retryAfter: duration to wait until enough tokens are replenished
func (b *TokenBucket) AllowN(n float64) (bool, float64, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.refill(now)

	if b.tokens >= n {
		b.tokens -= n
		return true, b.tokens, 0
	}

	// Calculate required wait time
	deficit := n - b.tokens
	retryAfterSec := deficit / b.refillRate
	retryAfter := time.Duration(math.Ceil(retryAfterSec * float64(time.Second)))

	return false, b.tokens, retryAfter
}

// Refill replenishes tokens based on elapsed duration. Must be called with lock held.
func (b *TokenBucket) refill(now time.Time) {
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	b.lastRefill = now

	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}

// AvailableTokens returns the current balance after refilling up to now.
func (b *TokenBucket) AvailableTokens() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(time.Now())
	return b.tokens
}

// Capacity returns the bucket burst capacity.
func (b *TokenBucket) Capacity() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capacity
}

// RefillRate returns the replenishment rate in tokens per second.
func (b *TokenBucket) RefillRate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.refillRate
}

// Reset restores the bucket to full capacity.
func (b *TokenBucket) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = b.capacity
	b.lastRefill = time.Now()
}
