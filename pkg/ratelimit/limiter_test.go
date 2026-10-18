package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucket_BasicFlow(t *testing.T) {
	b := NewTokenBucket(10, 120) // 2 tokens/sec
	if b.Capacity() != 10 {
		t.Fatalf("expected capacity 10, got %.1f", b.Capacity())
	}
	if b.RefillRate() != 2.0 {
		t.Fatalf("expected refill rate 2.0, got %.2f", b.RefillRate())
	}

	allowed, rem, _ := b.AllowN(5)
	if !allowed || rem != 5 {
		t.Fatalf("expected 5 remaining, got %.1f", rem)
	}
}

func TestConcurrencyGovernor_Basic(t *testing.T) {
	cg := NewConcurrencyGovernor(1, nil)
	l1, err := cg.AcquireLease("agent-1", "tool_a")
	if err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	if cg.GetActiveLeases() != 1 {
		t.Fatalf("expected 1 active lease, got %d", cg.GetActiveLeases())
	}

	// 2nd acquire should fail
	_, err = cg.AcquireLease("agent-1", "tool_a")
	if err == nil {
		t.Fatalf("expected error on second lease")
	}

	l1.Release()
	if cg.GetActiveLeases() != 0 {
		t.Fatalf("expected 0 active leases, got %d", cg.GetActiveLeases())
	}
}

func TestFloodShield_Basic(t *testing.T) {
	fs := NewFloodShield(50*time.Millisecond, 3, 200*time.Millisecond)
	for i := 0; i < 3; i++ {
		ok, err := fs.Check("agent-flood")
		if !ok || err != nil {
			t.Fatalf("call %d failed: %v", i+1, err)
		}
	}

	ok, err := fs.Check("agent-flood")
	if ok || err == nil {
		t.Fatalf("expected 4th call to trip flood shield")
	}
}

func TestLimiter_Reset(t *testing.T) {
	limiter := NewTokenBucketLimiter(RateLimiterConfig{MaxRPM: 60, Burst: 5})
	for i := 0; i < 5; i++ {
		_, _ = limiter.Allow("agent-reset")
	}

	// Should be rate limited now
	ok, _ := limiter.Allow("agent-reset")
	if ok {
		t.Fatalf("expected rate limit")
	}

	limiter.Reset()
	ok, err := limiter.Allow("agent-reset")
	if !ok || err != nil {
		t.Fatalf("expected allowed after reset: %v", err)
	}
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewTokenBucketLimiter(RateLimiterConfig{
		MaxRPM:             600,
		Burst:              50,
		MaxConcurrency:     20,
		RunawayLoopCeiling: 200,
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, _ = limiter.AllowTool("agent-concurrent", "tool_test", 1.0)
		}(i)
	}
	wg.Wait()

	m := limiter.GetMetrics()
	if m.TotalRequests != 50 {
		t.Fatalf("expected 50 total requests, got %d", m.TotalRequests)
	}
}
