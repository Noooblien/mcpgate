package tests

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Noooblien/mcpgate/pkg/ratelimit"
)

func TestTokenBucket_RefillAndCapacity(t *testing.T) {
	// 60 RPM = 1 token/sec, capacity 5
	b := ratelimit.NewTokenBucket(5, 60)
	if b.Capacity() != 5 {
		t.Fatalf("expected capacity 5, got %.1f", b.Capacity())
	}
	if b.AvailableTokens() != 5 {
		t.Fatalf("expected initial tokens 5, got %.1f", b.AvailableTokens())
	}

	// Consume 4 tokens
	allowed, remaining, _ := b.AllowN(4)
	if !allowed || remaining != 1 {
		t.Fatalf("expected 1 token remaining, got %.1f (allowed: %v)", remaining, allowed)
	}

	// Consume remaining 1 token
	allowed, remaining, _ = b.Allow()
	if !allowed || remaining > 0.001 {
		t.Fatalf("expected 0 tokens remaining, got %.4f", remaining)
	}

	// Next immediate request should be denied
	allowed, _, retryAfter := b.Allow()
	if allowed {
		t.Fatalf("expected request to be rate-limited, but was allowed")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retry-after, got %v", retryAfter)
	}

	// Reset bucket
	b.Reset()
	if b.AvailableTokens() != 5 {
		t.Fatalf("expected 5 tokens after reset, got %.1f", b.AvailableTokens())
	}
}

func TestConcurrencyGovernor_LeaseLifecycle(t *testing.T) {
	cg := ratelimit.NewConcurrencyGovernor(2, map[string]int{"heavy_tool": 1})

	// Acquire first lease
	l1, err := cg.AcquireLease("agent-1", "normal_tool")
	if err != nil {
		t.Fatalf("unexpected error acquiring l1: %v", err)
	}
	if cg.GetInFlight("agent-1") != 1 {
		t.Fatalf("expected 1 in-flight, got %d", cg.GetInFlight("agent-1"))
	}

	// Acquire second lease
	l2, err := cg.AcquireLease("agent-1", "normal_tool")
	if err != nil {
		t.Fatalf("unexpected error acquiring l2: %v", err)
	}
	if cg.GetInFlight("agent-1") != 2 {
		t.Fatalf("expected 2 in-flight, got %d", cg.GetInFlight("agent-1"))
	}

	// Third lease should be denied (client max = 2)
	_, err = cg.AcquireLease("agent-1", "normal_tool")
	if err == nil {
		t.Fatalf("expected concurrency error for third lease, got nil")
	}

	// Release l1
	l1.Release()
	if cg.GetInFlight("agent-1") != 1 {
		t.Fatalf("expected 1 in-flight after release, got %d", cg.GetInFlight("agent-1"))
	}

	// Re-releasing l1 should be an idempotent no-op
	l1.Release()
	if cg.GetInFlight("agent-1") != 1 {
		t.Fatalf("expected 1 in-flight after duplicate release, got %d", cg.GetInFlight("agent-1"))
	}

	// Test tool-specific concurrency limit (heavy_tool limit = 1)
	ht1, err := cg.AcquireLease("agent-2", "heavy_tool")
	if err != nil {
		t.Fatalf("unexpected error acquiring heavy_tool lease: %v", err)
	}
	_, err = cg.AcquireLease("agent-2", "heavy_tool")
	if err == nil {
		t.Fatalf("expected tool concurrency ceiling breach for heavy_tool, got nil")
	}
	ht1.Release()
	l2.Release()
}

func TestFloodShield_RunawayLoopQuarantine(t *testing.T) {
	// Window 200ms, ceiling 5, cooloff 500ms
	fs := ratelimit.NewFloodShield(200*time.Millisecond, 5, 500*time.Millisecond)

	// Send 5 calls rapidly: all should be permitted
	for i := 0; i < 5; i++ {
		ok, err := fs.Check("agent-looper")
		if !ok || err != nil {
			t.Fatalf("call %d should pass, got err: %v", i+1, err)
		}
	}

	// 6th rapid call trips the circuit breaker
	ok, err := fs.Check("agent-looper")
	if ok || err == nil {
		t.Fatalf("expected circuit breaker trip on 6th call")
	}
	if fs.TrippedCount() != 1 {
		t.Fatalf("expected 1 tripped count, got %d", fs.TrippedCount())
	}

	// Subsequent call during cool-off is quarantined
	ok, err = fs.Check("agent-looper")
	if ok || err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
		t.Fatalf("expected quarantined response, got ok=%v, err=%v", ok, err)
	}

	// Another innocent agent is NOT affected
	ok, err = fs.Check("agent-innocent")
	if !ok || err != nil {
		t.Fatalf("innocent agent should not be quarantined: %v", err)
	}
}

func TestTokenBucketLimiter_Allow_BackwardCompatibility(t *testing.T) {
	limiter := ratelimit.NewTokenBucketLimiter(ratelimit.RateLimiterConfig{
		MaxRPM: 60,
		Burst:  3,
	})

	for i := 0; i < 3; i++ {
		ok, err := limiter.Allow("agent-legacy")
		if !ok || err != nil {
			t.Fatalf("call %d should be allowed: %v", i+1, err)
		}
	}

	// 4th call exceeds burst
	ok, err := limiter.Allow("agent-legacy")
	if ok || err == nil {
		t.Fatalf("expected 4th call to be rejected by rate limiter")
	}
}

func TestTokenBucketLimiter_AllowTool_ToolLimits(t *testing.T) {
	limiter := ratelimit.NewTokenBucketLimiter(ratelimit.RateLimiterConfig{
		MaxRPM: 120,
		Burst:  10,
		ToolLimits: map[string]ratelimit.ToolLimit{
			"bash_exec": {MaxRPM: 60, Burst: 2},
		},
	})

	// First 2 bash calls allowed
	dec1, err := limiter.AllowTool("agent-worker", "bash_exec", 1.0)
	if !dec1.Allowed || err != nil {
		t.Fatalf("call 1 should pass: %v", err)
	}

	dec2, err := limiter.AllowTool("agent-worker", "bash_exec", 1.0)
	if !dec2.Allowed || err != nil {
		t.Fatalf("call 2 should pass: %v", err)
	}

	// 3rd bash call exceeds tool-specific burst of 2
	dec3, err := limiter.AllowTool("agent-worker", "bash_exec", 1.0)
	if dec3.Allowed || err == nil {
		t.Fatalf("call 3 should fail due to tool limit")
	}
	if !strings.Contains(dec3.Reason, "tool rate limit exceeded") {
		t.Fatalf("expected tool rate limit message, got %s", dec3.Reason)
	}

	// Headers RFC 6585 test
	headers := dec3.RFC6585Headers()
	if _, ok := headers["Retry-After"]; !ok {
		t.Fatalf("expected Retry-After header in 429 response")
	}

	// Other tools for same agent should still have client tokens
	decSafe, err := limiter.AllowTool("agent-worker", "read_file", 1.0)
	if !decSafe.Allowed || err != nil {
		t.Fatalf("read_file should pass: %v", err)
	}
}

func TestTokenBucketLimiter_TelemetryAndPercentiles(t *testing.T) {
	limiter := ratelimit.NewTokenBucketLimiter(ratelimit.RateLimiterConfig{
		MaxRPM:             60,
		Burst:              10,
		RunawayLoopCeiling: 50,
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, _ = limiter.AllowTool("agent-telemetry", "test_tool", 1.0)
		}(i)
	}
	wg.Wait()

	metrics := limiter.GetMetrics()
	if metrics.TotalRequests != 20 {
		t.Fatalf("expected 20 total requests, got %d", metrics.TotalRequests)
	}
	if metrics.AllowedRequests != 10 {
		t.Fatalf("expected 10 allowed requests (burst 10), got %d", metrics.AllowedRequests)
	}
	if metrics.ThrottledRateLimit != 10 {
		t.Fatalf("expected 10 throttled requests, got %d", metrics.ThrottledRateLimit)
	}
}

func TestSimulation_FullWorkloadSuite(t *testing.T) {
	scenarios := ratelimit.DefaultSimulationScenarios()
	if len(scenarios) < 4 {
		t.Fatalf("expected at least 4 default scenarios, got %d", len(scenarios))
	}

	summary, err := ratelimit.RunSimulation(nil, scenarios)
	if err != nil {
		t.Fatalf("simulation failed: %v", err)
	}

	if summary.TotalDispatched != 125 {
		t.Fatalf("expected 125 dispatched tool calls, got %d", summary.TotalDispatched)
	}
	if summary.TotalAllowed == 0 {
		t.Fatalf("expected allowed requests > 0, got %d", summary.TotalAllowed)
	}
	if summary.TotalThrottled == 0 {
		t.Fatalf("expected throttled requests > 0, got %d", summary.TotalThrottled)
	}
	if summary.BurstContainmentPct <= 0 {
		t.Fatalf("expected positive containment percentage, got %.2f%%", summary.BurstContainmentPct)
	}

	// Verify terminal scorecard formatting
	termReport := ratelimit.RenderTerminalScorecard(summary)
	if !strings.Contains(termReport, "MCPGATE TOKEN BUCKET RATE LIMITER") {
		t.Fatalf("invalid terminal scorecard output")
	}

	// Verify markdown report formatting
	mdReport := ratelimit.RenderMarkdownReport(summary)
	if !strings.Contains(mdReport, "| Workload Scenario |") {
		t.Fatalf("invalid markdown report output")
	}

	// Verify JSON serialization
	jsonStr, err := summary.RenderJSON()
	if err != nil {
		t.Fatalf("failed to render JSON: %v", err)
	}
	var parsed ratelimit.SimulationSummary
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to parse generated JSON: %v", err)
	}
	if parsed.TotalDispatched != summary.TotalDispatched {
		t.Fatalf("JSON mismatch: expected %d, got %d", summary.TotalDispatched, parsed.TotalDispatched)
	}
}
