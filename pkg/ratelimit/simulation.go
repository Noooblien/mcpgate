package ratelimit

import (
	"sync"
	"time"
)

// DefaultSimulationScenarios returns standard workload profiles for testing governor resilience.
func DefaultSimulationScenarios() []SimulationScenario {
	return []SimulationScenario{
		{
			Name:           "Steady State Research Agent",
			Description:    "Autonomous search agent dispatching requests at balanced 10ms intervals",
			AgentID:        "agent-researcher-01",
			ToolName:       "web_search",
			TotalRequests:  20,
			Concurrency:    2,
			Interval:       15 * time.Millisecond,
			SimulatedWork:  5 * time.Millisecond,
			CostPerRequest: 1.0,
		},
		{
			Name:           "Spiky Batch Extraction Agent",
			Description:    "Data extraction agent bursting 35 requests instantaneously to ingest files",
			AgentID:        "agent-batch-extractor",
			ToolName:       "extract_entity",
			TotalRequests:  35,
			Concurrency:    10,
			Interval:       1 * time.Millisecond,
			SimulatedWork:  2 * time.Millisecond,
			CostPerRequest: 1.0,
		},
		{
			Name:           "High-Concurrency Subprocess Worker",
			Description:    "Agent executing concurrent code tests exceeding tool concurrency limits",
			AgentID:        "agent-heavy-runner",
			ToolName:       "bash_exec",
			TotalRequests:  30,
			Concurrency:    15,
			Interval:       2 * time.Millisecond,
			SimulatedWork:  20 * time.Millisecond,
			CostPerRequest: 1.0,
		},
		{
			Name:           "Runaway Recursive Loop Attacker",
			Description:    "Rogue agent in infinite reflection loop attempting to flood gateway",
			AgentID:        "agent-rogue-loop",
			ToolName:       "query_eval",
			TotalRequests:  40,
			Concurrency:    8,
			Interval:       0,
			SimulatedWork:  1 * time.Millisecond,
			CostPerRequest: 1.0,
		},
	}
}

// RunSimulation executes a suite of scenarios against a configured governor.
func RunSimulation(governor *TokenBucketLimiter, scenarios []SimulationScenario) (*SimulationSummary, error) {
	if governor == nil {
		governor = NewTokenBucketLimiter(RateLimiterConfig{
			MaxRPM:             120, // 2 tokens/sec
			Burst:              15,  // burst ceiling of 15
			MaxConcurrency:     6,   // max 6 in-flight per agent
			MaxToolConcurrency: map[string]int{"bash_exec": 3},
			ToolLimits: map[string]ToolLimit{
				"bash_exec": {MaxRPM: 60, Burst: 5},
			},
			RunawayLoopWindow:  100 * time.Millisecond,
			RunawayLoopCeiling: 12,
			CircuitCooloff:     2 * time.Second,
		})
	}

	summary := &SimulationSummary{
		Timestamp:    time.Now(),
		AgentResults: make([]AgentSimulationResult, 0, len(scenarios)),
	}

	totalDispatched := 0
	totalAllowed := 0
	totalThrottled := 0

	for _, sc := range scenarios {
		res := executeScenario(governor, sc)
		summary.AgentResults = append(summary.AgentResults, res)
		totalDispatched += res.TotalDispatched
		totalAllowed += res.Allowed
		totalThrottled += (res.RateLimited + res.ConcurrencyGated + res.CircuitBroken)
	}

	summary.TotalDispatched = totalDispatched
	summary.TotalAllowed = totalAllowed
	summary.TotalThrottled = totalThrottled

	if totalThrottled > 0 {
		summary.BurstContainmentPct = float64(totalThrottled) / float64(totalDispatched) * 100.0
	}

	metrics := governor.GetMetrics()
	if metrics.TotalRequests > 0 {
		summary.GovernorOverheadMicros = float64(metrics.P50LatencyNanos) / 1000.0
	}

	return summary, nil
}

func executeScenario(governor *TokenBucketLimiter, sc SimulationScenario) AgentSimulationResult {
	start := time.Now()
	res := AgentSimulationResult{
		ScenarioName: sc.Name,
		AgentID:      sc.AgentID,
	}

	var mu sync.Mutex
	latencies := make([]time.Duration, 0, sc.TotalRequests)

	// Channel to throttle concurrency
	sem := make(chan struct{}, sc.Concurrency)
	var wg sync.WaitGroup

	for i := 0; i < sc.TotalRequests; i++ {
		wg.Add(1)
		sem <- struct{}{}

		go func(reqNum int) {
			defer func() {
				<-sem
				wg.Done()
			}()

			callStart := time.Now()

			// Phase 1: Rate limit & Flood Shield evaluation
			dec, _ := governor.AllowTool(sc.AgentID, sc.ToolName, sc.CostPerRequest)
			dur := time.Since(callStart)

			mu.Lock()
			latencies = append(latencies, dur)
			res.TotalDispatched++

			if !dec.Allowed {
				switch dec.Status {
				case StatusCircuitOpen:
					res.CircuitBroken++
				case StatusRateLimited:
					res.RateLimited++
				}
				mu.Unlock()
				return
			}
			mu.Unlock()

			// Phase 2: Concurrency Lease Acquisition
			lease, leaseErr := governor.AcquireLease(sc.AgentID, sc.ToolName)
			if leaseErr != nil {
				mu.Lock()
				res.ConcurrencyGated++
				mu.Unlock()
				return
			}

			// Simulate work inside concurrency lease
			if sc.SimulatedWork > 0 {
				time.Sleep(sc.SimulatedWork)
			}
			lease.Release()

			mu.Lock()
			res.Allowed++
			mu.Unlock()
		}(i)

		if sc.Interval > 0 {
			time.Sleep(sc.Interval)
		}
	}

	wg.Wait()
	res.Duration = time.Since(start)

	// Calculate latency percentiles
	if len(latencies) > 0 {
		var totalDur time.Duration
		for _, d := range latencies {
			totalDur += d
		}
		res.AvgLatencyMicros = float64(totalDur.Microseconds()) / float64(len(latencies))

		p99Idx := int(float64(len(latencies)) * 0.99)
		if p99Idx >= len(latencies) {
			p99Idx = len(latencies) - 1
		}
		res.P99LatencyMicros = float64(latencies[p99Idx].Microseconds())
	}

	return res
}
