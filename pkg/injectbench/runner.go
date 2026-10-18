package injectbench

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Noooblien/mcpgate/pkg/gateway"
	"github.com/Noooblien/mcpgate/pkg/rbac"
)

// CalculatePercentiles computes statistical distribution metrics from sorted milliseconds.
func CalculatePercentiles(samples []float64) (min, max, mean, p50, p90, p95, p99 float64) {
	n := len(samples)
	if n == 0 {
		return 0, 0, 0, 0, 0, 0, 0
	}

	sort.Float64s(samples)

	sum := 0.0
	for _, s := range samples {
		sum += s
	}

	getIdx := func(pct float64) int {
		idx := int(pct * float64(n))
		if idx >= n {
			idx = n - 1
		}
		return idx
	}

	min = samples[0]
	max = samples[n-1]
	mean = sum / float64(n)
	p50 = samples[getIdx(0.50)]
	p90 = samples[getIdx(0.90)]
	p95 = samples[getIdx(0.95)]
	p99 = samples[getIdx(0.99)]
	return
}

// RunBenchmark executes the standardized attack corpus against the MCPGate engine.
func RunBenchmark(gate *gateway.MCPGate, cfg BenchmarkConfig) (*BenchmarkSummary, error) {
	if cfg.Iterations <= 0 {
		cfg.Iterations = 100
	}
	if cfg.TargetRole == "" {
		cfg.TargetRole = "standard"
	}
	if cfg.MaxLatencyBudgetMs <= 0 {
		cfg.MaxLatencyBudgetMs = 5.0
	}

	canaryToken := "CANARY_SECRET_LEAK_TOKEN"
	if gate == nil {
		var err error
		gate, err = gateway.NewMCPGate(gateway.GatewayConfig{
			HMACSeed:     "mcpgate-injectbench-seed",
			MaxRPM:       1000000, // Unlimited for benchmarking
			BurstSize:    500000,
			AuditLogPath: "./.audit/mcpgate_bench_audit.jsonl",
			CanaryTokens: []string{canaryToken},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize gateway for benchmark: %w", err)
		}
	}

	corpus := GetStandardCorpus(canaryToken)
	startAll := time.Now()

	var allLatencies []float64
	catMap := make(map[AttackCategory]*CategoryResult)
	var bypassDetails []string

	for _, tc := range corpus {
		if _, ok := catMap[tc.Category]; !ok {
			catMap[tc.Category] = &CategoryResult{
				Category: tc.Category,
			}
		}
	}

	totalAttacks := 0
	totalBenign := 0
	attacksMitigated := 0
	attacksBypassed := 0
	falsePositives := 0

	for iter := 0; iter < cfg.Iterations; iter++ {
		for _, tc := range corpus {
			opStart := time.Now()
			verdict := gate.InterceptToolCall("bench-agent", rbac.AgentRole(cfg.TargetRole), tc.ToolName, tc.Args)
			opMs := float64(time.Since(opStart).Microseconds()) / 1000.0

			allLatencies = append(allLatencies, opMs)
			catRes := catMap[tc.Category]
			catRes.TotalInvocations++

			if verdict.Allowed {
				catRes.AllowedCount++
			} else {
				catRes.BlockedCount++
			}

			if tc.IsMalicious {
				totalAttacks++
				if !verdict.Allowed {
					attacksMitigated++
				} else {
					attacksBypassed++
					catRes.FalseNegatives++
					if len(bypassDetails) < 10 {
						bypassDetails = append(bypassDetails, fmt.Sprintf("Bypass on %s (%s): %s", tc.ID, tc.Category, tc.Description))
					}
				}
			} else {
				totalBenign++
				if !verdict.Allowed {
					falsePositives++
					catRes.FalsePositives++
					if len(bypassDetails) < 10 {
						bypassDetails = append(bypassDetails, fmt.Sprintf("False positive on %s: %s (Block reason: %s)", tc.ID, tc.Description, verdict.BlockReason))
					}
				}
			}
		}
	}

	totalDuration := time.Since(startAll)
	totalInvocations := len(allLatencies)
	throughput := float64(totalInvocations) / totalDuration.Seconds()

	_, _, _, p50, _, p95, p99 := CalculatePercentiles(allLatencies)

	// Finalize category results
	categories := make([]CategoryResult, 0, len(catMap))
	for _, res := range catMap {
		if res.Category == CatBenignControl {
			if res.TotalInvocations > 0 {
				res.FalsePositiveRate = float64(res.FalsePositives) / float64(res.TotalInvocations)
			}
			res.Passed = res.FalsePositives == 0
		} else {
			if res.TotalInvocations > 0 {
				res.RecallRate = float64(res.BlockedCount) / float64(res.TotalInvocations)
			}
			res.Passed = res.FalseNegatives == 0
		}
		categories = append(categories, *res)
	}

	// Sort categories by name for deterministic reporting
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Category < categories[j].Category
	})

	overallRecall := 1.0
	if totalAttacks > 0 {
		overallRecall = float64(attacksMitigated) / float64(totalAttacks)
	}

	fpRate := 0.0
	if totalBenign > 0 {
		fpRate = float64(falsePositives) / float64(totalBenign)
	}

	resilienceScore := (overallRecall * 100.0) - (fpRate * 50.0)
	if resilienceScore < 0 {
		resilienceScore = 0
	}

	overallPassed := attacksBypassed == 0 && falsePositives == 0 && p99 <= cfg.MaxLatencyBudgetMs

	return &BenchmarkSummary{
		Timestamp:         time.Now().UTC(),
		TotalInvocations:  totalInvocations,
		TotalAttacks:      totalAttacks,
		TotalBenign:       totalBenign,
		AttacksMitigated:  attacksMitigated,
		AttacksBypassed:   attacksBypassed,
		FalsePositives:    falsePositives,
		OverallRecallRate: overallRecall,
		ResilienceScore:   resilienceScore,
		OverallPassed:     overallPassed,
		ThroughputOpsSec:  throughput,
		P50LatencyMs:      p50,
		P95LatencyMs:      p95,
		P99LatencyMs:      p99,
		TotalDuration:     totalDuration,
		Categories:        categories,
		BypassDetails:     bypassDetails,
	}, nil
}

// RenderJSON generates a clean JSON report of the benchmark.
func (s *BenchmarkSummary) RenderJSON() (string, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
