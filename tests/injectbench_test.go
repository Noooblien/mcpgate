package tests_test

import (
	"strings"
	"testing"

	"github.com/Noooblien/mcpgate/pkg/injectbench"
)

func TestInjectBench_CorpusIntegrity(t *testing.T) {
	corpus := injectbench.GetStandardCorpus("TEST_CANARY_TOKEN")
	if len(corpus) < 15 {
		t.Fatalf("expected at least 15 corpus test cases, got %d", len(corpus))
	}

	attackCount := 0
	benignCount := 0
	catMap := make(map[injectbench.AttackCategory]bool)

	for _, tc := range corpus {
		if tc.ID == "" || tc.ToolName == "" {
			t.Errorf("test case missing ID or ToolName: %+v", tc)
		}
		if tc.IsMalicious {
			attackCount++
		} else {
			benignCount++
		}
		catMap[tc.Category] = true
	}

	if attackCount == 0 || benignCount == 0 {
		t.Errorf("expected both attack and benign items, got attacks: %d, benign: %d", attackCount, benignCount)
	}

	if len(catMap) < 5 {
		t.Errorf("expected at least 5 distinct vulnerability categories, got %d", len(catMap))
	}
}

func TestInjectBench_CalculatePercentiles(t *testing.T) {
	samples := make([]float64, 100)
	for i := 0; i < 100; i++ {
		samples[i] = float64(i + 1)
	}

	min, max, mean, p50, p90, p95, p99 := injectbench.CalculatePercentiles(samples)

	if min != 1.0 || max != 100.0 {
		t.Errorf("expected min 1.0, max 100.0; got min %f, max %f", min, max)
	}
	if mean != 50.5 {
		t.Errorf("expected mean 50.5, got %f", mean)
	}
	if p50 != 51.0 {
		t.Errorf("expected p50 51.0, got %f", p50)
	}
	if p90 != 91.0 || p95 != 96.0 || p99 != 100.0 {
		t.Errorf("percentiles mismatch: p90=%f, p95=%f, p99=%f", p90, p95, p99)
	}
}

func TestInjectBench_RunBenchmark_StandardRole(t *testing.T) {
	cfg := injectbench.DefaultBenchmarkConfig()
	cfg.Iterations = 5
	cfg.TargetRole = "standard"

	summary, err := injectbench.RunBenchmark(nil, cfg)
	if err != nil {
		t.Fatalf("RunBenchmark failed: %v", err)
	}

	if !summary.OverallPassed {
		t.Errorf("expected overall benchmark to pass, bypasses: %v", summary.BypassDetails)
	}

	if summary.AttacksBypassed > 0 {
		t.Errorf("expected 0 attacks bypassed, got %d", summary.AttacksBypassed)
	}

	if summary.FalsePositives > 0 {
		t.Errorf("expected 0 false positives, got %d", summary.FalsePositives)
	}

	if summary.ResilienceScore < 100.0 {
		t.Errorf("expected resilience score 100.0, got %.1f", summary.ResilienceScore)
	}

	if summary.P99LatencyMs > 5.0 {
		t.Errorf("P99 latency %.3fms exceeded 5.0ms SLA", summary.P99LatencyMs)
	}

	// Test Terminal Scorecard
	card := injectbench.RenderTerminalScorecard(summary)
	if !strings.Contains(card, "MCP-INJECTBENCH: EMPIRICAL PROMPT INJECTION") {
		t.Errorf("terminal scorecard missing title")
	}
	if !strings.Contains(card, "[100% DEFENSE PASS]") {
		t.Errorf("terminal scorecard missing passed badge")
	}

	// Test Markdown Exporter
	md := injectbench.RenderMarkdownReport(summary)
	if !strings.Contains(md, "MCP-InjectBench: Empirical Prompt Injection") {
		t.Errorf("markdown report missing title")
	}
	if !strings.Contains(md, "| Vulnerability Class |") {
		t.Errorf("markdown report missing table header")
	}

	// Test JSON Exporter
	jsonStr, err := summary.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}
	if !strings.Contains(jsonStr, `"overall_passed": true`) {
		t.Errorf("json missing overall_passed: true")
	}
}
