package firewall

import (
	"testing"
	"time"
)

func TestAgentLoopDetector_PerAgentIsolation(t *testing.T) {
	detector := NewAgentLoopDetector(5, 3, 5*time.Minute)
	args := map[string]interface{}{"query": "status"}

	// Agent 1 makes 3 identical calls -> allowed
	for i := 0; i < 3; i++ {
		isLoop, _ := detector.RecordAndCheck("agent_1", "check_status", args)
		if isLoop {
			t.Fatalf("agent_1 call %d prematurely flagged as loop", i+1)
		}
	}

	// Agent 2 makes 1 call with same tool and args -> should NOT be affected by agent_1
	isLoop2, _ := detector.RecordAndCheck("agent_2", "check_status", args)
	if isLoop2 {
		t.Fatalf("agent_2 should not be affected by agent_1 loop history")
	}

	// Agent 1 makes 4th identical call -> should trigger loop detection
	isLoop1Fourth, reason := detector.RecordAndCheck("agent_1", "check_status", args)
	if !isLoop1Fourth {
		t.Fatalf("expected agent_1 4th call to be flagged as infinite loop")
	}
	if reason == "" {
		t.Errorf("expected non-empty reason for loop block")
	}

	// Reset agent 1
	detector.Reset("agent_1")
	isLoop1AfterReset, _ := detector.RecordAndCheck("agent_1", "check_status", args)
	if isLoop1AfterReset {
		t.Fatalf("agent_1 should be allowed immediately after reset")
	}
}
