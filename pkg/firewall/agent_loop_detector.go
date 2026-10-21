package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentLoopDetector tracks sliding-window execution loops per agent across tool calls.
type AgentLoopDetector struct {
	mu             sync.Mutex
	agentHistory   map[string][]loopEntry
	windowSize     int
	maxRepetitions int
	ttl            time.Duration
}

type loopEntry struct {
	digest    string
	toolName  string
	timestamp time.Time
}

// NewAgentLoopDetector initializes a thread-safe multi-agent sliding-window loop detector.
func NewAgentLoopDetector(windowSize, maxRepetitions int, ttl time.Duration) *AgentLoopDetector {
	if windowSize <= 0 {
		windowSize = 8
	}
	if maxRepetitions <= 0 {
		maxRepetitions = 3
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &AgentLoopDetector{
		agentHistory:   make(map[string][]loopEntry),
		windowSize:     windowSize,
		maxRepetitions: maxRepetitions,
		ttl:            ttl,
	}
}

// RecordAndCheck calculates a call digest for the specific agent and returns true if an execution loop is detected.
func (ald *AgentLoopDetector) RecordAndCheck(agentID, toolName string, args map[string]interface{}) (bool, string) {
	ald.mu.Lock()
	defer ald.mu.Unlock()

	now := time.Now()
	b, _ := json.Marshal(args)
	h := sha256.Sum256([]byte(toolName + ":" + string(b)))
	digest := hex.EncodeToString(h[:16])

	history := ald.agentHistory[agentID]

	// Filter expired entries
	valid := history[:0]
	for _, entry := range history {
		if now.Sub(entry.timestamp) <= ald.ttl {
			valid = append(valid, entry)
		}
	}
	history = valid

	// Count repetitions of identical tool & arguments in the sliding window
	repetitions := 0
	for _, entry := range history {
		if entry.digest == digest {
			repetitions++
		}
	}

	// Append current execution
	if len(history) >= ald.windowSize {
		history = history[1:]
	}
	history = append(history, loopEntry{
		digest:    digest,
		toolName:  toolName,
		timestamp: now,
	})
	ald.agentHistory[agentID] = history

	if repetitions >= ald.maxRepetitions {
		return true, fmt.Sprintf("infinite tool execution loop detected for agent '%s': tool '%s' with identical parameters invoked %d times in sliding window (OWASP-LLM08)", agentID, toolName, repetitions+1)
	}

	return false, ""
}

// Reset clears the execution history for a given agent.
func (ald *AgentLoopDetector) Reset(agentID string) {
	ald.mu.Lock()
	defer ald.mu.Unlock()
	delete(ald.agentHistory, agentID)
}
