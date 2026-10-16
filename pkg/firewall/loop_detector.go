package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

// LoopDetector tracks consecutive tool calls to prevent infinite loops (OWASP-LLM08).
type LoopDetector struct {
	mu            sync.Mutex
	history       []string // Ring buffer of recent tool call signature hashes
	maxWindowSize int
	maxRepetitions int
}

// NewLoopDetector initializes a sliding-window recursive tool loop detector.
func NewLoopDetector(windowSize, maxRepetitions int) *LoopDetector {
	if windowSize <= 0 {
		windowSize = 8
	}
	if maxRepetitions <= 0 {
		maxRepetitions = 3
	}
	return &LoopDetector{
		history:        make([]string, 0, windowSize),
		maxWindowSize:  windowSize,
		maxRepetitions: maxRepetitions,
	}
}

// RecordAndCheck calculates a call digest and returns true if a loop is detected.
func (ld *LoopDetector) RecordAndCheck(toolName string, args map[string]interface{}) (bool, string) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	b, _ := json.Marshal(args)
	h := sha256.Sum256([]byte(toolName + ":" + string(b)))
	digest := hex.EncodeToString(h[:16])

	// Count occurrences in current history window
	repetitions := 0
	for _, past := range ld.history {
		if past == digest {
			repetitions++
		}
	}

	// Append to sliding window
	if len(ld.history) >= ld.maxWindowSize {
		ld.history = ld.history[1:]
	}
	ld.history = append(ld.history, digest)

	if repetitions >= ld.maxRepetitions {
		return true, fmt.Sprintf("infinite loop detected: tool '%s' with identical parameters invoked %d times in sliding window", toolName, repetitions+1)
	}

	return false, ""
}
