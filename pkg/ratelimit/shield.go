package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

type clientCallRecord struct {
	timestamps  []time.Time
	isolatedUntil time.Time
}

// FloodShield detects recursive agent loops and rapid runaway spikes.
type FloodShield struct {
	mu           sync.Mutex
	window       time.Duration
	ceiling      int
	cooloff      time.Duration
	records      map[string]*clientCallRecord
	trippedCount int64
}

// NewFloodShield creates a new runaway loop shield.
func NewFloodShield(window time.Duration, ceiling int, cooloff time.Duration) *FloodShield {
	if window <= 0 {
		window = 100 * time.Millisecond
	}
	if cooloff <= 0 {
		cooloff = 5 * time.Second
	}
	return &FloodShield{
		window:  window,
		ceiling: ceiling,
		cooloff: cooloff,
		records: make(map[string]*clientCallRecord),
	}
}

// Check verifies whether the client is allowed or currently quarantined by the circuit breaker.
func (fs *FloodShield) Check(clientID string) (bool, error) {
	if fs.ceiling <= 0 {
		return true, nil
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := time.Now()
	rec, exists := fs.records[clientID]
	if !exists {
		rec = &clientCallRecord{
			timestamps: make([]time.Time, 0, fs.ceiling+5),
		}
		fs.records[clientID] = rec
	}

	// Check if already isolated
	if now.Before(rec.isolatedUntil) {
		remaining := rec.isolatedUntil.Sub(now)
		return false, fmt.Errorf("runaway loop circuit breaker open: client %s quarantined for %.1fs",
			clientID, remaining.Seconds())
	}

	// Prune timestamps older than window
	cutoff := now.Add(-fs.window)
	validIdx := 0
	for i, t := range rec.timestamps {
		if t.After(cutoff) {
			validIdx = i
			break
		}
		if i == len(rec.timestamps)-1 {
			validIdx = len(rec.timestamps)
		}
	}
	rec.timestamps = rec.timestamps[validIdx:]

	// Append current call
	rec.timestamps = append(rec.timestamps, now)

	// Check if ceiling exceeded within window
	if len(rec.timestamps) > fs.ceiling {
		rec.isolatedUntil = now.Add(fs.cooloff)
		fs.trippedCount++
		return false, fmt.Errorf("runaway agent loop detected: %d calls within %v (ceiling: %d). Circuit breaker activated for %v",
			len(rec.timestamps), fs.window, fs.ceiling, fs.cooloff)
	}

	return true, nil
}

// TrippedCount returns total circuit breaker trips.
func (fs *FloodShield) TrippedCount() int64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.trippedCount
}

// Reset clears all client histories and isolation states.
func (fs *FloodShield) Reset() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.records = make(map[string]*clientCallRecord)
	fs.trippedCount = 0
}
