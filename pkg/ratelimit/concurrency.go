package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// ConcurrencyGovernor manages in-flight active request concurrency per client and tool.
type ConcurrencyGovernor struct {
	mu                 sync.Mutex
	clientInFlight     map[string]int
	toolInFlight       map[string]map[string]int // clientID -> toolName -> count
	defaultMaxClient   int
	toolMaxConcurrency map[string]int
	activeLeases       int
}

// NewConcurrencyGovernor creates a new concurrency governor.
func NewConcurrencyGovernor(defaultMaxClient int, toolMax map[string]int) *ConcurrencyGovernor {
	if toolMax == nil {
		toolMax = make(map[string]int)
	}
	return &ConcurrencyGovernor{
		clientInFlight:     make(map[string]int),
		toolInFlight:       make(map[string]map[string]int),
		defaultMaxClient:   defaultMaxClient,
		toolMaxConcurrency: toolMax,
	}
}

// AcquireLease attempts to grant an active concurrency lease for client and tool.
func (cg *ConcurrencyGovernor) AcquireLease(clientID, toolName string) (*ConcurrencyLease, error) {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	// Check per-client concurrency
	clientCount := cg.clientInFlight[clientID]
	if cg.defaultMaxClient > 0 && clientCount >= cg.defaultMaxClient {
		return nil, fmt.Errorf("concurrency ceiling reached for client %s (%d/%d in-flight)",
			clientID, clientCount, cg.defaultMaxClient)
	}

	// Check per-tool concurrency
	if toolName != "" {
		if maxTool, exists := cg.toolMaxConcurrency[toolName]; exists && maxTool > 0 {
			if _, ok := cg.toolInFlight[clientID]; !ok {
				cg.toolInFlight[clientID] = make(map[string]int)
			}
			toolCount := cg.toolInFlight[clientID][toolName]
			if toolCount >= maxTool {
				return nil, fmt.Errorf("tool concurrency ceiling reached for client %s tool %s (%d/%d in-flight)",
					clientID, toolName, toolCount, maxTool)
			}
		}
	}

	// Increment counters
	cg.clientInFlight[clientID]++
	if toolName != "" {
		if _, ok := cg.toolInFlight[clientID]; !ok {
			cg.toolInFlight[clientID] = make(map[string]int)
		}
		cg.toolInFlight[clientID][toolName]++
	}
	cg.activeLeases++

	leaseID := fmt.Sprintf("lease_%s_%d", clientID, time.Now().UnixNano())

	lease := &ConcurrencyLease{
		ID:         leaseID,
		ClientID:   clientID,
		ToolName:   toolName,
		AcquiredAt: time.Now(),
		releaseFn: func() {
			cg.releaseLease(clientID, toolName)
		},
	}

	return lease, nil
}

// releaseLease decrements in-flight counters.
func (cg *ConcurrencyGovernor) releaseLease(clientID, toolName string) {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	if cg.clientInFlight[clientID] > 0 {
		cg.clientInFlight[clientID]--
		if cg.clientInFlight[clientID] == 0 {
			delete(cg.clientInFlight, clientID)
		}
	}

	if toolName != "" {
		if tools, ok := cg.toolInFlight[clientID]; ok {
			if tools[toolName] > 0 {
				tools[toolName]--
				if tools[toolName] == 0 {
					delete(tools, toolName)
				}
			}
			if len(tools) == 0 {
				delete(cg.toolInFlight, clientID)
			}
		}
	}

	if cg.activeLeases > 0 {
		cg.activeLeases--
	}
}

// GetInFlight returns current active concurrent requests for client.
func (cg *ConcurrencyGovernor) GetInFlight(clientID string) int {
	cg.mu.Lock()
	defer cg.mu.Unlock()
	return cg.clientInFlight[clientID]
}

// GetActiveLeases returns total in-flight requests across all clients.
func (cg *ConcurrencyGovernor) GetActiveLeases() int {
	cg.mu.Lock()
	defer cg.mu.Unlock()
	return cg.activeLeases
}

// Reset clears all in-flight tracking.
func (cg *ConcurrencyGovernor) Reset() {
	cg.mu.Lock()
	defer cg.mu.Unlock()
	cg.clientInFlight = make(map[string]int)
	cg.toolInFlight = make(map[string]map[string]int)
	cg.activeLeases = 0
}
