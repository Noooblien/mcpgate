package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Noooblien/mcpgate/pkg/spec"
)

// AuditLedger manages an append-only, tamper-evident audit log of gateway interceptions.
type AuditLedger struct {
	mu          sync.Mutex
	filePath    string
	prevHash    string
	totalEvents int64
}

// NewAuditLedger opens or initializes the audit ledger file.
func NewAuditLedger(filePath string) (*AuditLedger, error) {
	if filePath == "" {
		filePath = "./.audit/mcpgate_audit.jsonl"
	}

	_ = os.MkdirAll("./.audit", 0755)

	ledger := &AuditLedger{
		filePath: filePath,
		prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	// Read existing entries to determine last hash
	if f, err := os.Open(filePath); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var ev spec.InterceptEvent
			if err := json.Unmarshal(scanner.Bytes(), &ev); err == nil {
				ledger.prevHash = ev.PayloadDigest
				ledger.totalEvents++
			}
		}
	}

	return ledger, nil
}

// RecordInterception appends an event to the ledger with rolling SHA-256 hash chaining.
func (l *AuditLedger) RecordInterception(event spec.InterceptEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	// Compute chained digest
	h := sha256.New()
	h.Write([]byte(l.prevHash))
	h.Write([]byte(event.EventID))
	h.Write([]byte(event.AgentID))
	h.Write([]byte(string(event.Verdict)))
	h.Write([]byte(event.ToolName))
	h.Write([]byte(event.Timestamp.Format(time.RFC3339Nano)))
	digest := hex.EncodeToString(h.Sum(nil))

	event.PayloadDigest = digest
	l.prevHash = digest
	l.totalEvents++

	line, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}

	return nil
}

// VerifyIntegrity reads all events from disk and checks the cryptographic hash chain.
func (l *AuditLedger) VerifyIntegrity() (bool, int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, 0, nil
		}
		return false, 0, err
	}
	defer f.Close()

	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	count := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev spec.InterceptEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			return false, count, fmt.Errorf("corrupt JSON entry at index %d: %w", count, err)
		}

		h := sha256.New()
		h.Write([]byte(expectedPrev))
		h.Write([]byte(ev.EventID))
		h.Write([]byte(ev.AgentID))
		h.Write([]byte(string(ev.Verdict)))
		h.Write([]byte(ev.ToolName))
		h.Write([]byte(ev.Timestamp.Format(time.RFC3339Nano)))
		calculated := hex.EncodeToString(h.Sum(nil))

		if calculated != ev.PayloadDigest {
			return false, count, fmt.Errorf("hash chain mismatch at entry %d (%s): expected %s, got %s",
				count, ev.EventID, calculated, ev.PayloadDigest)
		}

		expectedPrev = calculated
		count++
	}

	return true, count, nil
}
