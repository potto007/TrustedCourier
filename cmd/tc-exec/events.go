package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Optional diagnostics record no commands, paths, bodies, headers or credential
// values. They describe local broker activity, not TrustedCourier Audit Records.
type brokerEvents struct {
	file *os.File
	mu   sync.Mutex
}

func openBrokerEvents(path string) (*brokerEvents, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &brokerEvents{file: f}, nil
}
func (e *brokerEvents) record(phase string, m message, r reply) {
	if e == nil {
		return
	}
	action := m.Action
	if action != "submit" && action != "dispatch" && action != "request" {
		action = "unknown"
	}
	id := m.Job
	if r.Job != "" {
		id = r.Job
	}
	if !validJobID(id) {
		id = ""
	}
	event := map[string]any{"timestamp": time.Now().UTC(), "event": "broker_" + phase, "action": action, "job": id, "status": r.Status, "denied": r.Error != "", "truncated": r.Truncated}
	e.mu.Lock()
	defer e.mu.Unlock()
	// Diagnostics cannot change authorization or turn an accepted job into a
	// second execution. Logging failure never retries an operation.
	_ = json.NewEncoder(e.file).Encode(event)
}
