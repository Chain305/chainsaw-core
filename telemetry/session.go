package telemetry

// Each process gets a single session_id that tags every event it emits.
// For a short-lived CLI invocation this is effectively the run-id; for a
// long-running MCP server or chainproxy daemon this rotates at process
// boundary so analytics can scope per-restart windows.

import (
	"sync"

	"github.com/google/uuid"
)

var (
	sessionOnce sync.Once
	sessionID   string
)

// SessionID returns a stable UUIDv7 for the life of the process. Cheap
// after the first call. Never returns an error — a UUID generation
// failure is so unlikely that we fall back to a constant sentinel
// rather than propagate the error up every emission site.
func SessionID() string {
	sessionOnce.Do(func() {
		id, err := uuid.NewV7()
		if err != nil {
			sessionID = "session:unavailable"
			return
		}
		sessionID = id.String()
	})
	return sessionID
}
