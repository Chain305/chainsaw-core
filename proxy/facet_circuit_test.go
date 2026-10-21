package proxy

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestFacetHalfOpenProbeAnswered404ClosesCircuit drives a half-open probe
// through the real fetch path against an upstream that answers 404.
//
// A 4xx used to record nothing, so on a proxy whose traffic is mostly
// misses the half-open probes were spent on 404s and the breaker stayed
// half-open with no slots, refusing the next request with ErrCircuitOpen.
// The upstream answered; it is up, and the probe now says so.
//
// Verified by deletion: restoring the `status < 400` guard in
// recordCircuitOutcome makes the third Get fail with ErrCircuitOpen.
func TestFacetHalfOpenProbeAnswered404ClosesCircuit(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Millisecond,
		HalfOpenRequests: 1,
	})
	f, _ := newRevalidationFacet(t, &freshStorage{}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	f.circuitBreaker = cb

	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)

	for _, pkg := range []string{"absent-a", "absent-b", "absent-c"} {
		resp, err := f.Get(context.Background(), &Request{LogicalPath: pkg, Method: http.MethodGet})
		if err != nil {
			t.Fatalf("Get %s: %v (breaker state %s)", pkg, err, cb.State())
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Get %s: status %d, want 404", pkg, resp.StatusCode)
		}
	}
	if s := cb.State(); s != CircuitClosed {
		t.Fatalf("expected the 404 probe to close the circuit, got %s", s)
	}
}

// TestFacetCircuitOutcomeIgnores429 pins the one 4xx that stays
// unrecorded: a rate-limited upstream must not close the circuit.
func TestFacetCircuitOutcomeIgnores429(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Millisecond,
		HalfOpenRequests: 1,
	})
	f := &facet{circuitBreaker: cb}
	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)
	cb.Allow()
	f.recordCircuitOutcome(http.StatusTooManyRequests)
	if s := cb.State(); s != CircuitHalfOpen {
		t.Fatalf("expected 429 to leave the breaker half-open, got %s", s)
	}
}
