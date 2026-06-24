package proxy

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCircuitBreakerStartsClosed(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{})
	if s := cb.State(); s != CircuitClosed {
		t.Fatalf("expected closed, got %s", s)
	}
	if !cb.Allow() {
		t.Fatal("expected Allow to return true when closed")
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     1 * time.Second,
	})

	// 2 failures should keep circuit closed
	cb.RecordFailure()
	cb.RecordFailure()
	if s := cb.State(); s != CircuitClosed {
		t.Fatalf("expected closed after 2 failures, got %s", s)
	}

	// 3rd failure trips the circuit
	cb.RecordFailure()
	if s := cb.State(); s != CircuitOpen {
		t.Fatalf("expected open after 3 failures, got %s", s)
	}

	// Allow should return false when open
	if cb.Allow() {
		t.Fatal("expected Allow to return false when open")
	}
}

func TestCircuitBreakerSuccessResetsCount(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     1 * time.Second,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // resets consecutive count
	cb.RecordFailure()
	cb.RecordFailure()

	if s := cb.State(); s != CircuitClosed {
		t.Fatalf("expected closed after reset, got %s", s)
	}
}

func TestCircuitBreakerTransitionsToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
		HalfOpenRequests: 2,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	if s := cb.State(); s != CircuitOpen {
		t.Fatalf("expected open, got %s", s)
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	if s := cb.State(); s != CircuitHalfOpen {
		t.Fatalf("expected half-open after timeout, got %s", s)
	}

	// Should allow probe requests
	if !cb.Allow() {
		t.Fatal("expected Allow in half-open")
	}
}

func TestCircuitBreakerHalfOpenClosesOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
		HalfOpenRequests: 2,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(60 * time.Millisecond)

	// Transition to half-open via Allow
	cb.Allow()

	// Successes in half-open close the circuit
	cb.RecordSuccess()
	cb.RecordSuccess()

	if s := cb.State(); s != CircuitClosed {
		t.Fatalf("expected closed after half-open successes, got %s", s)
	}
}

func TestCircuitBreakerHalfOpenReopensOnFailure(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
		HalfOpenRequests: 2,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(60 * time.Millisecond)

	// Transition to half-open
	cb.Allow()

	// Failure in half-open immediately re-opens
	cb.RecordFailure()
	if s := cb.State(); s != CircuitOpen {
		t.Fatalf("expected open after half-open failure, got %s", s)
	}
}

func TestCircuitBreakerDefaults(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{})
	if cb.cfg.FailureThreshold != 5 {
		t.Fatalf("expected default threshold 5, got %d", cb.cfg.FailureThreshold)
	}
	if cb.cfg.ResetTimeout != 30*time.Second {
		t.Fatalf("expected default reset 30s, got %v", cb.cfg.ResetTimeout)
	}
	if cb.cfg.HalfOpenRequests != 2 {
		t.Fatalf("expected default half-open 2, got %d", cb.cfg.HalfOpenRequests)
	}
}

func TestRecordNetworkFailureClassifiesDNSAsTransient(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 2})

	// DNS errors should not trip the breaker even in excess of the threshold.
	dnsErr := &net.DNSError{Err: "no such host", Name: "upstream.example.com", IsNotFound: true}
	for range 10 {
		cb.RecordNetworkFailure(dnsErr)
	}
	if s := cb.State(); s != CircuitClosed {
		t.Fatalf("expected DNS errors to leave circuit closed, got %s", s)
	}
	if n := cb.ConsecutiveFailures(); n != 0 {
		t.Fatalf("expected no counted failures for DNS errors, got %d", n)
	}

	// A subsequent non-DNS error counts normally.
	cb.RecordNetworkFailure(errors.New("connection refused"))
	cb.RecordNetworkFailure(errors.New("i/o timeout"))
	if s := cb.State(); s != CircuitOpen {
		t.Fatalf("expected circuit to open after non-DNS errors, got %s", s)
	}
}

func TestIsDNSError(t *testing.T) {
	if !IsDNSError(&net.DNSError{Err: "no such host", Name: "x"}) {
		t.Error("expected net.DNSError to be classified as DNS")
	}
	if !IsDNSError(fmt.Errorf("wrapped: %w", &net.DNSError{Err: "server misbehaving", Name: "x"})) {
		t.Error("expected wrapped DNSError to be classified as DNS")
	}
	if !IsDNSError(errors.New("lookup upstream.example.com: no such host")) {
		t.Error("expected flattened lookup error to be classified as DNS")
	}
	if IsDNSError(errors.New("connection refused")) {
		t.Error("connection refused should not be classified as DNS")
	}
	if IsDNSError(nil) {
		t.Error("nil error should not be classified as DNS")
	}
}

func TestCircuitStateString(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("CircuitState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}
