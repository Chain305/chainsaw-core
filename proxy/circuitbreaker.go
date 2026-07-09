package proxy

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit breaker is open and the upstream
// is presumed unavailable. Callers should fall through to stale cache or 503.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitState represents the three-state machine of the circuit breaker.
type CircuitState int32

const (
	CircuitClosed   CircuitState = 0
	CircuitOpen     CircuitState = 1
	CircuitHalfOpen CircuitState = 2
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig controls the circuit breaker behaviour.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before the
	// circuit opens. Default: 5.
	FailureThreshold int
	// ResetTimeout is how long the circuit stays open before transitioning
	// to half-open. Default: 30s.
	ResetTimeout time.Duration
	// HalfOpenRequests is the number of probe requests allowed in half-open
	// state before the circuit closes again. Default: 2.
	HalfOpenRequests int
}

func (c CircuitBreakerConfig) withDefaults() CircuitBreakerConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.ResetTimeout <= 0 {
		c.ResetTimeout = 30 * time.Second
	}
	if c.HalfOpenRequests <= 0 {
		c.HalfOpenRequests = 2
	}
	return c
}

// CircuitBreaker implements a simple sliding-window circuit breaker with no
// external dependencies. It is safe for concurrent use.
type CircuitBreaker struct {
	cfg CircuitBreakerConfig

	mu              sync.Mutex
	state           CircuitState
	consecutiveFail int
	lastFailTime    time.Time
	halfOpenPassed  int
}

// NewCircuitBreaker creates a circuit breaker with the given configuration.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{cfg: cfg.withDefaults()}
}

// Allow checks whether a request should be allowed through. Returns false if
// the circuit is open (upstream presumed down). In half-open state, a limited
// number of probe requests are allowed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		if time.Since(cb.lastFailTime) >= cb.cfg.ResetTimeout {
			cb.state = CircuitHalfOpen
			cb.halfOpenPassed = 0
			return true
		}
		return false

	case CircuitHalfOpen:
		if cb.halfOpenPassed < cb.cfg.HalfOpenRequests {
			cb.halfOpenPassed++
			return true
		}
		return false
	}
	return true
}

// RecordSuccess records a successful upstream request. In half-open state,
// enough successes close the circuit.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFail = 0
	if cb.state == CircuitHalfOpen {
		cb.halfOpenPassed++
		if cb.halfOpenPassed >= cb.cfg.HalfOpenRequests {
			cb.state = CircuitClosed
		}
	}
}

// RecordFailure records a failed upstream request. Enough consecutive failures
// trip the circuit open.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFail++
	cb.lastFailTime = time.Now().UTC()

	if cb.state == CircuitHalfOpen {
		// Any failure in half-open immediately re-opens the circuit.
		cb.state = CircuitOpen
		return
	}
	if cb.consecutiveFail >= cb.cfg.FailureThreshold {
		cb.state = CircuitOpen
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Check for automatic transition from open to half-open.
	if cb.state == CircuitOpen && time.Since(cb.lastFailTime) >= cb.cfg.ResetTimeout {
		cb.state = CircuitHalfOpen
		cb.halfOpenPassed = 0
	}
	return cb.state
}

// ConsecutiveFailures returns the current consecutive failure count.
func (cb *CircuitBreaker) ConsecutiveFailures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.consecutiveFail
}

// RecordNetworkFailure classifies the underlying network error before
// deciding whether to count it toward the failure threshold.
//
// DNS resolution failures are treated as transient local network issues
// rather than "upstream is down" signals — a 30-second DNS flap at the
// client's resolver should not trip the breaker and drive every caller
// to stale cache. Counting DNS failures the same as persistent upstream
// 5xx makes the breaker hypersensitive to local networking noise.
//
// The classification is conservative: anything that is NOT identifiably
// a DNS error falls through to [CircuitBreaker.RecordFailure] and
// counts normally. Callers that already know their error is not a DNS
// error (e.g. HTTP 5xx responses) should call RecordFailure directly.
func (cb *CircuitBreaker) RecordNetworkFailure(err error) {
	if err == nil {
		return
	}
	if IsDNSError(err) {
		// Transient DNS — do not open the circuit on this alone. The
		// counter is intentionally NOT bumped so a flapping resolver
		// does not drive cache-only fallback for every caller.
		return
	}
	cb.RecordFailure()
}

// IsDNSError reports whether err is (or wraps) a DNS-resolution error.
// Used by the circuit breaker to classify failures: DNS problems are
// transient local-resolver issues, not evidence that the upstream
// origin is down.
func IsDNSError(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// Fallback: string-match the common wrappers the Go stdlib emits
	// when the DNSError has been flattened (e.g. by url.Error wrapping).
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "server misbehaving"),
		strings.Contains(msg, "dns: "),
		strings.Contains(msg, "lookup "):
		return true
	}
	return false
}
