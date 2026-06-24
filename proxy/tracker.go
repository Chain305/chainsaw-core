package proxy

import (
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamMetrics holds per-upstream health metrics for observability.
type UpstreamMetrics struct {
	// TotalRequests is the number of requests made to the upstream.
	TotalRequests int64 `json:"total_requests"`
	// TotalErrors is the number of upstream errors (network + 5xx).
	TotalErrors int64 `json:"total_errors"`
	// TotalRetries is the number of times a fetch was retried.
	TotalRetries int64 `json:"total_retries"`
	// CircuitBreakerState is the current circuit breaker state.
	CircuitBreakerState string `json:"circuit_breaker_state"`
	// ErrorRate is TotalErrors / TotalRequests as a percentage (0-100).
	ErrorRate float64 `json:"error_rate_pct"`
	// AvgLatencyMs is the average upstream latency in milliseconds.
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	// P95LatencyMs is the approximate 95th percentile latency.
	P95LatencyMs float64 `json:"p95_latency_ms"`
	// LastErrorTime is the timestamp of the most recent error.
	LastErrorTime *time.Time `json:"last_error_time,omitempty"`
}

// UpstreamTracker records per-upstream request metrics. Safe for concurrent use.
type UpstreamTracker struct {
	mu        sync.RWMutex
	requests  int64
	errors    int64
	retries   int64
	latencies []time.Duration // sliding window
	maxWindow int
	lastError time.Time
	hasError  bool
	breaker   *CircuitBreaker
}

// NewUpstreamTracker creates a tracker with a sliding window for latency tracking.
func NewUpstreamTracker(breaker *CircuitBreaker) *UpstreamTracker {
	return &UpstreamTracker{
		maxWindow: 1000, // keep last 1000 latencies for percentile calc
		breaker:   breaker,
	}
}

// RecordRequest records a request with its latency and whether it was an error.
func (t *UpstreamTracker) RecordRequest(latency time.Duration, isError bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.requests++
	if len(t.latencies) >= t.maxWindow {
		// Shift window: drop first half to avoid unbounded growth.
		copy(t.latencies, t.latencies[t.maxWindow/2:])
		t.latencies = t.latencies[:t.maxWindow/2]
	}
	t.latencies = append(t.latencies, latency)

	if isError {
		t.errors++
		t.lastError = time.Now()
		t.hasError = true
	}
}

// RecordRetry increments the retry counter.
func (t *UpstreamTracker) RecordRetry() {
	atomic.AddInt64(&t.retries, 1)
}

// Metrics returns a snapshot of the current metrics.
func (t *UpstreamTracker) Metrics() UpstreamMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()

	m := UpstreamMetrics{
		TotalRequests: t.requests,
		TotalErrors:   t.errors,
		TotalRetries:  atomic.LoadInt64(&t.retries),
	}

	if t.requests > 0 {
		m.ErrorRate = float64(t.errors) / float64(t.requests) * 100
	}

	if len(t.latencies) > 0 {
		var total time.Duration
		for _, l := range t.latencies {
			total += l
		}
		m.AvgLatencyMs = float64(total.Milliseconds()) / float64(len(t.latencies))

		// Approximate p95: sort a copy and pick the 95th percentile index.
		sorted := make([]time.Duration, len(t.latencies))
		copy(sorted, t.latencies)
		sortDurations(sorted)
		idx := int(float64(len(sorted)) * 0.95)
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		m.P95LatencyMs = float64(sorted[idx].Milliseconds())
	}

	if t.hasError {
		le := t.lastError
		m.LastErrorTime = &le
	}

	if t.breaker != nil {
		m.CircuitBreakerState = t.breaker.State().String()
	} else {
		m.CircuitBreakerState = "none"
	}

	return m
}

// sortDurations is a simple insertion sort for the latency window.
// The window is capped at 1000 entries so this is fast enough.
func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		key := d[i]
		j := i - 1
		for j >= 0 && d[j] > key {
			d[j+1] = d[j]
			j--
		}
		d[j+1] = key
	}
}

// UpstreamRegistry holds trackers for all configured upstream repositories.
type UpstreamRegistry struct {
	mu       sync.RWMutex
	trackers map[string]*UpstreamTracker // keyed by repo name
}

// NewUpstreamRegistry creates an empty upstream registry.
func NewUpstreamRegistry() *UpstreamRegistry {
	return &UpstreamRegistry{
		trackers: make(map[string]*UpstreamTracker),
	}
}

// Register adds a tracker for the given repository name.
func (r *UpstreamRegistry) Register(repoName string, tracker *UpstreamTracker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trackers[repoName] = tracker
}

// Get returns the tracker for the given repository name, or nil.
func (r *UpstreamRegistry) Get(repoName string) *UpstreamTracker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.trackers[repoName]
}

// AllMetrics returns metrics for all registered upstreams.
func (r *UpstreamRegistry) AllMetrics() map[string]UpstreamMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]UpstreamMetrics, len(r.trackers))
	for name, tracker := range r.trackers {
		result[name] = tracker.Metrics()
	}
	return result
}
