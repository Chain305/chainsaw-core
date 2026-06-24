package proxy

import (
	"sync"
	"testing"
	"time"
)

func TestNewUpstreamTracker_Defaults(t *testing.T) {
	tr := NewUpstreamTracker(nil)
	if tr.maxWindow != 1000 {
		t.Errorf("maxWindow: got %d, want 1000", tr.maxWindow)
	}
	m := tr.Metrics()
	if m.TotalRequests != 0 || m.TotalErrors != 0 || m.TotalRetries != 0 {
		t.Errorf("fresh tracker should have zero counters: %+v", m)
	}
	if m.CircuitBreakerState != "none" {
		t.Errorf("nil breaker should report 'none', got %q", m.CircuitBreakerState)
	}
	if m.LastErrorTime != nil {
		t.Errorf("no errors yet, LastErrorTime should be nil")
	}
	if m.ErrorRate != 0 {
		t.Errorf("no requests, ErrorRate should be 0, got %v", m.ErrorRate)
	}
}

func TestRecordRequest_Counts(t *testing.T) {
	tr := NewUpstreamTracker(nil)
	tr.RecordRequest(10*time.Millisecond, false)
	tr.RecordRequest(20*time.Millisecond, true)
	tr.RecordRequest(30*time.Millisecond, false)

	m := tr.Metrics()
	if m.TotalRequests != 3 {
		t.Errorf("TotalRequests: got %d, want 3", m.TotalRequests)
	}
	if m.TotalErrors != 1 {
		t.Errorf("TotalErrors: got %d, want 1", m.TotalErrors)
	}
	if m.ErrorRate < 33.3 || m.ErrorRate > 33.4 {
		t.Errorf("ErrorRate: got %v, want ~33.33", m.ErrorRate)
	}
	if m.LastErrorTime == nil {
		t.Error("LastErrorTime should be set after an error")
	}
}

func TestRecordRequest_LatencyAvgAndP95(t *testing.T) {
	tr := NewUpstreamTracker(nil)
	// 10 samples: 10ms..100ms
	for i := 1; i <= 10; i++ {
		tr.RecordRequest(time.Duration(i*10)*time.Millisecond, false)
	}
	m := tr.Metrics()
	// Avg = (10+20+...+100)/10 = 55
	if m.AvgLatencyMs != 55 {
		t.Errorf("AvgLatencyMs: got %v, want 55", m.AvgLatencyMs)
	}
	// p95 idx = int(10*0.95) = 9 -> sorted[9] = 100ms
	if m.P95LatencyMs != 100 {
		t.Errorf("P95LatencyMs: got %v, want 100", m.P95LatencyMs)
	}
}

func TestRecordRequest_SlidingWindow(t *testing.T) {
	tr := NewUpstreamTracker(nil)
	// Push 1200 entries to exceed window of 1000.
	for i := 0; i < 1200; i++ {
		tr.RecordRequest(time.Millisecond, false)
	}
	tr.mu.RLock()
	n := len(tr.latencies)
	tr.mu.RUnlock()
	if n > tr.maxWindow {
		t.Errorf("latencies window exceeded max: %d > %d", n, tr.maxWindow)
	}
	if n == 0 {
		t.Error("latencies should not be empty")
	}
	m := tr.Metrics()
	if m.TotalRequests != 1200 {
		t.Errorf("TotalRequests: got %d, want 1200", m.TotalRequests)
	}
}

func TestRecordRetry(t *testing.T) {
	tr := NewUpstreamTracker(nil)
	tr.RecordRetry()
	tr.RecordRetry()
	tr.RecordRetry()
	m := tr.Metrics()
	if m.TotalRetries != 3 {
		t.Errorf("TotalRetries: got %d, want 3", m.TotalRetries)
	}
}

func TestMetrics_WithCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 2})
	tr := NewUpstreamTracker(cb)

	m := tr.Metrics()
	if m.CircuitBreakerState != "closed" {
		t.Errorf("fresh breaker state: got %q, want closed", m.CircuitBreakerState)
	}

	cb.RecordFailure()
	cb.RecordFailure()
	m = tr.Metrics()
	if m.CircuitBreakerState != "open" {
		t.Errorf("after 2 failures: got %q, want open", m.CircuitBreakerState)
	}
}

func TestRecordRequest_ConcurrentSafe(t *testing.T) {
	tr := NewUpstreamTracker(nil)
	const goroutines = 16
	const perG = 200

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				tr.RecordRequest(time.Millisecond, j%3 == 0)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				tr.RecordRetry()
				_ = tr.Metrics()
			}
		}()
	}
	wg.Wait()

	m := tr.Metrics()
	if m.TotalRequests != goroutines*perG {
		t.Errorf("TotalRequests: got %d, want %d", m.TotalRequests, goroutines*perG)
	}
	if m.TotalRetries != goroutines*perG {
		t.Errorf("TotalRetries: got %d, want %d", m.TotalRetries, goroutines*perG)
	}
	if m.TotalErrors == 0 {
		t.Error("expected some errors recorded concurrently")
	}
}

func TestSortDurations(t *testing.T) {
	in := []time.Duration{5, 3, 8, 1, 4, 2, 7, 6}
	sortDurations(in)
	for i := 1; i < len(in); i++ {
		if in[i-1] > in[i] {
			t.Fatalf("not sorted at %d: %v", i, in)
		}
	}
	// empty and single
	sortDurations(nil)
	sortDurations([]time.Duration{42})
}

func TestUpstreamRegistry_RegisterGet(t *testing.T) {
	reg := NewUpstreamRegistry()
	if got := reg.Get("missing"); got != nil {
		t.Errorf("unknown repo: got %v, want nil", got)
	}
	tr := NewUpstreamTracker(nil)
	reg.Register("pypi", tr)
	if got := reg.Get("pypi"); got != tr {
		t.Errorf("Get returned different tracker")
	}
}

func TestUpstreamRegistry_RegisterOverwrite(t *testing.T) {
	reg := NewUpstreamRegistry()
	a := NewUpstreamTracker(nil)
	b := NewUpstreamTracker(nil)
	reg.Register("pypi", a)
	reg.Register("pypi", b)
	if got := reg.Get("pypi"); got != b {
		t.Errorf("Register should overwrite; got old tracker")
	}
}

func TestUpstreamRegistry_AllMetrics(t *testing.T) {
	reg := NewUpstreamRegistry()
	a := NewUpstreamTracker(nil)
	a.RecordRequest(5*time.Millisecond, false)
	b := NewUpstreamTracker(nil)
	b.RecordRequest(1*time.Millisecond, true)

	reg.Register("pypi", a)
	reg.Register("npm", b)

	all := reg.AllMetrics()
	if len(all) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(all))
	}
	if all["pypi"].TotalRequests != 1 || all["pypi"].TotalErrors != 0 {
		t.Errorf("pypi metrics wrong: %+v", all["pypi"])
	}
	if all["npm"].TotalErrors != 1 {
		t.Errorf("npm metrics wrong: %+v", all["npm"])
	}
}

func TestUpstreamRegistry_AllMetricsEmpty(t *testing.T) {
	reg := NewUpstreamRegistry()
	all := reg.AllMetrics()
	if len(all) != 0 {
		t.Errorf("empty registry should return empty map, got %d", len(all))
	}
}

func TestUpstreamRegistry_ConcurrentSafe(t *testing.T) {
	reg := NewUpstreamRegistry()
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			reg.Register("repo", NewUpstreamTracker(nil))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = reg.Get("repo")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = reg.AllMetrics()
		}
	}()
	wg.Wait()
}

func TestMetrics_SingleRequestAllErrors(t *testing.T) {
	tr := NewUpstreamTracker(nil)
	tr.RecordRequest(50*time.Millisecond, true)
	m := tr.Metrics()
	if m.ErrorRate != 100 {
		t.Errorf("ErrorRate should be 100, got %v", m.ErrorRate)
	}
	if m.AvgLatencyMs != 50 {
		t.Errorf("AvgLatencyMs: got %v, want 50", m.AvgLatencyMs)
	}
	if m.P95LatencyMs != 50 {
		t.Errorf("P95LatencyMs: got %v, want 50", m.P95LatencyMs)
	}
	if m.LastErrorTime == nil {
		t.Error("LastErrorTime should be set")
	}
}
