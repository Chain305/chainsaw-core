package httpclient

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNew_DefaultsApplied(t *testing.T) {
	t.Parallel()

	c := New()
	if c == nil {
		t.Fatal("New returned nil client")
	}
	if c.Timeout != 30*time.Second {
		t.Errorf("default Timeout = %v, want 30s", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.MaxIdleConns != 128 {
		t.Errorf("MaxIdleConns = %d, want 128", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 32 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 32", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}
	if tr.ExpectContinueTimeout != 1*time.Second {
		t.Errorf("ExpectContinueTimeout = %v, want 1s", tr.ExpectContinueTimeout)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false, want true")
	}
	if tr.Proxy == nil {
		t.Error("Proxy is nil, want http.ProxyFromEnvironment")
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil")
	}
}

func TestNew_OptionsOverride(t *testing.T) {
	t.Parallel()

	c := New(
		WithTimeout(7*time.Second),
		WithMaxIdleConnsPerHost(4),
		WithMaxIdleConns(16),
		WithIdleConnTimeout(15*time.Second),
	)
	if c.Timeout != 7*time.Second {
		t.Errorf("Timeout = %v, want 7s", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.MaxIdleConnsPerHost != 4 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 4", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxIdleConns != 16 {
		t.Errorf("MaxIdleConns = %d, want 16", tr.MaxIdleConns)
	}
	if tr.IdleConnTimeout != 15*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 15s", tr.IdleConnTimeout)
	}
}

// countingRoundTripper wraps an http.RoundTripper and counts calls.
type countingRoundTripper struct {
	inner http.RoundTripper
	calls int64
}

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(&c.calls, 1)
	return c.inner.RoundTrip(req)
}

func TestNew_TransportWrapping(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	var counter *countingRoundTripper
	c := New(WithTransport(func(base *http.Transport) http.RoundTripper {
		if base == nil {
			t.Fatal("WithTransport invoked with nil base transport")
		}
		// Sanity-check that the base carries our tuned defaults.
		if base.MaxIdleConnsPerHost != 32 {
			t.Errorf("wrapper saw MaxIdleConnsPerHost = %d, want 32", base.MaxIdleConnsPerHost)
		}
		counter = &countingRoundTripper{inner: base}
		return counter
	}))

	if counter == nil {
		t.Fatal("WithTransport callback was not invoked")
	}
	if c.Transport != counter {
		t.Errorf("client.Transport = %T, want *countingRoundTripper", c.Transport)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if got := atomic.LoadInt64(&counter.calls); got != 1 {
		t.Errorf("wrapper RoundTrip calls = %d, want 1", got)
	}
}
