package blobstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newThrottleStore(t *testing.T, handler http.HandlerFunc) BlobStore {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	bs, err := NewS3BlobStore(S3Config{
		Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, UsePathStyle: true,
		AccessKey: "k", SecretKey: "s",
	}, nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return bs
}

// Contabo answers bursts with a bodiless 429 on HEAD. The SDK did not treat
// that as retryable, so every one became an immediate error and a proxy 502
// (78 in four minutes at three concurrent installs, 2026-10-29).
func TestS3HeadRetries429(t *testing.T) {
	var calls atomic.Int32
	bs := newThrottleStore(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Length", "3")
		w.WriteHeader(http.StatusOK)
	})
	info, err := bs.Stat("some/key")
	if err != nil {
		t.Fatalf("Stat after two 429s: %v (calls=%d), want success on retry", err, calls.Load())
	}
	if info.Size() != 3 || calls.Load() != 3 {
		t.Fatalf("size=%d calls=%d, want 3 and 3", info.Size(), calls.Load())
	}
}

// When throttling outlasts the retries the error must say so, so the proxy
// can answer a retriable 503 rather than an untyped 502.
func TestS3PersistentThrottleIsErrUnavailable(t *testing.T) {
	bs := newThrottleStore(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	if _, err := bs.Stat("some/key"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Stat under persistent 429: %v, want ErrUnavailable", err)
	}
	if _, err := bs.Open("some/key"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open under persistent 429: %v, want ErrUnavailable", err)
	}
	if _, err := bs.Stat("some/key"); errors.Is(err, ErrBlobNotFound) {
		t.Fatal("throttling must not read as not-found")
	}
}

type outcomeRecorder struct{ outcomes []string }

func (o *outcomeRecorder) ObserveOp(op, outcome string, _ float64) {
	o.outcomes = append(o.outcomes, op+":"+outcome)
}

// Throttling is its own outcome on the blob-store metric, apart from error
// and not_found (J.2 A1): it is the store pushing back, which retries and
// the disk tier absorb, not a fault on our side.
func TestS3OutcomeSeparatesThrottling(t *testing.T) {
	status := http.StatusTooManyRequests
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	rec := &outcomeRecorder{}
	bs, err := NewS3BlobStore(S3Config{
		Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, UsePathStyle: true,
		AccessKey: "k", SecretKey: "s",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bs.(*S3BlobStore).observer = rec
	_, _ = bs.Open("k")
	status = http.StatusForbidden
	_, _ = bs.Open("k")
	status = http.StatusNotFound
	_, _ = bs.Open("k")
	want := []string{"get:throttled", "get:error", "get:not_found"}
	if strings.Join(rec.outcomes, ",") != strings.Join(want, ",") {
		t.Fatalf("outcomes %v, want %v", rec.outcomes, want)
	}
	if got := s3Outcome(context.DeadlineExceeded); got != "timeout" {
		t.Fatalf("deadline outcome %q, want timeout", got)
	}
}

// Requests past the in-flight cap wait for a slot only as long as the
// header timeout and then fail as ErrUnavailable (a retriable 503), and a
// HEAD the store never answers gives up at its own short timeout (J.2 A2).
func TestS3InflightCapAndHeaderTimeout(t *testing.T) {
	stall := make(chan struct{})
	var reached atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		<-stall
	}))
	defer srv.Close()
	defer close(stall)
	bs, err := NewS3BlobStore(S3Config{
		Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, UsePathStyle: true,
		AccessKey: "k", SecretKey: "s",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := bs.(*S3BlobStore)
	s.inflight = make(chan struct{}, 1)
	s.getTimeout, s.headTimeout = 300*time.Millisecond, 200*time.Millisecond

	s.inflight <- struct{}{} // the only slot is taken
	start := time.Now()
	if _, err := s.Open("k"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open with no free slot = %v, want ErrUnavailable", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("Open waited %v for a slot; its timeout is 300ms", waited)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("a request past the in-flight cap reached the store (%d)", n)
	}
	<-s.inflight

	start = time.Now()
	if _, err := s.Stat("k"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Stat against a silent store = %v, want ErrUnavailable", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("Stat waited %v; its header timeout is 200ms", waited)
	}
	if len(s.inflight) != 0 {
		t.Fatal("a timed-out Stat kept its slot")
	}
}
