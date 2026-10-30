package blobstore

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestS3(t *testing.T, h http.HandlerFunc) *S3BlobStore {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	bs, err := NewS3BlobStore(S3Config{
		Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, UsePathStyle: true,
		AccessKey: "k", SecretKey: "s",
	}, nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return bs.(*S3BlobStore)
}

// The 2026-10-30 prod 500s: Contabo took longer than the header timeout,
// Open's own timer cancelled the GET, and the SDK reported
// context.Canceled, which isS3Unavailable did not recognise. The proxy
// answered 500 (a server bug) instead of 503 + Retry-After (the store
// pushing back). Nothing is served either way; only the status changes.
func TestS3OpenHeaderTimeoutIsUnavailable(t *testing.T) {
	release := make(chan struct{})
	bs := newTestS3(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	bs.getTimeout = 150 * time.Millisecond

	_, err := bs.Open("some/key")
	if err == nil {
		t.Fatal("Open succeeded against a store that never answered")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("header timeout = %v, want it to wrap ErrUnavailable (503, not 500)", err)
	}
}

// A connection the store drops (curl 35/56 in the 2026-10-30 R2/Contabo
// bench) is the store failing, not a missing or corrupt object.
func TestS3OpenConnectionResetIsUnavailable(t *testing.T) {
	bs := newTestS3(t, func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})

	_, err := bs.Open("some/key")
	if err == nil {
		t.Fatal("Open succeeded against a store that dropped the connection")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dropped connection = %v, want it to wrap ErrUnavailable", err)
	}
}

// Negative control: a real 403 is a configuration fault, not the store
// pushing back, and must stay a plain error (500).
func TestS3OpenForbiddenIsNotUnavailable(t *testing.T) {
	bs := newTestS3(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := bs.Open("some/key")
	if err == nil {
		t.Fatal("Open succeeded against a 403")
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("403 = %v classified as unavailable; it is a fault, not back-pressure", err)
	}
}
