package blobstore

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// TestS3OpenBodySurvivesAfterHeaders is the 2026-10-10 prod 502: Open
// cancelled its context the moment GetObject returned the headers, and the
// SDK ties the body stream to that context. Any body not already buffered
// read "context canceled", so every proxy cache hit served from S3 failed
// ("read gzip response: context canceled") unless the object was tiny.
func TestS3OpenBodySurvivesAfterHeaders(t *testing.T) {
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	const chunks = 8
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(chunk)*chunks))
		w.WriteHeader(http.StatusOK)
		for i := 0; i < chunks; i++ {
			_, _ = w.Write(chunk)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()

	bs, err := NewS3BlobStore(S3Config{
		Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, UsePathStyle: true,
		AccessKey: "k", SecretKey: "s",
	}, nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	rc, err := bs.Open("some/key")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading the body after Open returned: %v", err)
	}
	if len(got) != len(chunk)*chunks {
		t.Fatalf("read %d bytes, want %d", len(got), len(chunk)*chunks)
	}
}
