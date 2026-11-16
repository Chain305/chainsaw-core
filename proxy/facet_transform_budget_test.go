package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

func withTransformBudget(t *testing.T, mib int64, wait time.Duration) {
	t.Helper()
	prevSem, prevWait := transformBudget, transformBudgetWait
	transformBudget, transformBudgetWait = semaphore.NewWeighted(mib), wait
	t.Cleanup(func() { transformBudget, transformBudgetWait = prevSem, prevWait })
}

// An upstream's Content-Length is a claim, not bytes: one that says 256 MiB
// over a 100-byte body must not get a 256 MiB buffer.
func TestReadTransformBodyDoesNotTrustLyingLength(t *testing.T) {
	got, release, err := readTransformBody(context.Background(), bytes.NewReader(make([]byte, 100)), MaxTransformBodySize)
	defer release()
	if err != nil || len(got) != 100 {
		t.Fatalf("read %d bytes, err %v", len(got), err)
	}
	if cap(got) > transformInitialAlloc {
		t.Fatalf("a 100-byte body claiming %d bytes got a %d-byte buffer", MaxTransformBodySize, cap(got))
	}
}

// The budget is process-wide: a second large read waits until the first
// releases, and a waiter whose context ends is refused, never served.
func TestTransformBudgetBlocksUntilRelease(t *testing.T) {
	withTransformBudget(t, 16, time.Minute)
	body := make([]byte, 10<<20)
	_, release1, err := readTransformBody(context.Background(), bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, release2, err := readTransformBody(context.Background(), bytes.NewReader(body), int64(len(body)))
		release2()
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("second read finished while the first held the budget (err %v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	release1()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second read after release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second read still blocked after the first released")
	}
}

func TestTransformBudgetCancelledWaiterIsRefused(t *testing.T) {
	withTransformBudget(t, 16, time.Minute)
	if !transformBudget.TryAcquire(16) {
		t.Fatal("budget not free")
	}
	defer transformBudget.Release(16)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, release, err := readTransformBody(ctx, bytes.NewReader([]byte("x")), 1)
	release()
	if !errors.Is(err, errTransformBudget) {
		t.Fatalf("err = %v, want errTransformBudget", err)
	}
}

// With the budget exhausted the facet refuses the document: it is never
// served (or cached) untransformed.
func TestFacetRefusesWhenTransformBudgetExhausted(t *testing.T) {
	withTransformBudget(t, 1, 50*time.Millisecond)
	if !transformBudget.TryAcquire(1) {
		t.Fatal("budget not free")
	}
	defer transformBudget.Release(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "abc")
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")
	store := &capturingStorage{}
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: store, Rewrite: upperTransformer{},
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})
	resp, err := f.Get(context.Background(), &Request{LogicalPath: "doc", Method: http.MethodGet, Header: http.Header{}})
	if err == nil {
		t.Fatalf("served status %d with the transform budget exhausted", resp.StatusCode)
	}
	if store.stored != 0 {
		t.Fatalf("stored %d bytes with the transform budget exhausted", store.stored)
	}
}
