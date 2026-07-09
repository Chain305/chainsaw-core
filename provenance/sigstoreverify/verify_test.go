package sigstoreverify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func TestCachedVerifierRetriesAfterFailureBackoff(t *testing.T) {
	fake := clockwork.NewFakeClock()
	calls := 0
	boom := errors.New("transient")
	want := &Verifier{}
	c := &cachedVerifier{
		clock: fake,
		loader: func(ctx context.Context) (*Verifier, error) {
			calls++
			if calls == 1 {
				return nil, boom
			}
			return want, nil
		},
	}

	// First call: fails, caches the error.
	if _, err := c.get(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("first call: want %v, got %v", boom, err)
	}
	if calls != 1 {
		t.Fatalf("first call: want loader invoked once, got %d", calls)
	}

	// Second call within backoff window: should return cached error without
	// invoking the loader again.
	fake.Advance(10 * time.Second)
	if _, err := c.get(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("second call: want cached %v, got %v", boom, err)
	}
	if calls != 1 {
		t.Fatalf("second call: loader should not re-run during backoff, got %d calls", calls)
	}

	// Advance past backoff: next call retries and succeeds.
	fake.Advance(failureBackoff + time.Second)
	got, err := c.get(context.Background())
	if err != nil {
		t.Fatalf("third call: want success, got %v", err)
	}
	if got != want {
		t.Fatalf("third call: want %p, got %p", want, got)
	}
	if calls != 2 {
		t.Fatalf("third call: want loader invoked twice total, got %d", calls)
	}

	// Success is cached for trustRootTTL.
	fake.Advance(trustRootTTL - time.Second)
	if got, err := c.get(context.Background()); err != nil || got != want {
		t.Fatalf("cached-success call: want %p nil, got %p %v", want, got, err)
	}
	if calls != 2 {
		t.Fatalf("cached-success: loader should not re-run, got %d calls", calls)
	}

	// Past TTL: refresh.
	fake.Advance(2 * time.Second)
	if _, err := c.get(context.Background()); err != nil {
		t.Fatalf("post-TTL call: want success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("post-TTL: want loader invoked a third time, got %d calls", calls)
	}
}

func TestInspectBundleIdentityRejectsMalformed(t *testing.T) {
	if _, err := InspectBundleIdentity([]byte("not-json")); err == nil {
		t.Fatal("want error for malformed bundle, got nil")
	}
	if _, err := InspectBundleIdentity([]byte("{}")); err == nil {
		t.Fatal("want error for empty bundle object, got nil")
	}
}

func TestNewLiveVerifierHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	done := make(chan struct{})
	go func() {
		_, _ = NewLiveVerifier(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("NewLiveVerifier did not return after context cancel within 2s")
	}
}
