package policy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPostgresInvalidationBusNilDSNIsNoOp guards the developer path:
// constructing a bus with an empty DSN must never panic and must not
// try to open a connection. Publish and Subscribe become no-ops so an
// operator running the server without Postgres-backed multi-replica
// policy invalidation stays on the TTL-based fallback.
func TestPostgresInvalidationBusNilDSNIsNoOp(t *testing.T) {
	bus := NewPostgresInvalidationBus("", nil)

	if err := bus.Publish(context.Background(), "chainsaw.policy.invalidate.org-1", nil); err != nil {
		t.Fatalf("Publish on empty-DSN bus must be a no-op, got %v", err)
	}

	cancel, err := bus.Subscribe(context.Background(), "chainsaw.policy.invalidate.*", func(string, []byte) {})
	if err != nil {
		t.Fatalf("Subscribe on empty-DSN bus must be a no-op, got %v", err)
	}
	if cancel == nil {
		t.Fatal("Subscribe on empty-DSN bus must return a non-nil cancel")
	}
	cancel()
}

// TestPostgresInvalidationBusSubscribeNilHandler rejects a nil handler
// early — without this guard the listener loop would wedge inside a
// nil-pointer deref on the first delivery.
func TestPostgresInvalidationBusSubscribeNilHandler(t *testing.T) {
	bus := NewPostgresInvalidationBus("postgres://ignored/ignored", nil)
	_, err := bus.Subscribe(context.Background(), "x.*", nil)
	if err == nil {
		t.Fatal("Subscribe must reject nil handler")
	}
}

// TestPostgresBusRoundTrip exercises the production path end-to-end:
// Publish on one bus → Subscribe on a second bus receives the same
// subject within 2 seconds. Requires a live Postgres; skipped under
// `go test -short` and when CHAINSAW_TEST_PG_DSN is unset so the
// default CI run stays offline.
func TestPostgresBusRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration under -short")
	}
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("CHAINSAW_TEST_PG_DSN not set; skipping live-DB Postgres bus test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sub := NewPostgresInvalidationBus(dsn, nil)
	pub := NewPostgresInvalidationBus(dsn, nil)

	got := make(chan string, 1)
	unsub, err := sub.Subscribe(ctx, invalidateSubjectPattern, func(subject string, _ []byte) {
		select {
		case got <- subject:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()

	// Give the listener a moment to finish LISTEN before we publish.
	time.Sleep(200 * time.Millisecond)

	want := invalidateSubjectFor("org-integration-test")
	if err := pub.Publish(ctx, want, nil); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case subject := <-got:
		if subject != want {
			t.Fatalf("subject mismatch: got %q want %q", subject, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NOTIFY round-trip")
	}
}
