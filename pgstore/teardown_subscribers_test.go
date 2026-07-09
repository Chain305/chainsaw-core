package pgstore

import (
	"context"
	"os"
	"testing"
)

// Integration coverage for AddTeardownSubscriber. Only runs when
// CHAINSAW_DATABASE_URL points at a real Postgres; skips otherwise, the
// same pattern as the rest of the pgstore integration suite. Proves the
// launch-C1 dedup invariant at the DB layer: a duplicate email is a no-op
// (single row, inserted=false), which is what lets the public
// /teardowns/subscribe handler return the SAME response for a new vs.
// existing email without becoming an enumeration oracle.
func TestAddTeardownSubscriber_DedupSingleRow(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	const email = "pgstore_test.teardown@example.com"

	// Clean any prior run's row so the assertions are deterministic.
	if _, err := store.DB().ExecContext(ctx,
		`DELETE FROM teardown_subscribers WHERE email=$1`, email); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.DB().ExecContext(context.Background(),
			`DELETE FROM teardown_subscribers WHERE email=$1`, email)
	})

	// First insert: genuinely new → inserted=true.
	inserted, err := store.AddTeardownSubscriber(ctx, email, "teardowns")
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if !inserted {
		t.Fatal("first insert: inserted=false, want true (new email)")
	}

	// Second insert of the SAME email: ON CONFLICT DO NOTHING → no-op,
	// inserted=false, and crucially no error (so the handler returns the
	// same 200 it did the first time).
	inserted, err = store.AddTeardownSubscriber(ctx, email, "show_hn")
	if err != nil {
		t.Fatalf("duplicate insert returned error (must be a silent no-op): %v", err)
	}
	if inserted {
		t.Fatal("duplicate insert: inserted=true, want false (dedup)")
	}

	// Exactly one row survives for this email.
	var count int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM teardown_subscribers WHERE email=$1`, email).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("row count = %d, want exactly 1 after a duplicate insert", count)
	}

	// The surviving row kept the ORIGINAL source (the conflict path did
	// not overwrite it) — confirms DO NOTHING, not DO UPDATE.
	var source string
	if err := store.DB().QueryRowContext(ctx,
		`SELECT source FROM teardown_subscribers WHERE email=$1`, email).Scan(&source); err != nil {
		t.Fatalf("select source: %v", err)
	}
	if source != "teardowns" {
		t.Fatalf("source = %q, want %q (DO NOTHING must not overwrite)", source, "teardowns")
	}
}
