package pgstore

import (
	"context"
	"os"
	"testing"
)

// Background-marked work reads the background pool when one is open, and
// everything else the write pool; with none open, all of it shares the
// write pool as before (J.3).
func TestDBForRoutesBackgroundWork(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	bg := WithBackground(ctx)

	if s.DBFor(bg) != s.DB() {
		t.Fatal("with no background pool open, background work did not share the write pool")
	}
	if err := s.OpenBackgroundPool(dsn, PoolConfig{MaxOpenConns: 0}); err != nil || s.DBFor(bg) != s.DB() {
		t.Fatalf("a 0-connection background pool opened (err %v)", err)
	}
	if err := s.OpenBackgroundPool(dsn, PoolConfig{MaxOpenConns: 2}); err != nil {
		t.Fatal(err)
	}
	if s.DBFor(bg) == s.DB() || s.DBFor(ctx) != s.DB() {
		t.Fatal("background work is not on its own pool, or foreground work moved to it")
	}
	if err := s.DBFor(bg).PingContext(bg); err != nil {
		t.Fatal(err)
	}
	if got := s.DBFor(bg).Stats().MaxOpenConnections; got != 2 {
		t.Fatalf("background pool max open = %d, want 2", got)
	}
}
