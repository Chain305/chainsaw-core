package pgstore

import (
	"os"
	"testing"
)

// TestReadPoolRewritesPlaceholders: every query in this codebase is written
// with `?` placeholders and relies on rewriteConnector to turn them into
// Postgres `$N`. The read pool was opened with a bare sql.OpenDB(connector),
// so once CHAINSAW_DATABASE_READ_URL was set in prod (2026-09-24) every query
// routed through ReadDB() failed with "syntax error at or near AND" / "at end
// of input": /api/violations/blocked answered 503 on every call, the durable
// audit log and the inventory drift detector failed on every tick.
func TestReadPoolRewritesPlaceholders(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("CHAINSAW_DATABASE_URL")
	}
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") == "1" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB=1 but no database DSN is set")
		}
		t.Skip("no database DSN")
	}
	db, err := openReadOnlyWithPool(dsn, PoolConfig{})
	if err != nil {
		t.Fatalf("open read pool: %v", err)
	}
	defer db.Close()
	var got int
	if err := db.QueryRow(`SELECT ?::int + ? WHERE ? = ?`, 40, 2, "a", "a").Scan(&got); err != nil {
		t.Fatalf("`?` query on the read pool: %v", err)
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}
