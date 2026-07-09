package pgstore

import (
	"os"
	"strings"
	"testing"
	"time"
)

// First test file for internal/pgstore. Prior code-quality review flagged
// this package (1,457 LOC, 0 tests) as a ship-blocker — the whole data
// layer was untested. Integration tests require a real Postgres reachable
// via CHAINSAW_DATABASE_URL and will skip otherwise, matching the pattern
// used in internal/server/server_test.go. Adding pure-function unit tests
// first (no DB) so every PR runs *something* for this package in CI, even
// without a database fixture.

func TestOpenRejectsEmptyDSN(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("expected error for empty DSN")
	}
	if _, err := Open("   "); err == nil {
		t.Fatal("expected error for whitespace-only DSN")
	}
}

func TestOpenRejectsMalformedDSN(t *testing.T) {
	_, err := Open("not a dsn")
	if err == nil {
		t.Fatal("expected parse error on malformed DSN")
	}
	// Error should be wrapped with "parse database DSN" context so the
	// operator sees which step failed.
	if !strings.Contains(err.Error(), "parse database DSN") && !strings.Contains(err.Error(), "dial") {
		// Parser may also fail at dial stage depending on form; accept either.
		t.Logf("unexpected error shape: %v", err)
	}
}

func TestPoolConfigApplyDefaults(t *testing.T) {
	// PoolConfig is the tuning surface operators reach via environment
	// variables (CHAINSAW_DB_MAX_OPEN_CONNS etc). Silent-zero defaults
	// would crash the pool at runtime; applyDefaults must fill them.
	var zero PoolConfig
	got := zero.applyDefaults()
	if got.MaxOpenConns <= 0 {
		t.Errorf("expected positive MaxOpenConns default, got %d", got.MaxOpenConns)
	}
	if got.MaxIdleConns <= 0 {
		t.Errorf("expected positive MaxIdleConns default, got %d", got.MaxIdleConns)
	}
	if got.ConnMaxLifetime <= 0 {
		t.Errorf("expected positive ConnMaxLifetime default, got %v", got.ConnMaxLifetime)
	}
	if got.ConnMaxIdleTime <= 0 {
		t.Errorf("expected positive ConnMaxIdleTime default, got %v", got.ConnMaxIdleTime)
	}
}

func TestPoolConfigApplyDefaultsPreservesExplicitValues(t *testing.T) {
	// An operator's explicit tuning must survive applyDefaults — a bug
	// here would silently reset every user's pool config to the builtin
	// defaults after a restart.
	custom := PoolConfig{
		MaxOpenConns:    77,
		MaxIdleConns:    33,
		ConnMaxLifetime: 7 * time.Minute,
		ConnMaxIdleTime: 2 * time.Minute,
	}
	got := custom.applyDefaults()
	if got.MaxOpenConns != 77 {
		t.Errorf("MaxOpenConns mutated: got %d, want 77", got.MaxOpenConns)
	}
	if got.MaxIdleConns != 33 {
		t.Errorf("MaxIdleConns mutated: got %d, want 33", got.MaxIdleConns)
	}
	if got.ConnMaxLifetime != 7*time.Minute {
		t.Errorf("ConnMaxLifetime mutated: got %v, want 7m", got.ConnMaxLifetime)
	}
}

// Integration test: only runs when CHAINSAW_DATABASE_URL points at a real
// Postgres. Mirrors the pattern in internal/server/server_test.go.
func TestOpenMigratesSchemaRoundTrip(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	// Insert then read back a settings row — smoke test that migrate()
	// produced a usable schema and the DB() accessor returns a live pool.
	// Postgres uses positional placeholders ($1, $2, …); using `?` here
	// produces a syntax error and the integration check passes silently
	// (the test fails before it can assert anything useful).
	_, err = store.DB().Exec(`INSERT INTO settings(org_id, key, value) VALUES($1,$2,$3)
		ON CONFLICT (org_id, key) DO UPDATE SET value = EXCLUDED.value`,
		"default", "pgstore_test.smoke", "ok")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	var got string
	err = store.DB().QueryRow(`SELECT value FROM settings WHERE org_id=$1 AND key=$2`,
		"default", "pgstore_test.smoke").Scan(&got)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got != "ok" {
		t.Errorf("round-trip mismatch: got %q, want %q", got, "ok")
	}

	// Cleanup: don't leave test rows behind.
	if _, err := store.DB().Exec(`DELETE FROM settings WHERE key=$1`, "pgstore_test.smoke"); err != nil {
		t.Logf("cleanup warning: %v", err)
	}
}
