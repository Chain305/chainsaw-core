package pgstore

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Schema-version tests. The unit-level coverage here focuses on the
// pure comparator + helpers so the ensureSchemaVersion() semantics
// can be exercised without a real Postgres. The integration path
// (INSERT on fresh DB, UPDATE on older DB, warn on newer DB) is
// gated behind CHAINSAW_DATABASE_URL the same way
// TestOpenMigratesSchemaRoundTrip is, so CI without a database
// fixture still runs meaningful coverage.

func TestSchemaVersionLess(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"equal", "0.16.0", "0.16.0", false},
		{"minor older", "0.15.0", "0.16.0", true},
		{"minor newer", "0.17.0", "0.16.0", false},
		{"patch older", "0.16.0", "0.16.1", true},
		{"major older", "0.9.9", "1.0.0", true},
		{"prefix-matches-shorter-older", "0.16", "0.16.0", true},
		{"numeric-not-lexical", "0.16.0", "0.2.0", false}, // 16 > 2 numerically
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := schemaVersionLess(tc.a, tc.b); got != tc.want {
				t.Fatalf("schemaVersionLess(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestSplitSemverLike(t *testing.T) {
	got := splitSemverLike("0.16.0")
	if len(got) != 3 || got[0] != "0" || got[1] != "16" || got[2] != "0" {
		t.Fatalf("unexpected split: %#v", got)
	}
	if got := splitSemverLike(""); len(got) != 1 || got[0] != "" {
		t.Fatalf("empty-input split = %#v", got)
	}
	if got := splitSemverLike("7"); len(got) != 1 || got[0] != "7" {
		t.Fatalf("single-segment split = %#v", got)
	}
}

func TestToInt(t *testing.T) {
	if n, ok := toInt("42"); !ok || n != 42 {
		t.Fatalf("toInt(42) = %d,%v", n, ok)
	}
	if _, ok := toInt("7a"); ok {
		t.Fatal("toInt should refuse non-digit suffix")
	}
	if _, ok := toInt(""); ok {
		t.Fatal("toInt should refuse empty input")
	}
}

func TestCurrentSchemaVersionNonEmpty(t *testing.T) {
	// Trip-wire: if someone clears the constant, every doctor run
	// downgrades to "DB reports X but binary supplied an empty
	// expected version" — this test fails loudly first.
	if CurrentSchemaVersion == "" {
		t.Fatal("CurrentSchemaVersion must not be empty")
	}
}

func TestErrNoSchemaVersionIsSentinel(t *testing.T) {
	// Doctor's adapter pivots on errors.Is(err, ErrNoSchemaVersion).
	// A common regression is redefining the variable locally rather
	// than using the package-level sentinel.
	wrapped := errors.Join(errors.New("outer"), ErrNoSchemaVersion)
	if !errors.Is(wrapped, ErrNoSchemaVersion) {
		t.Fatal("ErrNoSchemaVersion lost its identity when wrapped")
	}
}

// ---- Integration tests (real Postgres) ---------------------------

// TestSchemaVersionRoundTrip_FreshInsert verifies the first-boot path:
// Open() on a fresh DB inserts the CurrentSchemaVersion row.
func TestSchemaVersionRoundTrip_FreshInsert(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	v, err := store.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != CurrentSchemaVersion {
		t.Errorf("stored schema_version = %q, want %q", v, CurrentSchemaVersion)
	}
}

// TestSchemaVersionRoundTrip_IdempotentMatch verifies that re-opening
// a DB already at the current version is a no-op (no error, value
// preserved).
func TestSchemaVersionRoundTrip_IdempotentMatch(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	// Open twice; the second open should be a no-op. Both must
	// report the same stored version.
	s1, err := Open(dsn)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	v1, err := s1.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion #1: %v", err)
	}
	s1.Close()

	s2, err := Open(dsn)
	if err != nil {
		t.Fatalf("open #2: %v", err)
	}
	defer s2.Close()
	v2, err := s2.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion #2: %v", err)
	}
	if v1 != v2 {
		t.Errorf("schema_version changed across idempotent reopen: %q -> %q", v1, v2)
	}
	if v2 != CurrentSchemaVersion {
		t.Errorf("stored = %q, want CurrentSchemaVersion %q", v2, CurrentSchemaVersion)
	}
}

// TestSchemaVersionRoundTrip_OlderUpdated seeds the row with an older
// version, then re-opens and verifies the row was updated to
// CurrentSchemaVersion.
func TestSchemaVersionRoundTrip_OlderUpdated(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Force the row to an artificially-old value.
	if _, err := store.DB().Exec(`UPDATE schema_version SET version = $1 WHERE id = 1`, "0.0.1"); err != nil {
		t.Fatalf("seed older version: %v", err)
	}
	store.Close()

	// Reopen — ensureSchemaVersion should UPDATE to the current value.
	store2, err := Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store2.Close()
	v, err := store2.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != CurrentSchemaVersion {
		t.Errorf("after upgrade the row should advance to %q, got %q", CurrentSchemaVersion, v)
	}
}

// TestSchemaVersionRoundTrip_NewerPreserved seeds the row with a
// hypothetical newer version and verifies the binary does NOT
// overwrite it (downgrade-tolerance path).
func TestSchemaVersionRoundTrip_NewerPreserved(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const futureVersion = "99.99.99"
	if _, err := store.DB().Exec(`UPDATE schema_version SET version = $1 WHERE id = 1`, futureVersion); err != nil {
		t.Fatalf("seed future version: %v", err)
	}
	store.Close()

	store2, err := Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store2.Close()
	v, err := store2.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != futureVersion {
		t.Errorf("binary should not have overwritten newer stored version; got %q want %q", v, futureVersion)
	}
	// Reset so subsequent test runs start from a normal state.
	if _, err := store2.DB().Exec(`UPDATE schema_version SET version = $1 WHERE id = 1`, CurrentSchemaVersion); err != nil {
		t.Logf("cleanup warning: %v", err)
	}
}
