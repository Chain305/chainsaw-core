package pgstore

import (
	"os"
	"strings"
	"testing"
)

// TestMigrateDropsLegacyTrustScoreColumns pins F-02 phase 2.
//
// THE NEGATIVE CONTROL IS THE POINT, so read this before simplifying it.
//
// The obvious version of this test — migrate a database, then assert the
// columns are absent — is worthless twice over. It passes on a fresh database
// that never had them, so it would have passed during the entire four months
// the columns sat unwritten. And it keeps passing if someone deletes the DROP
// statements but leaves the addColumnIfMissing calls, or vice versa.
//
// So this test CREATES the columns itself and seeds a row, then migrates
// AGAIN. The assertion can only pass if a DROP actually executed against a
// database that really had them.
//
// Migrating a second time is also the only sequence that exercises the
// ordering hazard: migrateSchema runs its stmts list at migrate.go:2299 and
// then calls ensureEnhancedColumns at :2307, which reaches
// ensurePackageRegistryColumns. A DROP in stmts with the addColumnIfMissing
// calls left in place drops the column and immediately re-creates it — every
// boot, forever — and a single-pass fresh-DB test cannot see it.
//
// The seeded row is asserted to survive, so a lazy "fix" of DROP TABLE fails.
func TestMigrateDropsLegacyTrustScoreColumns(t *testing.T) {
	base := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if base == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty — " +
				"this run was supposed to exercise Postgres and would otherwise have " +
				"skipped while still reporting the package ok")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	dsn, cleanup := provisionScratchDatabase(t, base)
	defer cleanup()

	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open scratch store: %v", err)
	}
	defer store.Close()

	// Re-create the pre-drop world. This is what makes the assertion below
	// mean something: the columns exist, and one row carries the fossil
	// shape actually found in production (score 30, nine-key legacy blob).
	for _, ddl := range []string{
		`ALTER TABLE package_metadata ADD COLUMN IF NOT EXISTS trust_score INTEGER`,
		`ALTER TABLE package_metadata ADD COLUMN IF NOT EXISTS trust_score_breakdown TEXT`,
	} {
		if _, err := store.DB().Exec(ddl); err != nil {
			t.Fatalf("recreate pre-drop column: %v", err)
		}
	}
	if _, err := store.DB().Exec(`
		INSERT INTO package_metadata (org_id, repository, package, version, license_spdx, trust_score, trust_score_breakdown)
		VALUES ('default', 'npmjs', 'fossil-pkg', '1.0.0', 'MIT', 30, '{"malwareCheck":0,"vulnStatus":20,"typosquatCheck":10}')
	`); err != nil {
		t.Fatalf("seed fossil row: %v", err)
	}

	// Prove the fixture is real before relying on it.
	if !columnExists(t, store, "package_metadata", "trust_score") {
		t.Fatal("fixture setup failed: trust_score was not created, so this test " +
			"cannot prove a DROP ran")
	}

	// The second migrate. This is the run under test.
	if err := store.migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	for _, col := range []string{"trust_score", "trust_score_breakdown"} {
		if columnExists(t, store, "package_metadata", col) {
			t.Errorf("package_metadata.%s still exists after migrate.\n"+
				"Either the DROP is missing from migrateSchema's stmts, or "+
				"ensurePackageRegistryColumns re-created it at migrate.go:2307 — "+
				"which runs AFTER the stmts loop, so both edits must land together.", col)
		}
	}

	// The row must survive. A DROP TABLE would satisfy the assertions above.
	var n int
	if err := store.DB().QueryRow(
		`SELECT COUNT(*) FROM package_metadata WHERE package = 'fossil-pkg'`).Scan(&n); err != nil {
		t.Fatalf("count seeded row: %v", err)
	}
	if n != 1 {
		t.Errorf("seeded row count = %d, want 1 — dropping the COLUMNS must not "+
			"disturb the rows", n)
	}
	// And its other columns must be intact.
	var license string
	if err := store.DB().QueryRow(
		`SELECT license_spdx FROM package_metadata WHERE package = 'fossil-pkg'`).Scan(&license); err != nil {
		t.Fatalf("read surviving row: %v", err)
	}
	if license != "MIT" {
		t.Errorf("license_spdx = %q, want MIT", license)
	}
}

// TestEnsurePackageRegistryColumnsDoesNotResurrectTrustScore is the cheap
// guard that survives Postgres being unavailable.
//
// The DB test above passes if the DROP runs, even if someone later re-adds an
// addColumnIfMissing call in a DIFFERENT ensure* function that happens to run
// before the stmts loop. This one bans the identifier from the file outright.
func TestEnsurePackageRegistryColumnsDoesNotResurrectTrustScore(t *testing.T) {
	raw, err := os.ReadFile("migrate_packages.go")
	if err != nil {
		t.Fatalf("read migrate_packages.go: %v", err)
	}
	src := string(raw)

	// Vacuity: if the file stopped adding package_metadata columns entirely,
	// every check below would pass having scanned nothing.
	if !strings.Contains(src, `addColumnIfMissing("package_metadata"`) {
		t.Fatal("migrate_packages.go no longer adds any package_metadata column — " +
			"if this moved, re-point this guard; do not delete it")
	}

	for _, col := range []string{`"trust_score"`, `"trust_score_breakdown"`} {
		if strings.Contains(src, `addColumnIfMissing("package_metadata", `+col) {
			t.Errorf("migrate_packages.go re-creates package_metadata.%s.\n"+
				"This function runs AFTER migrateSchema's stmts loop, so the column "+
				"would be dropped and immediately re-added as all-NULL on every boot.", col)
		}
	}
}

// columnExists asks information_schema rather than probing with a SELECT, so
// a permissions error cannot read as "absent".
func columnExists(t *testing.T, s *Store, table, column string) bool {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`
		SELECT COUNT(*) FROM information_schema.columns
		 WHERE table_name = $1 AND column_name = $2
	`, table, column).Scan(&n); err != nil {
		t.Fatalf("information_schema lookup for %s.%s: %v", table, column, err)
	}
	return n > 0
}
