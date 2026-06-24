package pgstore

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// TestMigrate_FromV015Schema is the load-bearing scaffold for Eng review E10.
//
// What it proves: chainsaw's "no migration runner, idempotent DDL is enough"
// thesis (docs/MIGRATIONS.md) actually holds when migrate() is pointed at a
// non-empty database that lags the binary's expected schema.
//
// How it proves it:
//  1. Connect to a Postgres test container (skipped if unavailable).
//  2. Apply a synthetic v0.15.0-shape schema seed
//     (testdata/v0.15.0_schema.sql) — NOT a real production dump, just
//     enough tables to give migrate() a "stale starting state" with one
//     row that must survive the upgrade.
//  3. Call pgstore.Open(...) which internally calls migrate().
//  4. Assert: no error, post-0.16.0 tables/columns now exist, AND the
//     pre-existing webhook row written before migrate() is still there
//     with its original secret.
//
// If this test fails, the thesis is broken and the project genuinely
// needs an external migration runner (golang-migrate, goose, etc.) — see
// the TODO at the top of pgstore.migrate(). Until then, this gate is the
// only thing standing between the docs claim and reality.
//
// Adding more from-version coverage:
//
//	When N+1 ships (post-0.16.0), copy testdata/v0.15.0_schema.sql to
//	testdata/v<N>_schema.sql, drop the additions that landed in N+1, and
//	add a sibling TestMigrate_FromV<N>Schema below. The CI job in
//	.github/workflows/upgrade-path.yml already runs every test in this
//	file, so new from-version tests cost zero workflow churn.
func TestMigrate_FromV015Schema(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping upgrade-path integration test " +
			"(set this to a Postgres DSN with DROP+CREATE rights — the test wipes the public schema).")
	}

	// Step 1 — connect raw and seed the synthetic 0.15.0-shape schema.
	// We deliberately bypass pgstore.Open here so migrate() does NOT run
	// before the seed; this is the "operator's database before they pull
	// the new binary" state.
	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })

	if err := rawDB.Ping(); err != nil {
		t.Skipf("ping raw db failed (Postgres unreachable, treating as skip): %v", err)
	}

	seedPath := filepath.Join("testdata", "v0.15.0_schema.sql")
	seedBytes, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read seed %s: %v", seedPath, err)
	}
	if _, err := rawDB.Exec(string(seedBytes)); err != nil {
		t.Fatalf("apply v0.15.0 schema seed: %v", err)
	}

	// Sanity: the seeded webhook row must exist BEFORE we run migrate().
	// If this fails, the seed is busted and the rest of the assertions
	// would be misleading.
	var preExisting int
	if err := rawDB.QueryRow(
		`SELECT COUNT(*) FROM webhooks WHERE id = 'wh-pre-upgrade'`,
	).Scan(&preExisting); err != nil {
		t.Fatalf("seed precheck: %v", err)
	}
	if preExisting != 1 {
		t.Fatalf("seed precheck: expected 1 pre-existing webhook row, got %d", preExisting)
	}

	// Step 2 — open the store. This runs migrate(), which is what we're
	// actually testing. If migrate() can't reconcile the stale schema,
	// Open returns an error here.
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open after applying v0.15.0 seed (this is the thesis-failure case): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Step 3 — assert the "post-0.16.0 schema is now present" half of the
	// thesis. We probe a few representative tables added across the
	// effectiveness-uplift and supply-chain feature waves; if any of these
	// is missing, migrate()'s additive DDL didn't actually fire.
	postUpgradeTables := []string{
		"sbom_snapshots",            // [Unreleased] Pain 7
		"team_webhook_destinations", // [Unreleased] Pain 4
		"ownership_glob_rules",      // [Unreleased] Pain 4
		"exception_reminders_sent",  // [Unreleased] Pain 5
		"risk_weight_overrides",     // [Unreleased] Pain 9
		"findings",                  // 0.17.0 chainsaw-fnd
		"policy_versions",           // P1 audit gap G5
		"schema_version",            // 0.16.0 doctor probe row
	}
	for _, table := range postUpgradeTables {
		var exists bool
		err := store.DB().QueryRow(
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`,
			table,
		).Scan(&exists)
		if err != nil {
			t.Errorf("probe for table %q: %v", table, err)
			continue
		}
		if !exists {
			t.Errorf("post-upgrade table %q missing — migrate() did not create it from the v0.15.0 starting state", table)
		}
	}

	// Step 4 — the pre-existing webhook row MUST still be there with its
	// original secret. If this row vanished or got overwritten, the
	// "additive only" claim is a lie.
	//
	// NOTE: we deliberately do NOT assert on webhooks.secret_ciphertext
	// here. Per docs/MIGRATIONS.md → "[0.16.0] / webhooks.secret_ciphertext",
	// that column is one of the explicit operator-action items
	// ("Self-hosters must run, before restarting the upgraded binary,
	// ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS secret_ciphertext TEXT;")
	// — i.e. it is the documented exception that DOES require manual
	// DDL. The thesis we're gating is "every other addition is
	// idempotent and self-applies"; this test confirms exactly that.
	// If a future release moves the secret_ciphertext add into
	// migrate() (via addColumnIfMissing) the assertion can be added
	// back in the same PR that does the move.
	var gotSecret string
	if err := store.DB().QueryRow(
		`SELECT secret FROM webhooks WHERE id = $1`, "wh-pre-upgrade",
	).Scan(&gotSecret); err != nil {
		t.Fatalf("read pre-existing webhook row after migrate(): %v", err)
	}
	if gotSecret != "legacy-plaintext-secret" {
		t.Errorf("pre-existing webhook secret was mutated by migrate(): got %q, want %q", gotSecret, "legacy-plaintext-secret")
	}
}
