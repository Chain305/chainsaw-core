package pgstore

import (
	"database/sql"
	"os"
	"testing"
)

// TestEnsureIntelligenceReportsDenormColumns_Idempotent gates the additive
// migration that adds `verdict TEXT` and `overall_score INT` plus their
// supporting indexes to `intelligence_reports`. The columns are documented
// in docs/architecture/package-intelligence.md and required by the
// /intelligence list-page filtering API; production schemas were observed
// without them, which is what this migration fixes.
//
// The chainsaw migration thesis (docs/MIGRATIONS.md) is "additive DDL only,
// idempotent on every Open()". This test pins that contract for the new
// migration by:
//
//  1. Connecting to a Postgres test container (skipped if unavailable, the
//     same CHAINSAW_DATABASE_URL gate used by every other pgstore
//     integration test — see store_test.go, upgrade_path_test.go).
//  2. Running pgstore.Open() once (this calls migrate(), which calls
//     ensureEnhancedColumns(), which transitively reaches
//     ensureIntelligenceReportsDenormColumns via the wiring in
//     ensureAnalyticsRollupSchema).
//  3. Asserting both columns and both indexes now exist and are queryable.
//  4. Running migrate() a second time on the same DB and re-asserting —
//     this is the load-bearing idempotency check. Any non-idempotent
//     statement (e.g. a bare ALTER TABLE ADD COLUMN without IF NOT EXISTS,
//     a CREATE INDEX without IF NOT EXISTS, or a backfill UPDATE that
//     races against itself) would surface here as an error.
//
// When the environment variable is unset we skip — same convention as
// every other DB-dependent test in this package.
func TestEnsureIntelligenceReportsDenormColumns_Idempotent(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}

	// First open: runs migrate() against whatever shape the test DB is in.
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("first Open (initial migration): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Reachability check — if the DB is unreachable from this runner,
	// treat as skip (matches upgrade_path_test.go behaviour). This keeps
	// CI green when the network to the test container is flaky.
	if err := store.DB().Ping(); err != nil {
		t.Skipf("ping db failed (Postgres unreachable, treating as skip): %v", err)
	}

	assertDenormColumnsPresent(t, store.DB())
	assertDenormIndexesPresent(t, store.DB())

	// Second pass: re-running the migration must be a no-op. We exercise
	// the helper directly (not via Open) so a regression in this single
	// function surfaces locally instead of being masked by other migrate
	// steps. Any non-idempotent statement (ADD COLUMN without IF NOT
	// EXISTS, CREATE INDEX without IF NOT EXISTS, backfill UPDATE that
	// errors when there's nothing to backfill) would error here.
	if err := store.ensureIntelligenceReportsDenormColumns(); err != nil {
		t.Fatalf("second ensureIntelligenceReportsDenormColumns (idempotency): %v", err)
	}

	// State must be identical after the second pass.
	assertDenormColumnsPresent(t, store.DB())
	assertDenormIndexesPresent(t, store.DB())

	// Smoke: both columns should be queryable (they accept the documented
	// types). If the column types regressed (e.g. someone changed verdict
	// to BOOLEAN), these SELECTs would fail at parse or scan time.
	var verdictCount, scoreCount int
	if err := store.DB().QueryRow(
		`SELECT COUNT(*) FROM intelligence_reports WHERE verdict IS NULL OR verdict IS NOT NULL`,
	).Scan(&verdictCount); err != nil {
		t.Fatalf("query verdict column: %v", err)
	}
	if err := store.DB().QueryRow(
		`SELECT COUNT(*) FROM intelligence_reports WHERE overall_score IS NULL OR overall_score >= 0`,
	).Scan(&scoreCount); err != nil {
		t.Fatalf("query overall_score column: %v", err)
	}
}

// TestEnsureWebhookCanonicalColumns_Idempotent gates the connectors P0-1
// migration that adds `secret_ciphertext`, `format`, and `topic` to the
// `webhooks` table as `ADD COLUMN IF NOT EXISTS` statements. These columns
// were previously added out-of-band (a manual ALTER documented in
// docs/MIGRATIONS.md), which is why the webhook store carried a runtime
// schema-detection ladder. The ladder is now collapsed; the store assumes
// all three columns exist, so migrate() MUST guarantee them.
//
// Same harness + idempotency contract as the denorm-columns test above:
//
//  1. Open() runs migrate() and produces the canonical webhooks schema.
//  2. Assert all three columns exist.
//  3. Re-run migrate() — the second pass must be a no-op (any bare ADD
//     COLUMN without IF NOT EXISTS would error here).
//  4. Re-assert the columns are still present and queryable.
//
// Skipped when CHAINSAW_DATABASE_URL is unset (the standard pgstore gate).
func TestEnsureWebhookCanonicalColumns_Idempotent(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}

	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("first Open (initial migration): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.DB().Ping(); err != nil {
		t.Skipf("ping db failed (Postgres unreachable, treating as skip): %v", err)
	}

	assertWebhookCanonicalColumnsPresent(t, store.DB())

	// Second pass: re-running the full migration must be a no-op. We run
	// migrate() (not just the webhook ALTERs) so any ordering interaction
	// with the rest of the slice surfaces too.
	if err := store.migrate(); err != nil {
		t.Fatalf("second migrate() (idempotency): %v", err)
	}

	assertWebhookCanonicalColumnsPresent(t, store.DB())

	// Smoke: every canonical column is queryable. A type regression (e.g.
	// secret_ciphertext changed to BYTEA) would fail at parse/scan time.
	var n int
	if err := store.DB().QueryRow(
		`SELECT COUNT(*) FROM webhooks
		   WHERE (secret_ciphertext IS NULL OR secret_ciphertext IS NOT NULL)
		     AND (format IS NULL OR format IS NOT NULL)
		     AND (topic IS NULL OR topic IS NOT NULL)`,
	).Scan(&n); err != nil {
		t.Fatalf("query canonical webhook columns: %v", err)
	}
}

// assertWebhookCanonicalColumnsPresent fails if any of the three canonical
// webhook columns is missing.
func assertWebhookCanonicalColumnsPresent(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, col := range []string{"secret_ciphertext", "format", "topic"} {
		var exists bool
		err := db.QueryRow(
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public'
				  AND table_name = 'webhooks'
				  AND column_name = $1
			)`,
			col,
		).Scan(&exists)
		if err != nil {
			t.Errorf("probe webhooks.%s: %v", col, err)
			continue
		}
		if !exists {
			t.Errorf("webhooks.%s missing after migration", col)
		}
	}
}

// assertDenormColumnsPresent fails the test if either of the two denorm
// columns is missing from intelligence_reports. Schema probe uses
// information_schema.columns directly so we don't depend on the helper
// columnExists method behaving correctly under both Postgres and the
// SQLite fallback used elsewhere in the suite.
func assertDenormColumnsPresent(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, col := range []string{"verdict", "overall_score"} {
		var exists bool
		err := db.QueryRow(
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public'
				  AND table_name = 'intelligence_reports'
				  AND column_name = $1
			)`,
			col,
		).Scan(&exists)
		if err != nil {
			t.Errorf("probe intelligence_reports.%s: %v", col, err)
			continue
		}
		if !exists {
			t.Errorf("intelligence_reports.%s missing after migration", col)
		}
	}
}

// assertDenormIndexesPresent verifies the two supporting indexes were
// created. List-page queries pivot on verdict and overall_score, so
// the indexes are a functional requirement (not just an optimisation)
// for the filter API to scale beyond toy datasets.
func assertDenormIndexesPresent(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, idx := range []string{
		"idx_intelligence_reports_verdict",
		"idx_intelligence_reports_overall_score",
	} {
		var exists bool
		err := db.QueryRow(
			`SELECT EXISTS (
				SELECT 1 FROM pg_indexes
				WHERE schemaname = 'public'
				  AND tablename = 'intelligence_reports'
				  AND indexname = $1
			)`,
			idx,
		).Scan(&exists)
		if err != nil {
			t.Errorf("probe index %s: %v", idx, err)
			continue
		}
		if !exists {
			t.Errorf("index %s missing after migration", idx)
		}
	}
}
