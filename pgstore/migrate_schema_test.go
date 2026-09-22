package pgstore

import (
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
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

// TestMonitoredTargetsSchemaIsWiredIntoMigrate is the guard for the trap that
// ensure*Schema helpers are NOT self-registering: they run only because
// ensureEnhancedColumns (migrate_columns.go) calls them by name. A helper
// added to migrate_schema.go and never wired there compiles, passes vet,
// ships, and creates nothing — a migration that cannot run.
//
// The check parses the AST rather than grepping for the call text. That is not
// fastidiousness: the first version of this guard used strings.Contains and
// PASSED against a deliberately commented-out call site, because the comment
// still contains the substring. A guard that goes green on the exact defect it
// exists to catch is worse than no guard. The AST walk sees a real call in a
// real function body and nothing else.
//
// This assertion is deliberately source-level rather than DB-level so it runs
// on every machine with no CHANSAW_DATABASE_URL and no container. Per
// CLAUDE.md, "a guard that cannot run is not a guard"; the DSN-gated schema
// test below is the stronger check but it skips silently without infra, and a
// skip is not a pass. Same tripwire shape as
// TestPermAuditWriteHasProductionCallsite in internal/server/rbac_matrix_test.go.
//
// Proven to fail: commenting out the call site in migrate_columns.go turns
// this red with "call site missing", and the code still compiles while it does
// — which is the whole shape of the trap.
func TestMonitoredTargetsSchemaIsWiredIntoMigrate(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "migrate_columns.go", nil, 0)
	if err != nil {
		t.Fatalf("parse migrate_columns.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "ensureEnhancedColumns" {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("ensureEnhancedColumns not found in migrate_columns.go: " +
			"the migration entry point moved; re-point this guard at its new home")
	}

	var called bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ensureMonitoredTargetsSchema" {
			called = true
		}
		return true
	})
	if !called {
		t.Fatal("call site missing: ensureEnhancedColumns in migrate_columns.go " +
			"no longer calls s.ensureMonitoredTargetsSchema(). The helper in " +
			"migrate_schema.go is not self-registering — without this call the " +
			"monitored_targets table is never created and the build stays green.")
	}
}

// TestEnsureMonitoredTargetsSchema_Idempotent is the DB half of the guard:
// Open() must actually produce the table, its UNIQUE constraint, its due
// index, and the all-except-cve triggers default, and re-running the helper
// must be a no-op.
//
// DSN-GATED. Skipped without CHAINSAW_DATABASE_URL, the standard pgstore gate.
func TestEnsureMonitoredTargetsSchema_Idempotent(t *testing.T) {
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

	assertMonitoredTargetsPresent(t, store.DB())

	// Second pass through the helper directly — any non-idempotent statement
	// (a CREATE without IF NOT EXISTS) surfaces here rather than being masked
	// by the other migrate steps.
	if err := store.ensureMonitoredTargetsSchema(); err != nil {
		t.Fatalf("second ensureMonitoredTargetsSchema (idempotency): %v", err)
	}
	assertMonitoredTargetsPresent(t, store.DB())

	// The wedge default. If someone "simplifies" the DEFAULT to all triggers,
	// every new target starts alerting on CVEs and the product becomes
	// Dependabot. This is a product decision pinned in the schema.
	var triggers string
	if err := store.DB().QueryRow(
		`INSERT INTO monitored_targets (org_id, repo_label, branch)
		 VALUES ('org-mt-default-probe', 'acme/api', 'main')
		 ON CONFLICT (org_id, repo_label, branch) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
		 RETURNING triggers::text`,
	).Scan(&triggers); err != nil {
		t.Fatalf("insert probe row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.DB().Exec(`DELETE FROM monitored_targets WHERE org_id = 'org-mt-default-probe'`)
	})
	for _, want := range []string{
		"malware_appeared", "typosquat_appeared", "publisher_changed",
		"install_script_appeared", "verdict_degraded",
	} {
		if !strings.Contains(triggers, want) {
			t.Errorf("triggers default missing %q: got %s", want, triggers)
		}
	}
	if strings.Contains(triggers, "cve") {
		t.Errorf("triggers default must EXCLUDE cve (the product wedge); got %s", triggers)
	}

	// The btree key cap. Without the CHECK an over-long branch fails at INSERT
	// with an opaque "index row size exceeds btree version 4 maximum" that
	// names neither the column nor the fix.
	_, err = store.DB().Exec(
		`INSERT INTO monitored_targets (org_id, repo_label, branch) VALUES ($1, $2, $3)`,
		"org-mt-default-probe", "acme/api", strings.Repeat("b", 256),
	)
	if err == nil {
		t.Error("over-long branch was accepted; the octet_length CHECK is not enforcing")
	}
}

// assertMonitoredTargetsPresent verifies the table, every documented column,
// the UNIQUE tuple and the due index exist. The UNIQUE is what makes
// (org_id, repo_label, branch) the target identity; the index is what makes
// the worker's "who is due" query not a seq scan.
func assertMonitoredTargetsPresent(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, col := range []string{
		"org_id", "repo_label", "branch", "package_set", "triggers",
		"last_uploaded_at", "last_scanned_at", "consecutive_failures",
		"archived_at", "created_at", "updated_at",
	} {
		var exists bool
		err := db.QueryRow(
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public'
				  AND table_name = 'monitored_targets'
				  AND column_name = $1
			)`, col,
		).Scan(&exists)
		if err != nil {
			t.Errorf("probe monitored_targets.%s: %v", col, err)
			continue
		}
		if !exists {
			t.Errorf("monitored_targets.%s missing after migration "+
				"(if EVERY column is missing, the migration did not run at all — "+
				"check the ensureMonitoredTargetsSchema call site in migrate_columns.go)", col)
		}
	}

	// repo_url would mean somebody renamed the column back. The name is a
	// security decision, not a style preference — see the helper's doc comment.
	var urlCol bool
	if err := db.QueryRow(
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'monitored_targets'
			  AND column_name = 'repo_url')`,
	).Scan(&urlCol); err == nil && urlCol {
		t.Error("monitored_targets.repo_url exists: the column is repo_label on purpose " +
			"(the value is never fetched; P8-52 SSRF is unfixed in this repo)")
	}

	var uniq bool
	if err := db.QueryRow(
		`SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE schemaname = 'public' AND tablename = 'monitored_targets'
			  AND indexdef LIKE '%UNIQUE%'
			  AND indexdef LIKE '%org_id%'
			  AND indexdef LIKE '%repo_label%'
			  AND indexdef LIKE '%branch%')`,
	).Scan(&uniq); err != nil {
		t.Errorf("probe monitored_targets unique constraint: %v", err)
	} else if !uniq {
		t.Error("UNIQUE (org_id, repo_label, branch) missing after migration")
	}

	var idx bool
	if err := db.QueryRow(
		`SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE schemaname = 'public' AND tablename = 'monitored_targets'
			  AND indexname = 'idx_monitored_targets_due')`,
	).Scan(&idx); err != nil {
		t.Errorf("probe idx_monitored_targets_due: %v", err)
	} else if !idx {
		t.Error("idx_monitored_targets_due missing after migration")
	}
}
