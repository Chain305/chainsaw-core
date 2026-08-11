package pgstore

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// snapshotColumns records every "table.column" in the public schema. It is
// the primitive behind the fresh-install-vs-upgraded comparison in
// TestMigrate_FromV015Schema: a fresh install is the reference shape, and an
// upgraded database must contain everything in it.
//
// information_schema.columns covers views too; we filter to base tables so a
// view definition change can't masquerade as a missing migration.
func snapshotColumns(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`
		SELECT c.table_name, c.column_name
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			return nil, err
		}
		out[table+"."+column] = true
	}
	return out, rows.Err()
}

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

	// Step 0 — capture the FRESH-INSTALL schema shape.
	//
	// This is the reference the upgraded database has to converge on. We
	// wipe, run Open() (and therefore migrate()) against an empty database,
	// and record every column of every table. Step 5 later asserts the
	// upgraded-from-0.15.0 database is a superset of this.
	//
	// Why a generated reference instead of a hand-written column list: the
	// bug this guard exists for was a column that appears in the
	// repositories CREATE TABLE but had no addColumnIfMissing counterpart,
	// so fresh installs got it and upgrades silently did not. Any
	// hand-maintained list would have been written from the same CREATE
	// TABLE and drifted the same way. Diffing the two paths needs no
	// maintenance and catches every future instance of the same mistake.
	if _, err := rawDB.Exec(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("wipe schema before fresh-install reference run: %v", err)
	}
	freshStore, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open against an empty database (fresh-install reference): %v", err)
	}
	freshColumns, err := snapshotColumns(freshStore.DB())
	if err != nil {
		_ = freshStore.Close()
		t.Fatalf("snapshot fresh-install columns: %v", err)
	}
	if err := freshStore.Close(); err != nil {
		t.Fatalf("close fresh-install store: %v", err)
	}
	if len(freshColumns) == 0 {
		t.Fatalf("fresh-install reference snapshot is empty — migrate() created nothing")
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

	// Step 3b — probe COLUMNS on the tables the v0.15.0 seed already has.
	//
	// A table that predates the seed is never re-created (CREATE TABLE IF
	// NOT EXISTS is a no-op), so every column added to it since 0.15.0 can
	// only arrive through addColumnIfMissing. Probing table existence alone
	// cannot see that — which is precisely how five repositories columns
	// shipped in the CREATE TABLE with no migration counterpart and broke
	// config.LoadFromStore on every pre-0.16 upgrade with
	//   column "remote_proxy_url" does not exist
	//
	// The named list below is the read path's hard dependency: every column
	// config.fetchRepositories SELECTs. Keep it in step with that query.
	postUpgradeColumns := map[string][]string{
		"repositories": {
			"remote_proxy_url",           // 0.16.0 remote proxy
			"remote_skip_tls",            // 0.16.0 remote proxy
			"remote_timeout_seconds",     // 0.16.0 remote proxy
			"remote_headers",             // 0.16.0 remote proxy
			"cache_negative_ttl_seconds", // 0.16.0 negative caching
			"client_configuration_guide_template",
			"public_base_url",
			"anonymous_access",
			"org_id",
		},
	}
	for table, columns := range postUpgradeColumns {
		for _, column := range columns {
			var exists bool
			err := store.DB().QueryRow(
				`SELECT EXISTS (
					SELECT 1 FROM information_schema.columns
					WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
				)`,
				table, column,
			).Scan(&exists)
			if err != nil {
				t.Errorf("probe for column %s.%s: %v", table, column, err)
				continue
			}
			if !exists {
				t.Errorf("post-upgrade column %s.%s missing — it is in the CREATE TABLE but has no "+
					"addColumnIfMissing counterpart, so upgrading a pre-0.16 database never gains it",
					table, column)
			}
		}
	}

	// Step 3c — the generic guard: the upgraded database must be a superset
	// of the fresh-install shape captured in step 0. This needs no
	// maintenance and catches the next column that lands in a CREATE TABLE
	// without a matching addColumnIfMissing call.
	//
	// Superset, not equality: the 0.15.0 seed is allowed to carry columns a
	// fresh install no longer creates, and migrate() never drops anything.
	upgradedColumns, err := snapshotColumns(store.DB())
	if err != nil {
		t.Fatalf("snapshot upgraded columns: %v", err)
	}
	var missing []string
	for key := range freshColumns {
		if !upgradedColumns[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("upgrading from the v0.15.0 seed did not converge on the fresh-install schema; "+
			"%d column(s) a fresh install has are absent after migrate(): %s\n"+
			"Each one needs an addColumnIfMissing call in core/pgstore/migrate_columns.go "+
			"(a CREATE TABLE alone is a no-op against an existing table).",
			len(missing), strings.Join(missing, ", "))
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
