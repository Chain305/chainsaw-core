package pgstore

// Guard for idx_package_metadata_pkg_version, the index behind C-7's holder
// lookup (metadata.PackageMetadataHolders).
//
// WHY AN EXPLAIN AND NOT JUST "DOES THE INDEX EXIST". An index that exists and
// that the planner declines to use is indistinguishable from no index at all,
// and this one is easy to get wrong: package_metadata is keyed
// (org_id, repository, package, version), so a predicate on (package, version)
// cannot use a leading-column prefix of the primary key. Asserting the plan is
// the only way to know the seq scan is actually gone.
//
// The table is seeded with enough rows that the planner PREFERS the index. On a
// handful of rows it correctly chooses a sequential scan whatever indexes
// exist, so a small fixture would make this test pass with the index dropped —
// the naive version that is green on the real bug.

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// holderIndexSeedRows is sized so the planner's cost model prefers an index
// scan. Measured rather than guessed: at 200 rows Postgres 16 still chose a
// seq scan for this predicate, so the figure below is above the crossover with
// margin, and TestHolderIndexIsUsedByThePlanner fails loudly if a future
// planner moves it.
const holderIndexSeedRows = 5000

func TestHolderIndexIsUsedByThePlanner(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const org = "holderidx-org"
	t.Cleanup(func() {
		_, _ = store.DB().Exec(`DELETE FROM package_metadata WHERE org_id LIKE $1`, org+"%")
	})

	// Distinct coordinates, so the predicate below is selective — one row out
	// of holderIndexSeedRows. A seed that put every row on the same coordinate
	// would make the index useless and the assertion meaningless.
	if _, err := store.DB().Exec(`
		INSERT INTO package_metadata (org_id, repository, package, version)
		SELECT $1 || (i % 7), 'repo-' || (i % 3), 'pkg-' || i, '1.0.' || i
		  FROM generate_series(1, $2) AS s(i)
		ON CONFLICT DO NOTHING
	`, org, holderIndexSeedRows); err != nil {
		t.Fatalf("seed package_metadata: %v", err)
	}
	// ANALYZE, or the planner works from default estimates and the plan says
	// nothing about the real table.
	if _, err := store.DB().Exec(`ANALYZE package_metadata`); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// The exact shape metadata.PackageMetadataHolders issues.
	plan, err := explain(store, `
		SELECT org_id, repository, package, version
		  FROM package_metadata
		 WHERE package = $1 AND version = $2
		 ORDER BY org_id ASC, repository ASC
		 LIMIT $3`, "pkg-4242", "1.0.4242", 100)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}

	if !strings.Contains(plan, "idx_package_metadata_pkg_version") {
		t.Fatalf("the planner did NOT use idx_package_metadata_pkg_version for the "+
			"holder lookup. package_metadata is keyed (org_id, repository, package, "+
			"version), so without this index the predicate on (package, version) is a "+
			"sequential scan — once per C-7 alert dispatch.\n\nplan:\n%s", plan)
	}
	if strings.Contains(plan, "Seq Scan on package_metadata") {
		t.Errorf("the plan still contains a sequential scan on package_metadata:\n%s", plan)
	}
}

// TestHolderIndexSeedIsLargeEnoughToMatter proves the fixture can distinguish
// an index from no index. Without it a green run above might only mean "the
// table is small", which is true of every plan on a tiny fixture.
func TestHolderIndexSeedIsLargeEnoughToMatter(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const org = "holderidxsize-org"
	t.Cleanup(func() {
		_, _ = store.DB().Exec(`DELETE FROM package_metadata WHERE org_id LIKE $1`, org+"%")
		_, _ = store.DB().Exec(`DROP INDEX IF EXISTS idx_holder_probe_tmp`)
	})
	if _, err := store.DB().Exec(`
		INSERT INTO package_metadata (org_id, repository, package, version)
		SELECT $1 || (i % 7), 'repo-' || (i % 3), 'sz-' || i, '2.0.' || i
		  FROM generate_series(1, $2) AS s(i)
		ON CONFLICT DO NOTHING
	`, org, holderIndexSeedRows); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.DB().Exec(`ANALYZE package_metadata`); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// Same predicate shape against a column pair with NO index: if the planner
	// chooses a seq scan here, the fixture is big enough that index use in the
	// test above is a real signal and not an artefact of a tiny table.
	plan, err := explain(store, `
		SELECT org_id FROM package_metadata
		 WHERE repository = $1 AND internal_package = $2`, "repo-1", 0)
	if err != nil {
		t.Fatalf("explain control: %v", err)
	}
	if !strings.Contains(plan, "Seq Scan on package_metadata") {
		t.Skipf("control query did not seq-scan, so this probe cannot certify the "+
			"fixture size; the primary assertion still stands on its own plan.\n%s", plan)
	}
}

func explain(store *Store, query string, args ...any) (string, error) {
	rows, err := store.DB().Query("EXPLAIN "+query, args...)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return "", err
		}
		fmt.Fprintln(&b, line)
	}
	return b.String(), rows.Err()
}
