package pgstore

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSlugFoldedNameIndex: two spellings of one folded name cannot both
// hold a slug in a repository, and a database that already holds such a
// pair still migrates (the index is skipped and logged, not a boot failure).
func TestSlugFoldedNameIndex(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	db := store.DB()
	org := fmt.Sprintf("slugfold_%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM package_slugs WHERE org_id = $1`, org) })
	n := 0
	insert := func(repo, name, format string) error {
		n++
		_, err := db.Exec(`INSERT INTO package_slugs (id, org_id, repository, package_name, format) VALUES ($1, $2, $3, $4, $5)`,
			fmt.Sprintf("%s-%d", org, n), org, repo, name, format)
		return err
	}
	indexed := func() bool {
		var ok bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_package_slugs_folded_name_live')`).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !indexed() {
		t.Fatal("migrate did not create idx_package_slugs_folded_name_live (does the test database hold folded duplicates?)")
	}

	for _, c := range []struct{ format, first, second string }{
		{"pip", "Acme_Foo", "acme-foo"},
		{"cargo", "acme_foo", "Acme-Foo"},
		{"nuget", "Acme.Foo", "acme.foo"},
		{"docker", "alpine", "library/Alpine"},
	} {
		repo := "r-" + c.format
		if err := insert(repo, c.first, c.format); err != nil {
			t.Fatalf("%s: first spelling: %v", c.format, err)
		}
		if err := insert(repo, c.second, c.format); err == nil {
			t.Fatalf("%s: %q and %q both claimed one folded name", c.format, c.first, c.second)
		}
	}
	// Positive control: exact formats and other repositories are separate.
	for _, c := range [][3]string{{"r-npm", "Foo", "npm"}, {"r-npm", "foo", "npm"}, {"r-other", "acme-foo", "pip"}} {
		if err := insert(c[0], c[1], c[2]); err != nil {
			t.Fatalf("%v refused: %v", c, err)
		}
	}

	// A database that already holds a folded pair migrates without it.
	if _, err := db.Exec(`DROP INDEX IF EXISTS idx_package_slugs_folded_name_live`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.ensureSlugFoldedNameIndex() })
	if err := insert("r-dup", "Dup_Name", "pip"); err != nil {
		t.Fatal(err)
	}
	if err := insert("r-dup", "dup-name", "pip"); err != nil {
		t.Fatal(err)
	}
	if err := store.ensureSlugFoldedNameIndex(); err != nil {
		t.Fatalf("folded duplicates failed the migration: %v", err)
	}
	if indexed() {
		t.Fatal("the index was created over duplicates")
	}
	if _, err := db.Exec(`DELETE FROM package_slugs WHERE org_id = $1 AND repository = 'r-dup'`, org); err != nil {
		t.Fatal(err)
	}
	if err := store.ensureSlugFoldedNameIndex(); err != nil || !indexed() {
		t.Fatalf("merged duplicates: err=%v indexed=%v, want the index", err, indexed())
	}
}
