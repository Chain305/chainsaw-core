package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the pre-78f3548f guide-prose backfill (migrate_repo_guides.go).
//
// The DB-backed cases follow the package convention: they require a real
// Postgres via CHAINSAW_DATABASE_URL and skip otherwise (see store_test.go,
// migrate_schema_test.go, upgrade_path_test.go).
//
// They are safe against a SHARED CHAINSAW_DATABASE_URL even though the
// backfill statement is deliberately not org-scoped: every fixture uses a
// repository name suffixed with a per-run nonce, and the UPDATE keys on
// `name = ?`, so it cannot reach a row this test did not create. The fixtures
// are removed in cleanup by that same nonce.

// staleGuideProse is representative of what a pre-fix org actually holds: a
// registry URL missing the /chainproxy prefix (404) and the superseded
// base64-a-Bearer-token instruction (401). Critically, it contains zero
// instances of repositoryGuideFreshMarker — which is why render-time
// substitution cannot repair it and this backfill exists.
const staleGuideProse = `# npm Repository Configuration Guide

registry=https://chain305.com/repository/@acme/npmjs/
//chain305.com/repository/@acme/npmjs/:_auth=$(printf 'CLIENT_ID:CLIENT_SECRET' | base64)
`

// freshGuideProse stands in for post-fix seed prose. It carries the marker,
// which is what makes the backfill idempotent.
const freshGuideProse = `# npm Repository Configuration Guide

registry=https://your-chainsaw-base/repository/npmjs/
//your-chainsaw-base/repository/npmjs/:_authToken=${CHAINSAW_TOKEN}
`

// TestRepositoryGuideMarkerMatchesSeedYAML pins the constant against the file
// it was derived from. If a later edit renames the placeholder in
// configs/seed.yaml, the backfill's stale/fresh test silently inverts — every
// row would look stale forever — so the drift has to fail loudly here.
//
// core is published as a standalone module (chainsaw-core) where configs/ is
// absent, so a missing file is a skip, not a failure.
func TestRepositoryGuideMarkerMatchesSeedYAML(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "configs", "seed.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("configs/seed.yaml not present (core-only checkout): %v", err)
	}
	if !strings.Contains(string(raw), repositoryGuideFreshMarker) {
		t.Fatalf("configs/seed.yaml no longer contains %q. The backfill uses that token "+
			"to tell post-fix prose from pre-fix prose; if the placeholder was renamed, "+
			"move repositoryGuideFreshMarker with it in the same change.",
			repositoryGuideFreshMarker)
	}
}

// TestBackfillStaleRepositoryGuidesNoStore covers the no-DB guards so the
// package runs something for this migration without a database fixture.
func TestBackfillStaleRepositoryGuidesNoStore(t *testing.T) {
	t.Parallel()

	var nilStore *Store
	n, err := nilStore.BackfillStaleRepositoryGuides(context.Background(), []RepositoryGuide{{Name: "npmjs", Guide: freshGuideProse}})
	if err != nil {
		t.Fatalf("nil store: unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("nil store: expected 0 rows, got %d", n)
	}

	counts, err := nilStore.StaleRepositoryGuideCounts(context.Background(), nil)
	if err != nil {
		t.Fatalf("nil store counts: unexpected error: %v", err)
	}
	if len(counts) != 0 {
		t.Fatalf("nil store counts: expected empty map, got %v", counts)
	}
}

// TestBackfillStaleRepositoryGuides is the load-bearing case. It asserts, in
// one fixture:
//
//  1. a stale row is repaired;
//  2. a SIBLING row that is equally stale but operator-customised is repaired
//     WITHOUT losing enabled / anonymous_access / remote_url / format_options
//     — the exact columns config.ReplaceRepositoriesForOrgTx would have
//     clobbered, which is why this migration is a column-only UPDATE;
//  3. a row that already carries the post-fix marker is left byte-identical;
//  4. re-running reports 0 rows and changes nothing.
func TestBackfillStaleRepositoryGuides(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.DB().Ping(); err != nil {
		t.Skipf("ping db failed (Postgres unreachable, treating as skip): %v", err)
	}

	ctx := context.Background()
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := "guidebackfill_org_a_" + nonce
	orgB := "guidebackfill_org_b_" + nonce
	staleRepo := "guidebackfill_stale_" + nonce
	customRepo := "guidebackfill_custom_" + nonce
	freshRepo := "guidebackfill_fresh_" + nonce

	t.Cleanup(func() {
		for _, name := range []string{staleRepo, customRepo, freshRepo} {
			if _, err := store.DB().Exec(`DELETE FROM repositories WHERE name = $1`, name); err != nil {
				t.Logf("cleanup %s: %v", name, err)
			}
		}
	})

	const customRemote = "https://internal-mirror.acme.example/npm"
	const customFormatOptions = `{"apt":{"components":["main"]}}`

	// Row 1 — a plain stale row in one org.
	insertRepoFixture(t, store.DB(), repoFixture{
		OrgID: orgA, Name: staleRepo, RemoteURL: "https://registry.npmjs.org",
		Enabled: 1, AnonymousAccess: 0, Guide: staleGuideProse,
	})
	// Row 2 — a DIFFERENT org, equally stale, with operator customisations on
	// the columns a delete-and-reseed would have reset.
	insertRepoFixture(t, store.DB(), repoFixture{
		OrgID: orgB, Name: customRepo, RemoteURL: customRemote,
		Enabled: 0, AnonymousAccess: 1, Guide: staleGuideProse,
		FormatOptions: customFormatOptions,
	})
	// Row 3 — already on post-fix prose. Must not be touched.
	insertRepoFixture(t, store.DB(), repoFixture{
		OrgID: orgA, Name: freshRepo, RemoteURL: "https://registry.npmjs.org",
		Enabled: 1, AnonymousAccess: 0, Guide: freshGuideProse,
	})

	replacement := strings.TrimSpace(freshGuideProse)
	guides := []RepositoryGuide{
		{Name: staleRepo, Guide: freshGuideProse},
		{Name: customRepo, Guide: freshGuideProse},
		{Name: freshRepo, Guide: freshGuideProse},
		{Name: "  ", Guide: freshGuideProse},       // skipped: no name
		{Name: "guidebackfill_blank", Guide: "  "}, // skipped: blank replacement
	}

	// Dry run sees exactly the two stale rows and not the fresh one.
	counts, err := store.StaleRepositoryGuideCounts(ctx, guides)
	if err != nil {
		t.Fatalf("stale counts: %v", err)
	}
	if counts[staleRepo] != 1 {
		t.Errorf("stale counts[%s] = %d, want 1", staleRepo, counts[staleRepo])
	}
	if counts[customRepo] != 1 {
		t.Errorf("stale counts[%s] = %d, want 1", customRepo, counts[customRepo])
	}
	if n, ok := counts[freshRepo]; ok {
		t.Errorf("stale counts[%s] = %d, want absent — the row already carries %q",
			freshRepo, n, repositoryGuideFreshMarker)
	}

	updated, err := store.BackfillStaleRepositoryGuides(ctx, guides)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if updated != 2 {
		t.Fatalf("backfill updated %d rows, want 2 (the two stale rows only)", updated)
	}

	// 1. The plain stale row is repaired.
	got := readRepoFixture(t, store.DB(), orgA, staleRepo)
	if got.Guide != replacement {
		t.Errorf("stale row guide not repaired:\ngot:  %q\nwant: %q", got.Guide, replacement)
	}
	if strings.Contains(got.Guide, "base64") {
		t.Errorf("stale row still carries the superseded base64-Bearer prose")
	}

	// 2. The customised sibling is repaired but keeps every other column.
	custom := readRepoFixture(t, store.DB(), orgB, customRepo)
	if custom.Guide != replacement {
		t.Errorf("customised row guide not repaired:\ngot:  %q\nwant: %q", custom.Guide, replacement)
	}
	if custom.Enabled != 0 {
		t.Errorf("customised row enabled = %d, want 0 — a column-only UPDATE must not reset it", custom.Enabled)
	}
	if custom.AnonymousAccess != 1 {
		t.Errorf("customised row anonymous_access = %d, want 1 — a column-only UPDATE must not reset it", custom.AnonymousAccess)
	}
	if custom.RemoteURL != customRemote {
		t.Errorf("customised row remote_url = %q, want %q — a column-only UPDATE must not reset it", custom.RemoteURL, customRemote)
	}
	if custom.FormatOptions != customFormatOptions {
		t.Errorf("customised row format_options = %q, want %q — a column-only UPDATE must not reset it", custom.FormatOptions, customFormatOptions)
	}

	// 3. The already-fixed row is byte-identical.
	fresh := readRepoFixture(t, store.DB(), orgA, freshRepo)
	if fresh.Guide != freshGuideProse {
		t.Errorf("row already carrying %q was rewritten:\ngot:  %q\nwant: %q",
			repositoryGuideFreshMarker, fresh.Guide, freshGuideProse)
	}

	// 4. Re-running is a no-op.
	again, err := store.BackfillStaleRepositoryGuides(ctx, guides)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if again != 0 {
		t.Fatalf("second backfill updated %d rows, want 0 — the migration is not idempotent", again)
	}
	for _, c := range []struct {
		org, name, want string
	}{
		{orgA, staleRepo, replacement},
		{orgB, customRepo, replacement},
		{orgA, freshRepo, freshGuideProse},
	} {
		if g := readRepoFixture(t, store.DB(), c.org, c.name).Guide; g != c.want {
			t.Errorf("after second run %s/%s guide changed:\ngot:  %q\nwant: %q", c.org, c.name, g, c.want)
		}
	}

	// And the dry run agrees nothing is left to do for these names.
	counts, err = store.StaleRepositoryGuideCounts(ctx, guides)
	if err != nil {
		t.Fatalf("stale counts after backfill: %v", err)
	}
	for _, name := range []string{staleRepo, customRepo, freshRepo} {
		if n, ok := counts[name]; ok {
			t.Errorf("stale counts[%s] = %d after backfill, want absent", name, n)
		}
	}
}

type repoFixture struct {
	OrgID           string
	Name            string
	RemoteURL       string
	Enabled         int
	AnonymousAccess int
	Guide           string
	FormatOptions   string
}

func insertRepoFixture(t *testing.T, db *sql.DB, f repoFixture) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO repositories (
			org_id, name, format, type, enabled, anonymous_access,
			remote_url, client_configuration_guide_template, format_options
		) VALUES ($1,$2,'npm','proxy',$3,$4,$5,$6,$7)`,
		f.OrgID, f.Name, f.Enabled, f.AnonymousAccess, f.RemoteURL, f.Guide, f.FormatOptions)
	if err != nil {
		t.Fatalf("insert fixture %s/%s: %v", f.OrgID, f.Name, err)
	}
}

func readRepoFixture(t *testing.T, db *sql.DB, orgID, name string) repoFixture {
	t.Helper()
	var got repoFixture
	got.OrgID, got.Name = orgID, name
	err := db.QueryRow(`
		SELECT enabled, anonymous_access, remote_url,
		       COALESCE(client_configuration_guide_template, ''),
		       COALESCE(format_options, '')
		  FROM repositories WHERE org_id = $1 AND name = $2`,
		orgID, name,
	).Scan(&got.Enabled, &got.AnonymousAccess, &got.RemoteURL, &got.Guide, &got.FormatOptions)
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", orgID, name, err)
	}
	return got
}
