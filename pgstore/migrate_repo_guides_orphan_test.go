package pgstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// P8-28 — orphaned repository guide rows.
//
// A repository that is deleted from configs/seed.yaml does not take its rows
// with it: every org seeded while it was live still holds one, with whatever
// prose was current at seed time. The backfill can only rewrite a row it has
// replacement prose for, so the moment the name leaves `repositories:` those
// rows become permanently unrepairable — and cef96422 additionally stopped
// counting them, so the problem also stopped being visible.
//
// swift is the case that actually shipped: deleted at 5373b2ff, ~25 rows in
// production, and the in-code comment justifying its exclusion said its prose
// "contains no `your-chainsaw-base` token and never will", which is simply
// untrue — the guide is full of the token. It was excluded because it was not
// in the caller's list, not because of its prose.

// seededThenDeletedRepositories is the pinned set of repository names that
// were once in `repositories:` and are not any more. It is a hand-maintained
// ratchet on purpose: git archaeology in a test would be slow, fragile, and
// would not tell the next person WHY the name left.
//
// Deleting a repository from configs/seed.yaml means adding it here AND
// moving its client_configuration_guide into `retired_repository_guides:` in
// the same change. This test is what makes that non-optional.
var seededThenDeletedRepositories = map[string]string{
	"swift": "removed from repositories: at 5373b2ff — SE-0292 defines the " +
		"registry protocol but no public Swift package registry exists to proxy",
}

type seedGuideDoc struct {
	Repositories []struct {
		Name  string `yaml:"name"`
		Guide string `yaml:"client_configuration_guide"`
	} `yaml:"repositories"`
	Retired []struct {
		Name  string `yaml:"name"`
		Guide string `yaml:"client_configuration_guide"`
	} `yaml:"retired_repository_guides"`
}

// loadSeedGuideDoc reads configs/seed.yaml with a minimal schema. core is
// published as a standalone module where configs/ is absent, so a missing
// file is a skip, matching TestRepositoryGuideMarkerMatchesSeedYAML.
func loadSeedGuideDoc(t *testing.T) seedGuideDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "seed.yaml"))
	if err != nil {
		t.Skipf("configs/seed.yaml not present (core-only checkout): %v", err)
	}
	var doc seedGuideDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse configs/seed.yaml: %v", err)
	}
	return doc
}

// TestSeededThenDeletedRepositoriesRemainRepairable is the guard the plan
// asks for: every name that was seeded and then deleted must still be
// enumerable by repairable(), built the way the boot path builds it.
//
// It fails in three distinguishable ways, because they need different fixes:
// the name is missing from retired_repository_guides (add the entry), the
// retired prose lost the freshness marker (the backfill would find nothing
// stale to replace), or the name came back into `repositories:` (drop it from
// the pinned set here).
func TestSeededThenDeletedRepositoriesRemainRepairable(t *testing.T) {
	t.Parallel()
	doc := loadSeedGuideDoc(t)

	seeded := map[string]bool{}
	guides := make([]RepositoryGuide, 0, len(doc.Repositories)+len(doc.Retired))
	for _, r := range doc.Repositories {
		seeded[r.Name] = true
		guides = append(guides, RepositoryGuide{Name: r.Name, Guide: r.Guide})
	}
	retired := map[string]string{}
	for _, r := range doc.Retired {
		retired[r.Name] = r.Guide
		guides = append(guides, RepositoryGuide{Name: r.Name, Guide: r.Guide})
	}

	repair := repairable(guides)

	for name, why := range seededThenDeletedRepositories {
		if seeded[name] {
			t.Errorf("%q is back in configs/seed.yaml `repositories:` but is still "+
				"listed in seededThenDeletedRepositories (%s). Remove it from the "+
				"pinned set — a live repository does not need a retired guide.", name, why)
			continue
		}
		guide, ok := retired[name]
		if !ok {
			t.Errorf("%q was seeded and then deleted (%s), but configs/seed.yaml has no "+
				"`retired_repository_guides:` entry for it.\nEvery org seeded while it "+
				"was live still holds a repositories row with that name, and the guide "+
				"backfill can only rewrite a row it has replacement prose for. Without "+
				"the entry those rows are unrepairable forever — the exact defect "+
				"P8-28 describes.", name, why)
			continue
		}
		if !strings.Contains(guide, repositoryGuideFreshMarker) {
			t.Errorf("the retired guide for %q does not contain %q, so repairable() "+
				"excludes it and the backfill still cannot touch its rows.",
				name, repositoryGuideFreshMarker)
			continue
		}
		if _, ok := repair[name]; !ok {
			t.Errorf("repairable() does not enumerate %q even though its retired guide "+
				"carries the marker — repairable() and the retired list have diverged.", name)
		}
	}

	// A retired entry that duplicates a live repository is a merge accident:
	// two sources of prose for one name, and the last one appended wins.
	for name := range retired {
		if seeded[name] {
			t.Errorf("%q appears in BOTH `repositories:` and "+
				"`retired_repository_guides:`. The retired list is only for names "+
				"that are no longer seeded.", name)
		}
	}
}

// TestSwiftRetiredGuideCarriesTheMarker pins the specific false claim the
// old code comment made, so nobody restores it. If this ever legitimately
// changes — the swift guide is rewritten to address a bare host, say — the
// counting logic has to move with it.
func TestSwiftRetiredGuideCarriesTheMarker(t *testing.T) {
	t.Parallel()
	doc := loadSeedGuideDoc(t)
	for _, r := range doc.Retired {
		if r.Name != "swift" {
			continue
		}
		if !strings.Contains(r.Guide, repositoryGuideFreshMarker) {
			t.Fatalf("the swift guide no longer contains %q. migrate_repo_guides.go "+
				"used to claim it 'contains no `your-chainsaw-base` token and never "+
				"will' — that was false, and the rows were excluded for a different "+
				"reason entirely. Re-read the repairable() comment before changing "+
				"this.", repositoryGuideFreshMarker)
		}
		return
	}
	t.Fatal("no retired_repository_guides entry named swift")
}

// TestStaleGuideCountsSeparateOrphansFromRepairable is the DB-backed case.
// It builds three stale rows that differ ONLY in what the caller knows about
// them, and walks the orphan through its whole life cycle:
//
//	baseline          — seeded name -> Repairable, unknown name -> Orphaned,
//	                    seeded-but-markerless name -> Markerless.
//	negative control  — with the orphan still absent from the guide list, the
//	                    backfill updates 1 row, not 2. That is the defect:
//	                    the orphan row is untouched and, before this change,
//	                    also uncounted.
//	repair            — supply the retired guide for the orphan; it moves to
//	                    Repairable and the next run rewrites it.
//	preservation      — the orphan row carries operator customisations on
//	                    enabled / anonymous_access / remote_url /
//	                    format_options; a column-only UPDATE must keep all
//	                    four, exactly as for a seeded row.
//	idempotency       — a third run updates 0.
func TestStaleGuideCountsSeparateOrphansFromRepairable(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty — " +
				"this test proves nothing when it skips")
		}
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
	org := "guideorphan_org_" + nonce
	seededRepo := "guideorphan_seeded_" + nonce
	orphanRepo := "guideorphan_retired_" + nonce
	markerlessRepo := "guideorphan_markerless_" + nonce

	t.Cleanup(func() {
		for _, name := range []string{seededRepo, orphanRepo, markerlessRepo} {
			if _, err := store.DB().Exec(`DELETE FROM repositories WHERE name = $1`, name); err != nil {
				t.Logf("cleanup %s: %v", name, err)
			}
		}
	})

	const orphanRemote = "https://internal-mirror.acme.example/swift"
	const orphanFormatOptions = `{"apt":{"components":["main"]}}`
	// Markerless prose: a guide that legitimately addresses a bare host and
	// so never carries the freshness marker (docker-hub is the real
	// instance). Its rows match the stale predicate FOREVER while the
	// UPDATE correctly writes nothing, because the stored text already
	// equals the replacement. That pair — "63 stale rows found",
	// "0 rows updated", on every boot — is the phantom cef96422 was fixing.
	const markerlessProse = "docker login your-chainsaw-server"

	insertRepoFixture(t, store.DB(), repoFixture{
		OrgID: org, Name: seededRepo, RemoteURL: "https://registry.npmjs.org",
		Enabled: 1, AnonymousAccess: 0, Guide: staleGuideProse,
	})
	// The orphan carries every operator customisation a delete-and-reseed
	// would have destroyed, so the repair path is proven to be column-only
	// for orphans too and not just for seeded rows.
	insertRepoFixture(t, store.DB(), repoFixture{
		OrgID: org, Name: orphanRepo, RemoteURL: orphanRemote,
		Enabled: 0, AnonymousAccess: 1, Guide: staleGuideProse,
		FormatOptions: orphanFormatOptions,
	})
	// Already holding exactly the replacement prose: stale by the predicate,
	// untouchable by the UPDATE.
	insertRepoFixture(t, store.DB(), repoFixture{
		OrgID: org, Name: markerlessRepo, RemoteURL: "https://registry-1.docker.io",
		Enabled: 1, AnonymousAccess: 0, Guide: markerlessProse,
	})

	// --- baseline: the orphan is absent from the caller's list ------------
	withoutRetired := []RepositoryGuide{
		{Name: seededRepo, Guide: freshGuideProse},
		{Name: markerlessRepo, Guide: markerlessProse},
	}
	counts, err := store.StaleRepositoryGuideCounts(ctx, withoutRetired)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts.Repairable[seededRepo] != 1 {
		t.Errorf("Repairable[%s] = %d, want 1", seededRepo, counts.Repairable[seededRepo])
	}
	if counts.Orphaned[orphanRepo] != 1 {
		t.Errorf("Orphaned[%s] = %d, want 1 — a stale row with no seed guide is an orphan, "+
			"and it must be COUNTED; cef96422 silently dropped this whole bucket",
			orphanRepo, counts.Orphaned[orphanRepo])
	}
	if _, ok := counts.Repairable[orphanRepo]; ok {
		t.Errorf("Orphaned row %s landed in Repairable — the backfill has no prose for it", orphanRepo)
	}
	if counts.Markerless[markerlessRepo] != 1 {
		t.Errorf("Markerless[%s] = %d, want 1 — the repository IS seeded, its prose just "+
			"carries no freshness marker; that is a different thing from an orphan",
			markerlessRepo, counts.Markerless[markerlessRepo])
	}
	if _, ok := counts.Orphaned[markerlessRepo]; ok {
		t.Errorf("%s is in the supplied guide list and must not be reported as an orphan", markerlessRepo)
	}
	if got := counts.OrphanNames(); len(got) != 1 || got[0] != orphanRepo {
		t.Errorf("OrphanNames() = %v, want [%s] — the WARN line has to name the row", got, orphanRepo)
	}

	// --- NEGATIVE CONTROL 1: without the retired entry, 1 row not 2 -------
	// Three stale rows go in, one comes out repaired. The orphan is skipped
	// because nothing supplied prose for it; the markerless row is skipped
	// because its stored text already equals the replacement.
	updated, err := store.BackfillStaleRepositoryGuides(ctx, withoutRetired)
	if err != nil {
		t.Fatalf("backfill without retired guide: %v", err)
	}
	if updated != 1 {
		t.Fatalf("backfill without the retired guide updated %d rows, want exactly 1 "+
			"(the seeded row). If this reads 2, the orphan was repaired without anyone "+
			"supplying prose for it and this test is no longer measuring the defect.", updated)
	}
	if got := readRepoFixture(t, store.DB(), org, markerlessRepo).Guide; got != markerlessProse {
		t.Fatalf("markerless row was rewritten:\ngot:  %q\nwant: %q", got, markerlessProse)
	}
	// insertRepoFixture stores the prose verbatim, so compare untrimmed.
	if got := readRepoFixture(t, store.DB(), org, orphanRepo).Guide; got != staleGuideProse {
		t.Fatalf("orphan row changed while it had no replacement prose:\ngot:  %q\nwant: %q",
			got, staleGuideProse)
	}

	// --- repair: hand it the retired prose --------------------------------
	withRetired := append(append([]RepositoryGuide{}, withoutRetired...),
		RepositoryGuide{Name: orphanRepo, Guide: freshGuideProse})

	counts, err = store.StaleRepositoryGuideCounts(ctx, withRetired)
	if err != nil {
		t.Fatalf("counts with retired guide: %v", err)
	}
	if counts.Repairable[orphanRepo] != 1 {
		t.Errorf("Repairable[%s] = %d, want 1 once the retired guide is supplied",
			orphanRepo, counts.Repairable[orphanRepo])
	}
	if len(counts.Orphaned) != 0 {
		t.Errorf("Orphaned = %v, want empty once every stale name has prose", counts.Orphaned)
	}

	updated, err = store.BackfillStaleRepositoryGuides(ctx, withRetired)
	if err != nil {
		t.Fatalf("backfill with retired guide: %v", err)
	}
	if updated != 1 {
		t.Fatalf("backfill with the retired guide updated %d rows, want exactly 1 "+
			"(the orphan; the seeded row was repaired on the previous run)", updated)
	}

	// --- preservation: column-only, for an orphan as much as a seeded row --
	got := readRepoFixture(t, store.DB(), org, orphanRepo)
	if got.Guide != strings.TrimSpace(freshGuideProse) {
		t.Errorf("orphan guide not repaired:\ngot:  %q\nwant: %q", got.Guide, strings.TrimSpace(freshGuideProse))
	}
	if got.Enabled != 0 {
		t.Errorf("orphan enabled = %d, want 0 — the UPDATE must stay column-only", got.Enabled)
	}
	if got.AnonymousAccess != 1 {
		t.Errorf("orphan anonymous_access = %d, want 1 — the UPDATE must stay column-only", got.AnonymousAccess)
	}
	if got.RemoteURL != orphanRemote {
		t.Errorf("orphan remote_url = %q, want %q — the UPDATE must stay column-only", got.RemoteURL, orphanRemote)
	}
	if got.FormatOptions != orphanFormatOptions {
		t.Errorf("orphan format_options = %q, want %q — the UPDATE must stay column-only",
			got.FormatOptions, orphanFormatOptions)
	}

	// --- NEGATIVE CONTROL 2: idempotency ----------------------------------
	// The markerless row is the one that could loop: it never gains the
	// marker, so nothing but the `client_configuration_guide_template <> $1`
	// clause stops it being rewritten on every single boot.
	updated, err = store.BackfillStaleRepositoryGuides(ctx, withRetired)
	if err != nil {
		t.Fatalf("third backfill: %v", err)
	}
	if updated != 0 {
		t.Fatalf("third backfill updated %d rows, want 0 — the migration is not idempotent. "+
			"A markerless row that keeps matching the stale predicate is held by the "+
			"`<> $1` clause alone; if that clause goes, this loops on every boot.", updated)
	}

	// And the markerless row is still counted as Markerless, still never
	// repaired, still not an orphan. That triple is the whole point of the
	// split: it is visible, it is explained, and it is not alarming.
	counts, err = store.StaleRepositoryGuideCounts(ctx, withRetired)
	if err != nil {
		t.Fatalf("final counts: %v", err)
	}
	if counts.Markerless[markerlessRepo] != 1 {
		t.Errorf("Markerless[%s] = %d after every run, want 1 — the row is permanently "+
			"stale by the predicate and that is correct", markerlessRepo, counts.Markerless[markerlessRepo])
	}
	if counts.RepairableTotal() != 0 {
		t.Errorf("RepairableTotal() = %d after every row was repaired, want 0; buckets=%+v",
			counts.RepairableTotal(), counts)
	}
	if counts.Total() != 1 {
		t.Errorf("Total() = %d, want 1 (the markerless row only); buckets=%+v", counts.Total(), counts)
	}
}
