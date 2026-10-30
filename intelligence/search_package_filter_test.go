package intelligence

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The public and admin "latest" lookups resolved a package with a substring
// search and a 50-row window. On a common name, 50+ newer rows for longer
// names (lodash.get, lodash.merge, ...) filled the window, the package itself
// fell out, and a cached lookup answered 404. Package is an exact filter.
func TestSearchPackageFilterIsExact(t *testing.T) {
	store, db := verdictHistoryStore(t)
	ctx := context.Background()
	base := "srch" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name LIKE $1`, base+"%")
		_, _ = db.DB().Exec(`DELETE FROM verdict_history WHERE package_name LIKE $1`, base+"%")
	})

	exact := verdictReport(base, "1.0.0", "allow", 90)
	exact.Observation.CollectedAt = time.Now().UTC().Add(-time.Hour)
	if err := store.Upsert(ctx, "", exact); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		if err := store.Upsert(ctx, "", verdictReport(fmt.Sprintf("%s.sub%02d", base, i), "1.0.0", "allow", 90)); err != nil {
			t.Fatal(err)
		}
	}

	substr, err := store.Search(ctx, SearchQuery{Ecosystem: "npm", Q: base, Sort: "recent", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range substr.Rows {
		if row.Package == base {
			t.Fatal("precondition: the substring window should be full of longer names and miss the package; " +
				"if it does not, this test no longer reproduces the 404")
		}
	}

	res, err := store.Search(ctx, SearchQuery{Ecosystem: "npm", Package: base, Sort: "recent", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0].Package != base || res.Rows[0].Version != "1.0.0" {
		t.Fatalf("Package filter returned %d rows (%+v), want exactly %s@1.0.0", len(res.Rows), res.Rows, base)
	}
}
