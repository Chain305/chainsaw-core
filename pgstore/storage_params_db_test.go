package pgstore

import (
	"os"
	"strings"
	"testing"
)

// intelligence_reports carries fillfactor 80 and a 2% autovacuum scale
// factor after migration (J.3 I10), and re-migrating leaves them as they are.
func TestIntelligenceReportsStorageParameters(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	// Start from the stock settings, so the result proves the migration
	// set them rather than an earlier run.
	reset, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reset.DB().Exec(`ALTER TABLE intelligence_reports RESET (fillfactor, autovacuum_vacuum_scale_factor)`); err != nil {
		t.Fatal(err)
	}
	_ = reset.Close()
	for i := 0; i < 2; i++ { // the second Open re-runs migrate on a migrated DB
		s, err := Open(dsn)
		if err != nil {
			t.Fatal(err)
		}
		var opts string
		err = s.DB().QueryRow(`SELECT COALESCE(array_to_string(reloptions, ','), '') FROM pg_class
			WHERE relname = 'intelligence_reports' AND relnamespace = 'public'::regnamespace`).Scan(&opts)
		_ = s.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(opts, "fillfactor=80") || !strings.Contains(opts, "autovacuum_vacuum_scale_factor=0.02") {
			t.Fatalf("open %d: reloptions %q, want fillfactor=80 and autovacuum_vacuum_scale_factor=0.02", i, opts)
		}
	}
}
