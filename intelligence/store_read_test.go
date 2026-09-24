package intelligence

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// TestLagTolerantReadUsesTheReadPool proves the routing against Postgres. The
// read DSN is the same database with a search_path that holds no tables, so a
// read that reaches the READ pool fails visibly while one on the primary finds
// the row. An identical read DSN would pass even if the routing were ignored.
func TestLagTolerantReadUsesTheReadPool(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	q := u.Query()
	q.Set("search_path", "chainsaw_read_pool_probe_no_tables")
	u.RawQuery = q.Encode()

	pg, err := pgstore.OpenWithConfig(dsn, u.String(), pgstore.PoolConfig{}, pgstore.PoolConfig{})
	if err != nil {
		t.Fatalf("open with read dsn: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	store := NewStore(pg)
	ctx := context.Background()

	eco := "npm-readpool-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() { _, _ = pg.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco) })
	now := time.Now().UTC().Truncate(time.Second)
	key := Key{Ecosystem: eco, Package: "left-pad", Version: "1.3.0"}
	if err := store.Upsert(ctx, "org-test", &Report{
		Identity:    IdentitySection{Ecosystem: eco, Package: key.Package, Version: key.Version},
		SupplyChain: SupplyChainSection{MalwareStatus: "clean", TrustScore: 80},
		Observation: ObservationSection{CollectedAt: now, FreshUntil: now.Add(24 * time.Hour)},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Default: the primary, which has the row. Scan's cache-first read and
	// xreplicaflight's peek rely on this staying read-your-write.
	if _, err := store.Get(ctx, "", key); err != nil {
		t.Fatalf("primary Get: %v — an unmarked read must stay on the writable pool", err)
	}
	if _, err := store.Search(ctx, SearchQuery{Ecosystem: eco, Limit: 10}); err != nil {
		t.Fatalf("primary Search: %v", err)
	}

	// Marked lag-tolerant: the read pool, which cannot see the table.
	lag := WithLagTolerantRead(ctx)
	if _, err := store.Get(lag, "", key); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("lag-tolerant Get err = %v, want a relation error from the read pool — "+
			"the read did not reach the read pool", err)
	}
	if _, err := store.Search(lag, SearchQuery{Ecosystem: eco, Limit: 10}); err == nil {
		t.Fatal("lag-tolerant Search succeeded — it did not reach the read pool")
	}
}
